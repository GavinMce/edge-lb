//! The Logs page: recent connections, gathered from every edge when you ask.
//!
//! The controller stores nothing. Each edge keeps its own short, in-memory record (see
//! `accesslog`); a request here asks the edges for it over the same pinned mutual-TLS channel the
//! controller already uses, then merges and filters the answers.

use super::model::{Edge, EdgeStatus};
use super::{Controller, CtlError};
use crate::accesslog::{Entry, Kind, Outcome, Page, MAX_PAGE};
use crate::edge_client::ClientError;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::task::JoinSet;

/// One slow or dead edge must not hold the whole page up for long.
const PER_EDGE_TIMEOUT: Duration = Duration::from_secs(6);
const DEFAULT_LIMIT: usize = 200;

#[derive(Debug, Default, Deserialize)]
pub struct LogQuery {
    /// Only this edge.
    pub edge: Option<String>,
    /// Only this route (its id).
    pub route: Option<String>,
    /// `ok`, `unreachable`, `no_route` or `aborted`; or `rejected` for the last two together.
    pub outcome: Option<String>,
    /// Part of the client address.
    pub client: Option<String>,
    /// Part of the hostname the client asked for.
    pub host: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct LogRow {
    #[serde(flatten)]
    pub entry: Entry,
    pub edge: String,
    pub edge_name: String,
}

/// How each edge answered, so a missing edge is explained and not just absent.
#[derive(Debug, Serialize)]
pub struct LogSource {
    pub id: String,
    pub name: String,
    pub returned: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogsView {
    /// Newest first.
    pub entries: Vec<LogRow>,
    pub sources: Vec<LogSource>,
}

#[derive(Clone, Copy)]
enum Want {
    One(Outcome),
    Rejected,
}

impl Want {
    fn parse(s: &str) -> Option<Want> {
        Some(match s {
            "ok" => Want::One(Outcome::Ok),
            "unreachable" => Want::One(Outcome::Unreachable),
            "no_route" => Want::One(Outcome::NoRoute),
            "aborted" => Want::One(Outcome::Aborted),
            "rejected" => Want::Rejected,
            _ => return None,
        })
    }

    fn accepts(self, o: Outcome) -> bool {
        match self {
            Want::One(x) => x == o,
            Want::Rejected => o.is_rejection(),
        }
    }

    /// Which of the edge's two rings can hold such entries.
    fn kind(self) -> Kind {
        match self {
            Want::Rejected | Want::One(Outcome::NoRoute | Outcome::Aborted) => Kind::Rejects,
            Want::One(_) => Kind::Traffic,
        }
    }
}

struct Filter {
    route: Option<String>,
    client: Option<String>,
    host: Option<String>,
    want: Option<Want>,
}

impl Filter {
    fn is_empty(&self) -> bool {
        self.route.is_none() && self.client.is_none() && self.host.is_none()
    }

    fn matches(&self, e: &Entry) -> bool {
        self.route.as_ref().is_none_or(|r| e.route.as_deref() == Some(r.as_str()))
            && self.client.as_ref().is_none_or(|c| e.client.to_string().contains(c.as_str()))
            && self.host.as_ref().is_none_or(|h| e.host.as_deref().is_some_and(|x| x.to_ascii_lowercase().contains(h.as_str())))
            && self.want.is_none_or(|w| w.accepts(e.outcome))
    }
}

fn clean(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn status_word(s: EdgeStatus) -> String {
    serde_json::to_value(s).ok().and_then(|v| v.as_str().map(|w| w.replace('_', " "))).unwrap_or_default()
}

impl Controller {
    /// Recent connections from the edges, newest first.
    pub async fn access_logs(&self, q: LogQuery) -> Result<LogsView, CtlError> {
        let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_PAGE);
        let want = match clean(q.outcome) {
            None => None,
            Some(o) => Some(Want::parse(&o).ok_or_else(|| CtlError::Invalid(vec![format!("unknown outcome \"{o}\" (use ok, unreachable, no_route, aborted or rejected)")]))?),
        };
        let filter = Filter { route: clean(q.route), client: clean(q.client), host: clean(q.host).map(|h| h.to_ascii_lowercase()), want };
        let kind = want.map_or(Kind::All, Want::kind);
        // With a filter, most of what an edge returns may be thrown away, so ask for all it can give.
        let ask = if filter.is_empty() && want.is_none() { limit } else { MAX_PAGE };

        let edge_id = clean(q.edge);
        let edges: Vec<Edge> = self.store.read(|s| s.edges.iter().filter(|e| edge_id.as_deref().is_none_or(|id| e.id == id)).cloned().collect());
        if let (Some(id), true) = (&edge_id, edges.is_empty()) {
            return Err(CtlError::NotFound(id.clone()));
        }

        let mut sources = Vec::new();
        let mut asking = JoinSet::new();
        for e in edges {
            if !matches!(e.status, EdgeStatus::Healthy | EdgeStatus::Draining) {
                sources.push(LogSource { id: e.id, name: e.name, returned: 0, error: Some(format!("edge is {}", status_word(e.status))) });
                continue;
            }
            match self.client_for(&e) {
                Ok(client) => {
                    asking.spawn(async move {
                        let r = tokio::time::timeout(PER_EDGE_TIMEOUT, client.connections(0, ask, kind.as_str())).await;
                        (e.id, e.name, r)
                    });
                }
                Err(err) => sources.push(LogSource { id: e.id, name: e.name, returned: 0, error: Some(format!("{err:#}")) }),
            }
        }

        let mut rows: Vec<LogRow> = Vec::new();
        while let Some(joined) = asking.join_next().await {
            let Ok((id, name, result)) = joined else { continue };
            let page = match result {
                Err(_) => Err("timed out".to_string()),
                // An older edge has no such endpoint; say what to do about it.
                Ok(Err(ClientError::Other(m))) if m.starts_with("HTTP 404") => Err("this edge is older than the connection log; reinstall it to update".to_string()),
                Ok(Err(e)) => Err(e.to_string()),
                Ok(Ok(v)) => serde_json::from_value::<Page>(v).map_err(|e| format!("unexpected reply: {e}")),
            };
            match page {
                Ok(p) => {
                    let before = rows.len();
                    rows.extend(p.entries.into_iter().filter(|e| filter.matches(e)).map(|entry| LogRow { entry, edge: id.clone(), edge_name: name.clone() }));
                    sources.push(LogSource { id, name, returned: rows.len() - before, error: None });
                }
                Err(error) => sources.push(LogSource { id, name, returned: 0, error: Some(error) }),
            }
        }

        rows.sort_by(|a, b| b.entry.ts_ms.cmp(&a.entry.ts_ms).then(b.entry.seq.cmp(&a.entry.seq)));
        rows.truncate(limit);
        sources.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(LogsView { entries: rows, sources })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(route: Option<&str>, host: Option<&str>, client: &str, outcome: Outcome) -> Entry {
        Entry {
            seq: 1,
            ts_ms: 1,
            client: client.parse().unwrap(),
            port: 443,
            route: route.map(String::from),
            host: host.map(String::from),
            target: None,
            outcome,
            bytes_up: 0,
            bytes_down: 0,
            duration_ms: 0,
        }
    }

    fn filter(route: Option<&str>, client: Option<&str>, host: Option<&str>, want: Option<&str>) -> Filter {
        Filter { route: route.map(String::from), client: client.map(String::from), host: host.map(String::from), want: want.and_then(Want::parse) }
    }

    #[test]
    fn filters_combine_with_and() {
        let e = entry(Some("web"), Some("App.Example.com"), "203.0.113.7", Outcome::Ok);
        assert!(filter(None, None, None, None).matches(&e));
        assert!(filter(Some("web"), Some("203.0.113"), Some("app.example"), Some("ok")).matches(&e));
        assert!(!filter(Some("api"), None, None, None).matches(&e), "route must match exactly");
        assert!(!filter(Some("we"), None, None, None).matches(&e), "route is not a substring match");
        assert!(!filter(None, Some("198.51"), None, None).matches(&e));
        assert!(!filter(None, None, Some("other"), None).matches(&e));
        assert!(!filter(None, None, None, Some("rejected")).matches(&e));
    }

    #[test]
    fn a_hostname_filter_skips_entries_with_no_hostname() {
        let e = entry(None, None, "203.0.113.7", Outcome::Aborted);
        assert!(!filter(None, None, Some("x"), None).matches(&e));
        assert!(filter(None, None, None, Some("rejected")).matches(&e));
        assert!(filter(None, None, None, Some("aborted")).matches(&e));
        assert!(!filter(None, None, None, Some("no_route")).matches(&e));
    }

    #[test]
    fn the_outcome_decides_which_ring_to_ask_for() {
        assert_eq!(Want::parse("ok").unwrap().kind(), Kind::Traffic);
        assert_eq!(Want::parse("unreachable").unwrap().kind(), Kind::Traffic);
        assert_eq!(Want::parse("no_route").unwrap().kind(), Kind::Rejects);
        assert_eq!(Want::parse("rejected").unwrap().kind(), Kind::Rejects);
        assert!(Want::parse("everything").is_none());
    }
}
