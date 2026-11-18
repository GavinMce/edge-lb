//! A bounded, in-memory record of recent connections, for the controller's Logs page.
//!
//! Two rings share one sequence counter: ordinary traffic, and connections that were turned away
//! (no route matched, or the client left before saying what it wanted). Scanners on the open
//! internet can produce the second kind by the thousand a minute, so they get a ring of their own:
//! a scan can't push the real traffic out of the log.
//!
//! Nothing here is written to disk. A restart empties the log, which also means client addresses
//! never outlive the process.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Connections that were forwarded (or tried to be).
pub const TRAFFIC_CAP: usize = 4000;
/// Connections that were turned away.
pub const REJECT_CAP: usize = 2000;
/// Most entries one request may ask for.
pub const MAX_PAGE: usize = 1000;
/// A client-supplied hostname is cut here so one hostile ClientHello can't bloat the log.
const MAX_HOST: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Forwarded to a target; the connection ran its course.
    Ok,
    /// Something was sent, but no route matched its hostname or port.
    NoRoute,
    /// A route matched, but none of its targets would accept a connection.
    Unreachable,
    /// The client connected and left (or stayed silent) before we could tell what it wanted.
    Aborted,
}

impl Outcome {
    /// Turned away without being forwarded anywhere, as opposed to a real attempt at service.
    pub fn is_rejection(self) -> bool {
        matches!(self, Outcome::NoRoute | Outcome::Aborted)
    }
}

/// Which ring(s) a reader wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    #[default]
    All,
    Traffic,
    Rejects,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "all" | "" => Some(Kind::All),
            "traffic" => Some(Kind::Traffic),
            "rejects" => Some(Kind::Rejects),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::All => "all",
            Kind::Traffic => "traffic",
            Kind::Rejects => "rejects",
        }
    }
}

/// What the data plane knows when a connection ends.
pub struct Closed {
    pub client: IpAddr,
    /// The port the client connected to.
    pub port: u16,
    pub route: Option<String>,
    pub host: Option<String>,
    /// `ip:port` of the target that was used (or the last one tried).
    pub target: Option<String>,
    pub outcome: Outcome,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Grows by one per connection on this edge; lets a reader ask only for what is new.
    pub seq: u64,
    /// When the connection ended, in milliseconds since the Unix epoch.
    pub ts_ms: u64,
    pub client: IpAddr,
    pub port: u16,
    pub route: Option<String>,
    pub host: Option<String>,
    pub target: Option<String>,
    pub outcome: Outcome,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Page {
    /// The newest sequence number handed out so far; pass it back as `after` to get only newer entries.
    pub next: u64,
    /// Oldest first.
    pub entries: Vec<Entry>,
}

#[derive(Default)]
struct Inner {
    last: u64,
    traffic: VecDeque<Entry>,
    rejects: VecDeque<Entry>,
}

#[derive(Default)]
pub struct AccessLog {
    inner: Mutex<Inner>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn clip(mut s: String) -> String {
    if s.len() > MAX_HOST {
        let mut end = MAX_HOST;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

impl AccessLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, c: Closed) {
        let mut g = self.inner.lock().unwrap();
        g.last += 1;
        let rejected = c.outcome.is_rejection();
        let e = Entry {
            seq: g.last,
            ts_ms: now_ms(),
            client: c.client,
            port: c.port,
            route: c.route,
            host: c.host.map(clip),
            target: c.target,
            outcome: c.outcome,
            bytes_up: c.bytes_up,
            bytes_down: c.bytes_down,
            duration_ms: c.duration_ms,
        };
        let (ring, cap) = if rejected { (&mut g.rejects, REJECT_CAP) } else { (&mut g.traffic, TRAFFIC_CAP) };
        if ring.len() >= cap {
            ring.pop_front();
        }
        ring.push_back(e);
    }

    /// Entries newer than `after`, oldest first. If more than `limit` qualify, the newest `limit`.
    pub fn page(&self, after: u64, limit: usize, kind: Kind) -> Page {
        let limit = limit.clamp(1, MAX_PAGE);
        let g = self.inner.lock().unwrap();
        let mut out: Vec<&Entry> = Vec::new();
        if kind != Kind::Rejects {
            out.extend(g.traffic.iter().filter(|e| e.seq > after));
        }
        if kind != Kind::Traffic {
            out.extend(g.rejects.iter().filter(|e| e.seq > after));
        }
        out.sort_by_key(|e| e.seq);
        let skip = out.len().saturating_sub(limit);
        Page { next: g.last, entries: out.into_iter().skip(skip).cloned().collect() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed(outcome: Outcome, host: &str) -> Closed {
        Closed {
            client: "203.0.113.7".parse().unwrap(),
            port: 443,
            route: Some("web".into()),
            host: Some(host.into()),
            target: Some("10.0.0.5:443".into()),
            outcome,
            bytes_up: 10,
            bytes_down: 20,
            duration_ms: 5,
        }
    }

    #[test]
    fn entries_come_back_oldest_first_and_only_those_after_the_cursor() {
        let log = AccessLog::new();
        for i in 0..5 {
            log.record(closed(Outcome::Ok, &format!("h{i}.test")));
        }
        let p = log.page(0, 100, Kind::All);
        assert_eq!(p.next, 5);
        assert_eq!(p.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
        let p = log.page(3, 100, Kind::All);
        assert_eq!(p.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [4, 5]);
        assert!(log.page(5, 100, Kind::All).entries.is_empty());
    }

    #[test]
    fn a_small_limit_keeps_the_newest_entries() {
        let log = AccessLog::new();
        for i in 0..10 {
            log.record(closed(Outcome::Ok, &format!("h{i}.test")));
        }
        let p = log.page(0, 3, Kind::All);
        assert_eq!(p.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [8, 9, 10]);
    }

    #[test]
    fn a_flood_of_rejected_connections_cannot_push_real_traffic_out() {
        let log = AccessLog::new();
        log.record(closed(Outcome::Ok, "real.test"));
        for _ in 0..(REJECT_CAP * 3) {
            log.record(closed(Outcome::NoRoute, "scanner.test"));
        }
        let traffic = log.page(0, MAX_PAGE, Kind::Traffic);
        assert_eq!(traffic.entries.len(), 1);
        assert_eq!(traffic.entries[0].host.as_deref(), Some("real.test"));
        let rejects = log.page(0, MAX_PAGE, Kind::Rejects);
        assert_eq!(rejects.entries.len(), MAX_PAGE, "limited by the page size, not the ring");
        assert!(rejects.entries.iter().all(|e| e.outcome == Outcome::NoRoute));
    }

    #[test]
    fn each_ring_is_bounded() {
        let log = AccessLog::new();
        for _ in 0..(TRAFFIC_CAP + 50) {
            log.record(closed(Outcome::Ok, "a.test"));
        }
        let g = log.inner.lock().unwrap();
        assert_eq!(g.traffic.len(), TRAFFIC_CAP);
        assert_eq!(g.traffic.front().unwrap().seq, 51, "the oldest were dropped");
    }

    #[test]
    fn rejections_and_traffic_interleave_by_sequence() {
        let log = AccessLog::new();
        log.record(closed(Outcome::Ok, "a"));
        log.record(closed(Outcome::Aborted, "b"));
        log.record(closed(Outcome::Unreachable, "c"));
        log.record(closed(Outcome::NoRoute, "d"));
        let all = log.page(0, 10, Kind::All);
        assert_eq!(all.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3, 4]);
        // An unreachable target is a service problem, so it stays with the traffic.
        let traffic = log.page(0, 10, Kind::Traffic);
        assert_eq!(traffic.entries.iter().map(|e| e.outcome).collect::<Vec<_>>(), [Outcome::Ok, Outcome::Unreachable]);
    }

    #[test]
    fn a_hostile_hostname_is_cut_to_size() {
        let log = AccessLog::new();
        log.record(closed(Outcome::Ok, &"é".repeat(5000)));
        let host = log.page(0, 1, Kind::All).entries[0].host.clone().unwrap();
        assert!(host.len() <= MAX_HOST);
        assert!(host.chars().all(|c| c == 'é'), "cut on a character boundary");
    }

    #[test]
    fn kind_parses_only_known_words() {
        assert_eq!(Kind::parse("rejects"), Some(Kind::Rejects));
        assert_eq!(Kind::parse(""), Some(Kind::All));
        assert_eq!(Kind::parse("everything"), None);
    }
}
