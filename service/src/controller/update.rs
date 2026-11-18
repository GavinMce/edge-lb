//! Keeping the machines this controller manages on the controller's own version.
//!
//! The rule is simple: the edge and gateway software a controller installs is the controller's own
//! release, so "up to date" means "same version as me". Nothing is fetched from the internet by the
//! machines themselves.
//!
//! * An **edge** is updated by the controller over SSH, the way it was installed, with a copy of the
//!   old version kept so a bad update can be undone (see `bootstrap`). One at a time.
//! * A **gateway** sits behind NAT and only dials out, so it is asked: the controller marks the update
//!   as wanted, the gateway notices in its next sync and its root updater pulls the binary back from
//!   the controller (see `gateway_update`).
//!
//! What has been asked for, and how it went, is kept in memory only. Starting an update is always a
//! person's decision here; nothing starts one by itself.

use super::bootstrap::InstallCtx;
use super::model::*;
use super::sites::ONLINE_WITHIN_SECS;
use super::{Controller, CtlError, Live};
use crate::gateway::{UpdateOffer, UpdateResult, CAP_SELF_UPDATE};
use crate::pki;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// The version of the edge and gateway software this controller installs: its own.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A gateway update nobody has acted on for this long is reported as failed.
const GATEWAY_PATIENCE_SECS: u64 = 15 * 60;

fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().trim_start_matches('v').split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let v = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
    parts.next().is_none().then_some(v)
}

/// The version an update would install: `want`, if `have` is older than it or isn't known.
/// A machine that is *newer* than the controller (the controller was rolled back) is left alone.
pub fn available(have: Option<&str>, want: &str) -> Option<String> {
    let want_v = parse_version(want)?;
    match have.map(str::trim).filter(|h| !h.is_empty()) {
        None => Some(want.to_string()),
        Some(h) => match parse_version(h) {
            Some(hv) if hv >= want_v => None,
            _ => Some(want.to_string()),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone)]
pub(crate) struct UpdateRun {
    pub state: UpdateState,
    pub message: String,
    pub at: Ts,
    /// The version the machine ran when this started.
    pub from: Option<String>,
}

/// What the UI needs to show for one edge or gateway.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateView {
    /// The version an update would install; `None` when the machine is current.
    pub available: Option<String>,
    /// How the last or current update is going. `None` if none was started since the controller started.
    pub state: Option<UpdateState>,
    pub message: Option<String>,
    pub at: Option<Ts>,
}

impl Controller {
    fn set_run(&self, key: &str, state: UpdateState, message: impl Into<String>, from: Option<String>) {
        let mut runs = self.updates.lock().unwrap();
        let from = from.or_else(|| runs.get(key).and_then(|r| r.from.clone()));
        runs.insert(key.to_string(), UpdateRun { state, message: message.into(), at: now(), from });
    }

    fn note_run(&self, key: &str, message: impl Into<String>) {
        if let Some(r) = self.updates.lock().unwrap().get_mut(key) {
            r.message = message.into();
        }
    }

    pub(crate) fn update_view(&self, key: &str, available: Option<String>) -> UpdateView {
        let runs = self.updates.lock().unwrap();
        let Some(r) = runs.get(key) else { return UpdateView { available, ..Default::default() } };
        let (state, message) = if r.state == UpdateState::Running && key.starts_with("site:") && now().saturating_sub(r.at) > GATEWAY_PATIENCE_SECS {
            (UpdateState::Failed, "the gateway did not pick the update up. It may have gone offline; start it again once it is back".to_string())
        } else {
            (r.state, r.message.clone())
        };
        UpdateView { available, state: Some(state), message: Some(message), at: Some(r.at) }
    }

    fn is_running(&self, key: &str) -> bool {
        self.update_view(key, None).state == Some(UpdateState::Running)
    }

    // ---- edges ---------------------------------------------------------------------------------------

    pub(crate) fn edge_update_view(&self, e: &Edge, live: Option<&Live>) -> UpdateView {
        let avail = matches!(e.status, EdgeStatus::Healthy | EdgeStatus::Unreachable).then(|| available(live.and_then(|l| l.version.as_deref()), AGENT_VERSION)).flatten();
        self.update_view(&format!("edge:{}", e.id), avail)
    }

    /// Start updating one edge to this controller's version, in the background.
    ///
    /// The edge keeps its identity, routes and WireGuard key. It is restarted, so connections through
    /// it are cut for a few seconds. One edge at a time, so a rollout can't take every edge down together.
    pub fn update_edge(self: &Arc<Self>, actor: &str, id: &str) -> Result<(), CtlError> {
        let e = self.store.read(|s| s.edge(id).cloned()).ok_or_else(|| CtlError::NotFound(id.into()))?;
        if !matches!(e.status, EdgeStatus::Healthy | EdgeStatus::Unreachable) {
            return Err(CtlError::Conflict(format!("{} is {}; it can be updated once it is serving", e.name, status_word(e.status))));
        }
        if e.ip.is_none() || e.mgmt_fingerprint.is_none() {
            return Err(CtlError::Conflict(format!("{} has not finished installing", e.name)));
        }
        let others: Vec<(String, String)> = self.store.read(|s| s.edges.iter().filter(|x| x.id != id).map(|x| (x.id.clone(), x.name.clone())).collect());
        // Read before taking the updates lock: `edges()` takes these two the other way round.
        let from = self.live.read().unwrap().get(id).and_then(|l| l.version.clone());
        let key = format!("edge:{id}");
        {
            // Decide that this may start, and record it as started, in one step.
            let mut runs = self.updates.lock().unwrap();
            let running = |k: &str| runs.get(k).is_some_and(|r| r.state == UpdateState::Running);
            if running(&key) {
                return Err(CtlError::Conflict(format!("{} is already being updated", e.name)));
            }
            if let Some((_, name)) = others.iter().find(|(oid, _)| running(&format!("edge:{oid}"))) {
                return Err(CtlError::Conflict(format!("{name} is being updated; update one edge at a time")));
            }
            runs.insert(key.clone(), UpdateRun { state: UpdateState::Running, message: "waiting for the edge to be free".into(), at: now(), from });
        }
        self.audit.record(actor, "edge.update", &format!("{id}: to v{AGENT_VERSION}"));
        let c = self.clone();
        tokio::spawn(async move {
            // The slot the reconciler uses for this edge. While it is held the edge isn't polled, so the few
            // seconds of a restart are not mistaken for an outage. A routine check holds it only briefly, so
            // wait for it rather than turning the request down.
            let mut tries = 0;
            while !c.inflight.lock().unwrap().insert(e.id.clone()) {
                tries += 1;
                if tries > 300 {
                    let msg = "the controller was still busy with this edge after 30 seconds; try again".to_string();
                    c.set_run(&key, UpdateState::Failed, msg.clone(), None);
                    c.audit.record("system", "edge.update_failed", &format!("{}: {msg}", e.id));
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            c.note_run(&key, "uploading the new version");
            match c.do_edge_update(&e, &key).await {
                Ok(msg) => {
                    c.set_run(&key, UpdateState::Done, msg.clone(), None);
                    c.mutate(&e.id, |x| super::lifecycle::push_log(x, &msg));
                    c.audit.record("system", "edge.updated", &format!("{}: {msg}", e.id));
                }
                Err(msg) => {
                    c.set_run(&key, UpdateState::Failed, msg.clone(), None);
                    c.mutate(&e.id, |x| super::lifecycle::push_log(x, &format!("update failed: {msg}")));
                    c.audit.record("system", "edge.update_failed", &format!("{}: {msg}", e.id));
                }
            }
            c.inflight.lock().unwrap().remove(&e.id);
        });
        Ok(())
    }

    /// `Ok` is what happened, in words for the UI; `Err` is why the edge was left on its old version.
    async fn do_edge_update(&self, e: &Edge, key: &str) -> Result<String, String> {
        let fmt = |x: anyhow::Error| format!("{x:#}");
        let t = Self::target(e).ok_or("the edge has no address")?;
        let bs = self.bootstrapper().await.map_err(fmt)?;
        let ctx = InstallCtx { ca_pem: self.store.read(|s| s.ca.cert.clone()), agents: self.opts.agents.clone() };
        let was = self.live.read().unwrap().get(&e.id).and_then(|l| l.version.clone());

        self.note_run(key, "installing the new version and restarting the edge");
        // The script puts the old version back itself if the new one won't start.
        let done = bs.update(&t, &ctx).await.map_err(|x| format!("{}; the edge was left on its previous version", fmt(x)))?;

        // The edge must be the same edge: same identity, or the pin would no longer match.
        let pinned = e.mgmt_fingerprint.clone().unwrap_or_default();
        let fp = pki::fingerprint_pem(&done.cert_pem).map_err(fmt)?;
        if fp != pinned {
            let undone = bs.rollback(&t).await.map(|_| "put the previous version back").unwrap_or("could NOT put the previous version back");
            return Err(format!("the updated edge presented a different identity than the one pinned, so the controller could no longer trust it; {undone}"));
        }

        self.note_run(key, "waiting for the edge to answer");
        let client = self.client_for(e).map_err(fmt)?;
        let pause = self.opts.poll_every.min(Duration::from_secs(1));
        let mut last = String::from("no answer");
        let mut reported = None;
        // A budget of time, not of attempts: one attempt against a dead machine can itself take seconds.
        let deadline = tokio::time::Instant::now() + self.opts.update_wait;
        loop {
            match client.status().await {
                Ok(v) => {
                    reported = v["version"].as_str().map(String::from);
                    self.set_live(&e.id, |l| {
                        l.reachable = true;
                        l.last_seen = Some(now());
                        l.version = reported.clone();
                        l.generation = v["generation"].as_u64();
                        l.consecutive_failures = 0;
                        l.last_error = None;
                        l.status = Some(v);
                    });
                    break;
                }
                Err(err) => last = err.to_string(),
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(pause).await;
        }
        let Some(reported) = reported else {
            let undone = bs.rollback(&t).await.map(|_| "put the previous version back").unwrap_or("could NOT put the previous version back");
            return Err(format!("the edge did not answer over its management channel after updating ({last}); {undone}"));
        };
        if let Some(k) = done.wg_public_key.as_ref() {
            self.mutate(&e.id, |x| x.wg_public_key = Some(k.clone()));
        }
        Ok(if reported == AGENT_VERSION {
            match was.as_deref() {
                Some(w) if w == reported => format!("reinstalled v{reported}"),
                Some(w) => format!("updated from v{w} to v{reported}"),
                None => format!("updated to v{reported}"),
            }
        } else {
            format!("installed, but the edge reports v{reported} and this controller is v{AGENT_VERSION}: the binary this controller carries for the edge's CPU may be from a different build")
        })
    }

    // ---- gateways ------------------------------------------------------------------------------------

    pub(crate) fn gateway_update_view(&self, site: &str, version: Option<&str>) -> UpdateView {
        self.update_view(&format!("site:{site}"), version.and_then(|v| available(Some(v), AGENT_VERSION)))
    }

    /// Ask a site's gateway to move to this controller's version. It acts on this at its next sync.
    pub fn update_gateway(&self, actor: &str, site_id: &str) -> Result<(), CtlError> {
        let name = self.store.read(|s| s.site(site_id).map(|x| (x.name.clone(), x.gateway.public_key.is_some()))).ok_or_else(|| CtlError::NotFound(site_id.into()))?;
        if !name.1 {
            return Err(CtlError::Conflict(format!("{} has no gateway yet", name.0)));
        }
        let (online, version, can) = {
            let live = self.gw_live.read().unwrap();
            match live.get(site_id) {
                Some(l) => (now().saturating_sub(l.last_seen) <= ONLINE_WITHIN_SECS, Some(l.version.clone()), l.caps.iter().any(|c| c == CAP_SELF_UPDATE)),
                None => (false, None, false),
            }
        };
        if !online {
            return Err(CtlError::Conflict("the gateway is offline; it can only be updated while it is connected".into()));
        }
        if !can {
            return Err(CtlError::Conflict("this gateway was installed before gateways could update themselves. Re-enrol it once (Re-enrol gateway), and later updates can be started from here".into()));
        }
        let key = format!("site:{site_id}");
        if self.is_running(&key) {
            return Err(CtlError::Conflict("an update is already in progress for this gateway".into()));
        }
        self.set_run(&key, UpdateState::Running, "waiting for the gateway to pick the update up", version);
        self.audit.record(actor, "gateway.update", &format!("{site_id}: to v{AGENT_VERSION}"));
        Ok(())
    }

    /// Called on every gateway sync: moves a requested update along, and returns the offer to hand
    /// the gateway while one is wanted and the gateway isn't on that version yet.
    pub(crate) fn gw_update_step(&self, site_id: &str, reported: &str, result: Option<&UpdateResult>) -> Option<UpdateOffer> {
        let mut runs = self.updates.lock().unwrap();
        let run = runs.get_mut(&format!("site:{site_id}"))?;
        if run.state != UpdateState::Running {
            return None;
        }
        if let Some(r) = result.filter(|r| !r.ok) {
            run.state = UpdateState::Failed;
            run.message = r.error.clone().unwrap_or_else(|| "the update failed".into());
            run.at = now();
            return None;
        }
        if reported == AGENT_VERSION {
            run.message = if run.from.as_deref() == Some(reported) { format!("already running v{reported}") } else { format!("updated to v{reported}") };
            run.state = UpdateState::Done;
            run.at = now();
            return None;
        }
        run.message = "the gateway is installing the update".into();
        Some(UpdateOffer { version: AGENT_VERSION.into() })
    }
}

fn status_word(s: EdgeStatus) -> String {
    serde_json::to_value(s).ok().and_then(|v| v.as_str().map(|w| w.replace('_', " "))).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_is_offered_to_older_or_unknown_versions_only() {
        assert_eq!(available(Some("0.1.2"), "0.1.3").as_deref(), Some("0.1.3"));
        assert_eq!(available(Some("0.1.9"), "0.1.10").as_deref(), Some("0.1.10"), "compared as numbers, not text");
        assert_eq!(available(Some("0.9.0"), "0.10.0").as_deref(), Some("0.10.0"));
        assert_eq!(available(Some("1.0.0"), "0.9.9"), None, "a newer machine is left alone");
        assert_eq!(available(Some("0.1.3"), "0.1.3"), None);
        assert_eq!(available(Some("v0.1.3"), "0.1.3"), None);
        assert_eq!(available(Some("0.1.3-rc.1"), "0.1.3"), None, "a pre-release tag is not a different release");
        assert_eq!(available(None, "0.1.3").as_deref(), Some("0.1.3"), "unknown: offer it");
        assert_eq!(available(Some(" "), "0.1.3").as_deref(), Some("0.1.3"));
        assert_eq!(available(Some("garbage"), "0.1.3").as_deref(), Some("0.1.3"));
        assert_eq!(available(Some("0.1.2"), "garbage"), None, "never offer a version we can't read");
    }

    #[test]
    fn versions_must_be_exactly_three_numbers() {
        assert_eq!(parse_version("0.1.3"), Some((0, 1, 3)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("a.b.c"), None);
    }
}
