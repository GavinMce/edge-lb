//! The reconciler: walks every edge through its lifecycle, one small idempotent step per tick.
//!
//! Creating -> WaitingForSsh -> Bootstrapping -> Joining -> Healthy <-> Unreachable
//!                                                   Healthy -> Draining -> Deleting -> (gone)
//!
//! All progress is persisted, so a controller restart resumes each edge where it was.

use super::bootstrap::{InstallCtx, Target};
use super::dns;
use super::model::*;
use super::providers::{CreateServer, Hetzner};
use super::{Controller, Live};
use crate::edge_client::{ClientError, EdgeClient};
use crate::pki;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

const CREATE_TIMEOUT_SECS: u64 = 600;
const JOIN_TIMEOUT_SECS: u64 = 180;
const SSH_WAIT_HETZNER_SECS: u64 = 900;
const SSH_WAIT_MANUAL_SECS: u64 = 180;
const MAX_LOG: usize = 40;
const DNS_REFRESH: Duration = Duration::from_secs(60);

pub(crate) fn push_log(e: &mut Edge, msg: &str) {
    e.log.push(LogEntry { ts: now(), msg: msg.to_string() });
    if e.log.len() > MAX_LOG {
        let excess = e.log.len() - MAX_LOG;
        e.log.drain(..excess);
    }
}

impl Controller {
    pub(crate) async fn run(self: Arc<Self>) {
        let mut tick = tokio::time::interval(self.opts.tick);
        loop {
            tick.tick().await;
            self.tick();
        }
    }

    fn tick(self: &Arc<Self>) {
        self.ensure_addresses();
        let ids: Vec<String> = self.store.read(|s| s.edges.iter().map(|e| e.id.clone()).collect());
        for id in ids {
            if !self.inflight.lock().unwrap().insert(id.clone()) {
                continue; // previous step still running
            }
            let c = self.clone();
            tokio::spawn(async move {
                c.step(&id).await;
                c.inflight.lock().unwrap().remove(&id);
            });
        }
        if self.inflight.lock().unwrap().insert("\0dns".into()) {
            let c = self.clone();
            tokio::spawn(async move {
                c.dns_tick().await;
                c.inflight.lock().unwrap().remove("\0dns");
            });
        }
    }

    async fn step(&self, id: &str) {
        let Some(e) = self.store.read(|s| s.edge(id).cloned()) else { return };
        if self.backoff.lock().unwrap().get(id).is_some_and(|t| *t > Instant::now()) {
            return;
        }
        debug!(edge = %e.id, status = ?e.status, "step");
        match e.status {
            EdgeStatus::Creating => self.step_creating(&e).await,
            EdgeStatus::WaitingForSsh => self.step_waiting(&e).await,
            EdgeStatus::Bootstrapping => self.step_bootstrap(&e).await,
            EdgeStatus::Joining => self.step_joining(&e).await,
            EdgeStatus::Healthy | EdgeStatus::Unreachable => self.step_poll(&e).await,
            EdgeStatus::Draining => self.step_draining(&e).await,
            EdgeStatus::Deleting => self.step_deleting(&e).await,
            EdgeStatus::Failed => {}
        }
    }

    // ---- state helpers -------------------------------------------------------------------------

    pub(crate) fn mutate(&self, id: &str, f: impl FnOnce(&mut Edge)) {
        let _ = self.store.update(|s| {
            if let Some(e) = s.edges.iter_mut().find(|e| e.id == id) {
                f(e);
            }
        });
    }

    fn transition(&self, id: &str, to: EdgeStatus, msg: &str) {
        self.backoff.lock().unwrap().remove(id);
        self.mutate(id, |e| {
            e.status = to;
            e.status_since = now();
            e.attempts = 0;
            e.error = None;
            push_log(e, msg);
        });
    }

    fn fail(&self, id: &str, msg: &str) {
        warn!(edge = %id, "edge failed: {msg}");
        self.backoff.lock().unwrap().remove(id);
        self.mutate(id, |e| {
            e.status = EdgeStatus::Failed;
            e.status_since = now();
            e.error = Some(msg.to_string());
            push_log(e, &format!("failed: {msg}"));
        });
        self.audit.record("system", "edge.failed", &format!("{id}: {msg}"));
    }

    /// Record a transient problem. Only a *changed* message is logged, so retries don't spam.
    fn soft_error(&self, id: &str, msg: String) {
        let mut attempts = 0;
        self.mutate(id, |e| {
            e.attempts += 1;
            attempts = e.attempts;
            if e.error.as_deref() != Some(msg.as_str()) {
                push_log(e, &msg);
            }
            e.error = Some(msg);
        });
        let (base, max) = self.opts.retry_backoff;
        let delay = base.saturating_mul(1u32 << attempts.saturating_sub(1).min(10)).min(max);
        self.backoff.lock().unwrap().insert(id.to_string(), Instant::now() + delay);
    }

    /// Provider errors: a rejected credential will never fix itself, so fail now; anything else
    /// is retried with backoff until the overall creation timeout.
    fn provider_error(&self, e: &Edge, msg: String) {
        if msg.contains("rejected the API token") {
            self.fail(&e.id, &msg);
        } else {
            self.soft_error(&e.id, msg);
        }
    }

    /// Like `soft_error`, but gives up (Failed) after `max` consecutive attempts.
    fn soft_error_or_fail(&self, e: &Edge, msg: String, max: u32) {
        if e.attempts + 1 >= max {
            self.fail(&e.id, &msg);
        } else {
            self.soft_error(&e.id, msg);
        }
    }

    pub(crate) fn target(e: &Edge) -> Option<Target> {
        Some(Target { edge_id: e.id.clone(), ip: e.ip?, ssh_user: e.ssh_user.clone(), ssh_port: e.ssh_port, mgmt_port: e.mgmt_port })
    }

    pub(crate) fn client_for(&self, e: &Edge) -> anyhow::Result<EdgeClient> {
        let ip = e.ip.ok_or_else(|| anyhow::anyhow!("edge has no IP address"))?;
        let fp = e.mgmt_fingerprint.as_deref().ok_or_else(|| anyhow::anyhow!("edge identity not pinned yet"))?;
        let client = self.store.read(|s| s.client.clone());
        EdgeClient::new(ip, e.mgmt_port, fp, &client)
    }

    pub(crate) fn hetzner(&self) -> anyhow::Result<(Hetzner, String)> {
        let (token, image) = self.store.read(|s| (s.settings.hetzner_token.clone(), s.settings.hetzner_image.clone()));
        let token = token.ok_or_else(|| anyhow::anyhow!("the Hetzner API token is not set (Settings)"))?;
        Ok((Hetzner::new(&self.opts.hetzner_base, &token)?, image))
    }

    pub(crate) fn set_live(&self, id: &str, f: impl FnOnce(&mut Live)) {
        let mut live = self.live.write().unwrap();
        f(live.entry(id.to_string()).or_default());
    }

    // ---- steps -----------------------------------------------------------------------------------

    async fn step_creating(&self, e: &Edge) {
        let (location, server_type) = match &e.provider {
            ProviderSpec::Manual => return self.transition(&e.id, EdgeStatus::WaitingForSsh, "using the machine you provided"),
            ProviderSpec::Hetzner { location, server_type } => (location.clone(), server_type.clone()),
        };
        if now().saturating_sub(e.status_since) > CREATE_TIMEOUT_SECS {
            return self.fail(&e.id, "timed out waiting for the provider to create the server");
        }
        let (h, image) = match self.hetzner() {
            Ok(x) => x,
            Err(err) => return self.fail(&e.id, &err.to_string()),
        };

        // A server may already exist (we asked, then restarted before the IP was recorded).
        let existing = match &e.server_id {
            Some(sid) => h.get_server(sid).await.map_err(|x| x.to_string()),
            None => h.find_by_edge_id(&e.id).await.map_err(|x| x.to_string()),
        };
        let info = match existing {
            Ok(Some(i)) => i,
            Ok(None) if e.server_id.is_some() => return self.fail(&e.id, "the server disappeared from the provider"),
            Ok(None) => {
                let key = match self.ssh_key().await {
                    Ok(k) => k.clone(),
                    Err(err) => return self.provider_error(e, err.to_string()),
                };
                let key_id = match h.ensure_ssh_key("edge-lb", &key.public).await {
                    Ok(k) => k,
                    Err(err) => return self.provider_error(e, err.to_string()),
                };
                let req = CreateServer { edge_id: e.id.clone(), name: format!("edge-lb-{}", e.id), location, server_type, image, ssh_key_id: key_id };
                match h.create_server(&req).await {
                    Ok(i) => {
                        self.mutate(&e.id, |x| push_log(x, &format!("provider created server {}", i.id)));
                        i
                    }
                    Err(err) => return self.provider_error(e, format!("{err:#}")),
                }
            }
            Err(err) => return self.provider_error(e, err),
        };
        self.mutate(&e.id, |x| {
            x.server_id = Some(info.id.clone());
            if info.ipv4.is_some() {
                x.ip = info.ipv4;
            }
        });
        if let Some(ip) = info.ipv4 {
            if let (Ok(bs), Some(mut t)) = (self.bootstrapper().await, Self::target(e)) {
                t.ip = ip;
                bs.forget(&t).await; // a recycled IP must not trip over an old host key
            }
            self.transition(&e.id, EdgeStatus::WaitingForSsh, &format!("server is up at {ip}"));
        }
    }

    async fn step_waiting(&self, e: &Edge) {
        let Some(t) = Self::target(e) else { return self.fail(&e.id, "edge has no IP address") };
        let bs = match self.bootstrapper().await {
            Ok(b) => b,
            Err(err) => return self.fail(&e.id, &format!("{err:#}")),
        };
        let limit = match e.provider {
            ProviderSpec::Hetzner { .. } => SSH_WAIT_HETZNER_SECS,
            ProviderSpec::Manual => SSH_WAIT_MANUAL_SECS,
        };
        match bs.probe(&t).await {
            Ok(()) => self.transition(&e.id, EdgeStatus::Bootstrapping, "SSH is reachable; installing"),
            Err(err) if now().saturating_sub(e.status_since) > limit => {
                self.fail(&e.id, &format!("could not log in over SSH: {err:#}. For an existing machine, add the controller's SSH key to authorized_keys (see Settings)"))
            }
            Err(err) => self.soft_error(&e.id, format!("waiting for SSH: {err:#}")),
        }
    }

    async fn step_bootstrap(&self, e: &Edge) {
        let Some(t) = Self::target(e) else { return self.fail(&e.id, "edge has no IP address") };
        let bs = match self.bootstrapper().await {
            Ok(b) => b,
            Err(err) => return self.fail(&e.id, &format!("{err:#}")),
        };
        let ca_pem = self.store.read(|s| s.ca.cert.clone());
        let ctx = InstallCtx { ca_pem, agents: self.opts.agents.clone() };
        match bs.install(&t, &ctx).await {
            Ok(done) => match pki::fingerprint_pem(&done.cert_pem) {
                Ok(fp) => {
                    self.mutate(&e.id, |x| {
                        x.mgmt_fingerprint = Some(fp.clone());
                        x.mgmt_port = done.mgmt_port;
                        x.wg_public_key = done.wg_public_key.clone();
                    });
                    let wg_note = if done.wg_public_key.is_some() { "WireGuard ready" } else { "no WireGuard (gateway sites unavailable)" };
                    self.transition(&e.id, EdgeStatus::Joining, &format!("installed; pinned identity {}; {wg_note}", &fp[..16]));
                }
                Err(err) => self.fail(&e.id, &format!("edge returned an unusable identity: {err:#}")),
            },
            Err(err) => self.soft_error_or_fail(e, format!("install failed: {err:#}"), 3),
        }
    }

    async fn step_joining(&self, e: &Edge) {
        let client = match self.client_for(e) {
            Ok(c) => c,
            Err(err) => return self.fail(&e.id, &err.to_string()),
        };
        let (routes, wg, hash, gen) = self.store.read(|s| {
            let r = s.routes_for(&e.id);
            let w = s.edge(&e.id).and_then(|x| s.wg_for_edge(x));
            let h = config_hash(&r, &w);
            (r, w, h, s.generation)
        });
        match client.put_config(gen, &routes, wg.as_ref()).await {
            Ok(()) => {
                self.mutate(&e.id, |x| x.applied_hash = Some(hash));
                self.transition(&e.id, EdgeStatus::Healthy, &format!("joined; serving {} route(s)", routes.len()));
                self.audit.record("system", "edge.healthy", &e.id);
            }
            Err(err) if now().saturating_sub(e.status_since) > JOIN_TIMEOUT_SECS => self.fail(
                &e.id,
                &format!("the edge was installed but never accepted its config: {err}. Is TCP port {} open to the controller (provider firewall)?", e.mgmt_port),
            ),
            Err(err) => self.soft_error(&e.id, format!("waiting for the edge: {err}")),
        }
    }

    async fn step_poll(&self, e: &Edge) {
        let client = match self.client_for(e) {
            Ok(c) => c,
            Err(err) => return self.fail(&e.id, &err.to_string()),
        };
        let (routes, wg, desired, gen) = self.store.read(|s| {
            let r = s.routes_for(&e.id);
            let w = s.edge(&e.id).and_then(|x| s.wg_for_edge(x));
            let h = config_hash(&r, &w);
            (r, w, h, s.generation)
        });
        let due = self.live.read().unwrap().get(&e.id).and_then(|l| l.last_poll).is_none_or(|t| t.elapsed() >= self.opts.poll_every);
        let needs_push = e.applied_hash.as_deref() != Some(desired.as_str());
        // A rejected push (e.g. a conflict only this edge sees) is retried at the poll rate, not every tick.
        if !due && !(needs_push && e.error.is_none()) {
            return;
        }

        if needs_push {
            match client.put_config(gen, &routes, wg.as_ref()).await {
                Ok(()) => {
                    self.mutate(&e.id, |x| {
                        x.applied_hash = Some(desired.clone());
                        x.error = None;
                        push_log(x, &format!("applied {} route(s){}", routes.len(), wg.as_ref().map(|w| format!(", {} tunnel peer(s)", w.peers.len())).unwrap_or_default()));
                    });
                }
                Err(ClientError::Rejected(d)) => {
                    self.set_live(&e.id, |l| l.last_poll = Some(Instant::now()));
                    return self.soft_error(&e.id, format!("edge rejected its config: {}", d.join("; ")));
                }
                Err(ClientError::Other(err)) => return self.poll_failed(e, err),
            }
        }
        match client.status().await {
            Ok(v) => {
                self.set_live(&e.id, |l| {
                    l.reachable = true;
                    l.last_seen = Some(now());
                    l.version = v["version"].as_str().map(String::from);
                    l.generation = v["generation"].as_u64();
                    l.consecutive_failures = 0;
                    l.last_error = None;
                    l.status = Some(v);
                    l.last_poll = Some(Instant::now());
                });
                if e.status == EdgeStatus::Unreachable {
                    self.transition(&e.id, EdgeStatus::Healthy, "reachable again");
                }
            }
            Err(err) => self.poll_failed(e, err.to_string()),
        }
    }

    fn poll_failed(&self, e: &Edge, err: String) {
        let mut failures = 0;
        self.set_live(&e.id, |l| {
            l.reachable = false;
            l.consecutive_failures += 1;
            failures = l.consecutive_failures;
            l.last_error = Some(err.clone());
            l.last_poll = Some(Instant::now());
        });
        if failures >= 3 && e.status == EdgeStatus::Healthy {
            self.transition(&e.id, EdgeStatus::Unreachable, &format!("lost contact: {err}"));
            self.mutate(&e.id, |x| x.error = Some(format!("unreachable: {err}")));
            self.audit.record("system", "edge.unreachable", &format!("{}: {err}", e.id));
        }
    }

    async fn step_draining(&self, e: &Edge) {
        let Some(started) = e.drain_started else {
            return self.mutate(&e.id, |x| x.drain_started = Some(now()));
        };
        if let Ok(client) = self.client_for(e) {
            if let Ok(v) = client.status().await {
                self.set_live(&e.id, |l| {
                    l.reachable = true;
                    l.status = Some(v);
                });
            }
        }
        let active = self.live.read().unwrap().get(&e.id).and_then(|l| l.status.as_ref().and_then(|s| s["active_connections"].as_i64()));
        let elapsed = now().saturating_sub(started);
        let limit = self.store.read(|s| s.settings.drain_seconds);
        if elapsed >= limit || (elapsed >= 3 && active == Some(0)) {
            self.transition(&e.id, EdgeStatus::Deleting, "drained");
        }
    }

    async fn step_deleting(&self, e: &Edge) {
        match &e.provider {
            ProviderSpec::Hetzner { .. } => {
                let (h, _) = match self.hetzner() {
                    Ok(x) => x,
                    Err(err) => {
                        return self.soft_error(&e.id, format!("cannot delete the server: {err}. Remove it in the Hetzner console, then use 'forget'"));
                    }
                };
                let sid = match &e.server_id {
                    Some(s) => Some(s.clone()),
                    None => match h.find_by_edge_id(&e.id).await {
                        Ok(x) => x.map(|i| i.id),
                        Err(err) => return self.soft_error(&e.id, format!("{err:#}")),
                    },
                };
                if let Some(sid) = sid {
                    if let Err(err) = h.delete_server(&sid).await {
                        return self.soft_error(&e.id, format!("deleting server {sid}: {err:#}"));
                    }
                    self.mutate(&e.id, |x| push_log(x, &format!("provider deleted server {sid}")));
                }
            }
            ProviderSpec::Manual => {
                if e.attempts == 0 && e.mgmt_fingerprint.is_some() {
                    // The machine is yours: take our software off it, once, best effort.
                    if let (Ok(bs), Some(t)) = (self.bootstrapper().await, Self::target(e)) {
                        let r = bs.uninstall(&t).await;
                        let msg = match r {
                            Ok(()) => "removed edge-lb from the machine".to_string(),
                            Err(err) => format!("could not clean up the machine ({err:#}); remove edge-lbd manually"),
                        };
                        self.mutate(&e.id, |x| {
                            x.attempts = 1;
                            push_log(x, &msg);
                        });
                    }
                }
            }
        }
        if let (Ok(bs), Some(t)) = (self.bootstrapper().await, Self::target(e)) {
            bs.forget(&t).await;
        }
        self.remove_edge("system", &e.id);
    }

    /// Drop an edge record. Routes scoped only to it are disabled rather than silently widening
    /// to "all edges".
    pub(crate) fn remove_edge(&self, actor: &str, id: &str) {
        let mut disabled = Vec::new();
        let _ = self.store.update(|s| {
            s.edges.retain(|e| e.id != id);
            for r in s.routes.iter_mut() {
                if r.edges.iter().any(|x| x == id) {
                    r.edges.retain(|x| x != id);
                    if r.edges.is_empty() {
                        r.route.enabled = false;
                        disabled.push(r.route.name.clone());
                    }
                }
            }
            s.generation += 1;
        });
        self.live.write().unwrap().remove(id);
        let note = if disabled.is_empty() { String::new() } else { format!("; disabled route(s) that only ran there: {}", disabled.join(", ")) };
        self.audit.record(actor, "edge.removed", &format!("{id}{note}"));
    }

    /// Escape hatch: drop the record without touching the provider or the machine.
    pub fn forget_edge(&self, actor: &str, id: &str) -> Result<(), super::CtlError> {
        if self.store.read(|s| s.edge(id).is_none()) {
            return Err(super::CtlError::NotFound(id.into()));
        }
        self.remove_edge(actor, id);
        Ok(())
    }

    // ---- DNS -------------------------------------------------------------------------------------

    async fn dns_tick(&self) {
        let (settings, ips) = self.store.read(|s| {
            let ips: BTreeSet<Ipv4Addr> = s
                .edges
                .iter()
                .filter(|e| e.status.serving())
                .filter_map(|e| match e.ip {
                    Some(IpAddr::V4(v)) => Some(v),
                    _ => None,
                })
                .collect();
            (s.settings.dns.clone(), ips)
        });
        let Some(d) = settings else { return };
        let key = format!("{}|{:?}|{:?}|{}", d.zone_id, d.names, ips, d.ttl);
        {
            let run = self.dns_run.lock().unwrap();
            if run.key == key && run.at.is_some_and(|t| t.elapsed() < DNS_REFRESH) {
                return;
            }
        }
        let result = match dns::Cloudflare::new(&self.opts.cloudflare_base, &d.cloudflare_token, &d.zone_id) {
            Ok(cf) => dns::reconcile(&cf, &d.names, &ips, d.ttl).await,
            Err(e) => Err(e),
        };
        let mut run = self.dns_run.lock().unwrap();
        run.key = key;
        run.at = Some(Instant::now());
        match result {
            Ok(rep) => {
                run.status = super::DnsStatus { last_sync: Some(now()), last_error: None, held: rep.held };
                if rep.created + rep.deleted > 0 {
                    drop(run);
                    self.audit.record("system", "dns.sync", &format!("{} created, {} deleted", rep.created, rep.deleted));
                }
            }
            Err(e) => {
                warn!("dns sync failed: {e:#}");
                run.status.last_error = Some(format!("{e:#}"));
            }
        }
    }
}
