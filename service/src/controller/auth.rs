//! Admin password hashing, login sessions, and brute-force throttling.

use anyhow::{anyhow, Result};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MIN_PASSWORD_LEN: usize = 12;
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const FREE_ATTEMPTS: u32 = 5;

pub fn hash_password(pw: &str) -> Result<String> {
    if pw.chars().count() < MIN_PASSWORD_LEN {
        return Err(anyhow!("password must be at least {MIN_PASSWORD_LEN} characters"));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| anyhow!("hashing failed: {e}"))
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash).map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok()).unwrap_or(false)
}

fn random_token() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sessions are looked up by the hash of the cookie value, so a memory dump of the map
/// doesn't hand out usable cookies.
fn key(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

struct Session {
    username: String,
    expires: Instant,
}

struct Throttle {
    failures: u32,
    locked_until: Option<Instant>,
}

#[derive(Default)]
pub struct Sessions {
    sessions: Mutex<HashMap<String, Session>>,
    throttle: Mutex<HashMap<IpAddr, Throttle>>,
}

impl Sessions {
    pub fn create(&self, username: &str) -> String {
        let token = random_token();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, v| v.expires > Instant::now());
        s.insert(key(&token), Session { username: username.to_string(), expires: Instant::now() + SESSION_TTL });
        token
    }

    pub fn lookup(&self, token: &str) -> Option<String> {
        let mut s = self.sessions.lock().unwrap();
        let k = key(token);
        match s.get_mut(&k) {
            Some(sess) if sess.expires > Instant::now() => {
                sess.expires = Instant::now() + SESSION_TTL; // sliding
                Some(sess.username.clone())
            }
            Some(_) => {
                s.remove(&k);
                None
            }
            None => None,
        }
    }

    pub fn destroy(&self, token: &str) {
        self.sessions.lock().unwrap().remove(&key(token));
    }

    pub fn destroy_all(&self) {
        self.sessions.lock().unwrap().clear();
    }

    /// Time left on a lockout, if this address is currently locked out.
    pub fn locked_for(&self, ip: IpAddr) -> Option<Duration> {
        let t = self.throttle.lock().unwrap();
        t.get(&ip).and_then(|t| t.locked_until).and_then(|u| u.checked_duration_since(Instant::now()))
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut t = self.throttle.lock().unwrap();
        let e = t.entry(ip).or_insert(Throttle { failures: 0, locked_until: None });
        e.failures += 1;
        if e.failures >= FREE_ATTEMPTS {
            let secs = (30u64 << (e.failures - FREE_ATTEMPTS).min(5)).min(900);
            e.locked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.throttle.lock().unwrap().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip_and_policy() {
        assert!(hash_password("short").is_err());
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterY", &h));
        assert!(!verify_password("x", "not-a-hash"));
    }

    #[test]
    fn sessions_expire_and_are_revocable() {
        let s = Sessions::default();
        let t = s.create("admin");
        assert_eq!(s.lookup(&t).as_deref(), Some("admin"));
        assert!(s.lookup("nope").is_none());
        s.destroy(&t);
        assert!(s.lookup(&t).is_none());
        let t2 = s.create("admin");
        s.destroy_all();
        assert!(s.lookup(&t2).is_none());
    }

    #[test]
    fn lockout_after_repeated_failures_and_reset_on_success() {
        let s = Sessions::default();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..4 {
            s.record_failure(ip);
        }
        assert!(s.locked_for(ip).is_none());
        s.record_failure(ip);
        assert!(s.locked_for(ip).is_some());
        s.record_success(ip);
        assert!(s.locked_for(ip).is_none());
        // Another address is unaffected.
        assert!(s.locked_for("203.0.113.6".parse().unwrap()).is_none());
    }
}
