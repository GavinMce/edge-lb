//! Keep an nftables set in step with the ports we listen on, so the strict firewall
//! opens exactly the ports your routes need and nothing else.

use anyhow::{anyhow, bail, Result};
use std::collections::BTreeSet;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftSet {
    pub family: String,
    pub table: String,
    pub set: String,
}

impl NftSet {
    /// Parse `family:table:set`, e.g. `inet:edge_lb:routes`.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            bail!("expected family:table:set (e.g. inet:edge_lb:routes), got '{s}'");
        }
        for p in &parts {
            if !p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                bail!("invalid nftables identifier '{p}'");
            }
        }
        Ok(Self { family: parts[0].into(), table: parts[1].into(), set: parts[2].into() })
    }

    pub fn script(&self, ports: &BTreeSet<u16>) -> String {
        let mut s = format!("flush set {} {} {}\n", self.family, self.table, self.set);
        if !ports.is_empty() {
            let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
            s += &format!(
                "add element {} {} {} {{ {} }}\n",
                self.family,
                self.table,
                self.set,
                list.join(", ")
            );
        }
        s
    }

    /// Replace the set contents atomically (one nft transaction).
    pub async fn sync(&self, ports: &BTreeSet<u16>) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("cannot run nft: {e}"))?;
        child.stdin.take().unwrap().write_all(self.script(ports).as_bytes()).await?;
        let out = child.wait_with_output().await?;
        if !out.status.success() {
            bail!("nft failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_script() {
        let s = NftSet::parse("inet:edge_lb:routes").unwrap();
        assert_eq!(s.script(&BTreeSet::new()), "flush set inet edge_lb routes\n");
        let ports: BTreeSet<u16> = [443, 25565, 80].into();
        assert_eq!(
            s.script(&ports),
            "flush set inet edge_lb routes\nadd element inet edge_lb routes { 80, 443, 25565 }\n"
        );
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(NftSet::parse("inet:edge_lb").is_err());
        assert!(NftSet::parse("inet:edge lb:routes").is_err());
        assert!(NftSet::parse("inet:x;flush ruleset:routes").is_err());
    }
}
