//! Tiny private PKI for the controller <-> edge channel.
//!
//! * The controller owns a CA. It signs its own client certificate; edges trust only that CA.
//! * Each edge generates its own self-signed server certificate (the private key never leaves
//!   the edge). The controller *pins* that exact certificate by fingerprint.
//!
//! Result: an edge only answers the controller, and the controller only talks to the edge it
//! enrolled — no public CA, no hostnames, no DNS involved.

use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Pem {
    pub cert: String,
    pub key: String,
}

impl std::fmt::Debug for Pem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pem { .. }") // never print key material
    }
}

/// The CA's parameters are deterministic, so the issuer can be rebuilt from the key alone.
fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("static params");
    p.distinguished_name.push(DnType::CommonName, "edge-lb controller CA");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p
}

pub fn new_ca() -> Result<Pem> {
    let key = KeyPair::generate()?;
    let cert = ca_params().self_signed(&key)?;
    Ok(Pem { cert: cert.pem(), key: key.serialize_pem() })
}

/// Issue a client-auth certificate signed by the CA.
pub fn issue_client(ca_key_pem: &str, common_name: &str) -> Result<Pem> {
    let issuer = Issuer::new(ca_params(), KeyPair::from_pem(ca_key_pem).context("CA key")?);
    let key = KeyPair::generate()?;
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name.push(DnType::CommonName, common_name);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = p.signed_by(&key, &issuer)?;
    Ok(Pem { cert: cert.pem(), key: key.serialize_pem() })
}

/// A self-signed server certificate for an edge's management endpoint.
pub fn self_signed_server() -> Result<Pem> {
    let key = KeyPair::generate()?;
    let mut p = CertificateParams::new(vec!["edge-lb-edge".to_string()])?;
    p.distinguished_name.push(DnType::CommonName, "edge-lb edge");
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = p.self_signed(&key)?;
    Ok(Pem { cert: cert.pem(), key: key.serialize_pem() })
}

pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("bad certificate PEM: {e}"))
}

pub fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| anyhow!("bad private key PEM: {e}"))
}

pub fn fingerprint_der(der: &[u8]) -> String {
    Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 fingerprint of the first certificate in a PEM blob.
pub fn fingerprint_pem(pem: &str) -> Result<String> {
    let certs = certs_from_pem(pem)?;
    let first = certs.first().ok_or_else(|| anyhow!("no certificate in PEM"))?;
    Ok(fingerprint_der(first.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_parseable_material_and_stable_fingerprints() {
        let ca = new_ca().unwrap();
        let client = issue_client(&ca.key, "controller").unwrap();
        let server = self_signed_server().unwrap();
        for p in [&ca, &client, &server] {
            assert_eq!(certs_from_pem(&p.cert).unwrap().len(), 1);
            key_from_pem(&p.key).unwrap();
        }
        let fp = fingerprint_pem(&server.cert).unwrap();
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, fingerprint_pem(&server.cert).unwrap());
        assert_ne!(fp, fingerprint_pem(&ca.cert).unwrap());
    }

    #[test]
    fn debug_never_leaks_keys() {
        let ca = new_ca().unwrap();
        assert!(!format!("{ca:?}").contains("PRIVATE"));
    }
}
