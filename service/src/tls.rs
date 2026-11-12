//! rustls plumbing: mutual-TLS server for edges, certificate-pinning client for the controller.

use crate::pki;
use anyhow::Result;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

/// Install the `ring` crypto provider process-wide (idempotent).
pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Edge side: present our self-signed cert, and *require* a client cert signed by the controller CA.
pub fn edge_server_config(cert_pem: &str, key_pem: &str, controller_ca_pem: &str) -> Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    for c in pki::certs_from_pem(controller_ca_pem)? {
        roots.add(c)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider()).build()?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(pki::certs_from_pem(cert_pem)?, pki::key_from_pem(key_pem)?)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Controller side, for gateways: present the controller's self-signed certificate and require no
/// client certificate (a gateway proves itself with a one-time token, then a secret). Gateways pin
/// this certificate, so there is no public CA involved.
pub fn gateway_server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(pki::certs_from_pem(cert_pem)?, pki::key_from_pem(key_pem)?)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Accepts exactly one server certificate: the one whose SHA-256 matches the pin.
/// Handshake signatures are still verified, so possession of the private key is proven.
#[derive(Debug)]
struct PinVerifier {
    fingerprint: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if pki::fingerprint_der(end_entity.as_ref()) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server certificate does not match the pinned fingerprint".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Controller side: pin one edge's certificate and authenticate with our client certificate.
pub fn pinned_client_config(
    pinned_fingerprint: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<ClientConfig> {
    let p = provider();
    let mut cfg = ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            fingerprint: pinned_fingerprint.to_string(),
            provider: p,
        }))
        .with_client_auth_cert(pki::certs_from_pem(client_cert_pem)?, pki::key_from_pem(client_key_pem)?)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// A client that pins the server's certificate but presents NO client certificate: what a gateway
/// uses to talk to the controller.
pub fn pinned_client_config_no_auth(pinned_fingerprint: &str) -> Result<ClientConfig> {
    let p = provider();
    let mut cfg = ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { fingerprint: pinned_fingerprint.to_string(), provider: p }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Serve `app` over TLS on an already-bound listener. Runs until the task is aborted.
pub async fn serve(listener: TcpListener, cfg: Arc<ServerConfig>, app: Router) {
    let acceptor = TlsAcceptor::from(cfg);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("mgmt accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    debug!(%peer, "tls handshake rejected: {e}");
                    return;
                }
                Err(_) => return,
            };
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                .await;
        });
    }
}
