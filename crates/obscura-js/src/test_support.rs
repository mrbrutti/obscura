//! Test-only TLS fixture, mirroring the private one in obscura-net: a
//! throwaway CA signs a 127.0.0.1 leaf that serves one canned HTTPS response
//! on an ephemeral port.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const FIXTURE_BODY: &str = "private ca ok";

/// Returns the port and the CA certificate as PEM.
pub(crate) async fn https_fixture_with_private_ca() -> (u16, String) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    // A CA name distinct from the leaf's and from other fixtures' (OpenSSL-style
    // verifiers pick the issuer by name).
    static NEXT_CA: AtomicUsize = AtomicUsize::new(1);
    let ca_number = NEXT_CA.fetch_add(1, Ordering::Relaxed);
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("obscura-js test CA {ca_number}"),
    );
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    let certs = vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
        leaf_cert.der().to_vec(),
    )];
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
    );
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let _ = tls.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    FIXTURE_BODY.len(),
                    FIXTURE_BODY
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    (port, ca_cert.pem())
}
