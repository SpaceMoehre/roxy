//! Downstream MITM TLS acceptor.
//!
//! Builds a [`SslAcceptor`] from a DER-encoded leaf certificate and
//! private key so the proxy can terminate TLS on behalf of the
//! intercepted domain.

use anyhow::{Context, Result};
use boring::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslVersion},
    x509::X509,
};

/// Creates a BoringSSL TLS acceptor configured for MITM interception.
///
/// The acceptor uses Mozilla’s intermediate v5 configuration, TLS
/// 1.2–1.3, and advertises `http/1.1` via ALPN.
///
/// # Errors
///
/// Returns an error if the DER cannot be parsed or the
/// certificate/key pair is invalid.
pub fn build_downstream_mitm_acceptor(cert_der: &[u8], key_der: &[u8]) -> Result<SslAcceptor> {
    let cert =
        X509::from_der(cert_der).context("failed parsing generated leaf certificate for TLS")?;
    let key = PKey::private_key_from_der(key_der)
        .context("failed parsing generated leaf private key for TLS")?;

    let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .context("failed building downstream TLS acceptor")?;
    tls_builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .context("failed setting downstream TLS minimum protocol version")?;
    tls_builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("failed setting downstream TLS maximum protocol version")?;
    tls_builder
        .set_certificate(&cert)
        .context("failed assigning downstream certificate")?;
    tls_builder
        .set_private_key(&key)
        .context("failed assigning downstream private key")?;
    tls_builder
        .check_private_key()
        .context("downstream certificate/private key mismatch")?;
    tls_builder
        .set_alpn_protos(b"\x08http/1.1")
        .context("failed configuring downstream ALPN protocol list")?;

    Ok(tls_builder.build())
}
