//! Upstream TLS client connector.
//!
//! Provides a lazily-initialised, globally-cached [`SslConnector`]
//! pre-configured with:
//!
//! * TLS 1.2–1.3
//! * **X25519MLKEM768** post-quantum key exchange (falls back to
//!   X25519 on older BoringSSL builds)
//! * **Brotli** certificate decompression
//! * **ALPN** for `h2` + `http/1.1`

use std::{
    io,
    sync::{Arc, OnceLock},
};

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVerifyMode,
    SslVersion,
};
use tracing::warn;

/// Returns a shared, immutable [`SslConnector`] suitable for outbound
/// HTTPS requests.
///
/// Two separate connectors are cached: one that verifies peer
/// certificates and one that does not.  The connector is built once
/// on first call and reused for the lifetime of the process.
pub fn client_connector(accept_invalid_certs: bool) -> Arc<SslConnector> {
    static STRICT: OnceLock<Arc<SslConnector>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<SslConnector>> = OnceLock::new();

    if accept_invalid_certs {
        INSECURE
            .get_or_init(|| Arc::new(build_client_connector(true)))
            .clone()
    } else {
        STRICT
            .get_or_init(|| Arc::new(build_client_connector(false)))
            .clone()
    }
}

/// Returns a shared [`SslConnector`] that only advertises HTTP/1.1
/// during ALPN negotiation, suitable for retrying requests that
/// failed over HTTP/2 with a protocol error.
pub fn client_connector_h1_only(accept_invalid_certs: bool) -> Arc<SslConnector> {
    static STRICT_H1: OnceLock<Arc<SslConnector>> = OnceLock::new();
    static INSECURE_H1: OnceLock<Arc<SslConnector>> = OnceLock::new();

    if accept_invalid_certs {
        INSECURE_H1
            .get_or_init(|| Arc::new(build_client_connector_impl(true, false)))
            .clone()
    } else {
        STRICT_H1
            .get_or_init(|| Arc::new(build_client_connector_impl(false, false)))
            .clone()
    }
}

fn build_client_connector(accept_invalid_certs: bool) -> SslConnector {
    build_client_connector_impl(accept_invalid_certs, true)
}

fn build_client_connector_impl(accept_invalid_certs: bool, enable_h2: bool) -> SslConnector {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).expect("failed building TLS connector");
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .expect("failed setting TLS minimum protocol version");
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .expect("failed setting TLS maximum protocol version");
    if let Err(err) = builder.set_curves_list("X25519MLKEM768") {
        warn!(
            %err,
            "upstream does not support X25519MLKEM768 in this BoringSSL build; falling back to X25519"
        );
        builder
            .set_curves_list("X25519")
            .expect("failed setting TLS fallback key exchange groups");
    }
    builder
        .set_sigalgs_list("ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256")
        .expect("failed setting TLS signature algorithms");
    builder.enable_signed_cert_timestamps();
    if let Err(err) = builder.add_certificate_compression_algorithm(BrotliCertCompression) {
        warn!(
            %err,
            "failed enabling TLS certificate compression extension for client"
        );
    }
    builder.set_permute_extensions(false);
    builder.set_verify(if accept_invalid_certs {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });
    let alpn = if enable_h2 {
        &b"\x02h2\x08http/1.1"[..]
    } else {
        &b"\x08http/1.1"[..]
    };
    builder
        .set_alpn_protos(alpn)
        .expect("failed configuring TLS ALPN protocol list");
    builder.build()
}

#[derive(Clone, Copy, Debug)]
struct BrotliCertCompression;

impl CertificateCompressor for BrotliCertCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, _input: &[u8], _output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "certificate compression is not used on client-side sends",
        ))
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        brotli::BrotliDecompress(&mut io::Cursor::new(input), output)
    }
}
