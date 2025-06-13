//! craftclient

use rustls::craft::GreaseOr::Grease;
use rustls::craft::{
    CraftExtension, ExtensionSpec, Fingerprint, GreaseOrCurve, GreaseOrVersion, KeepExtension,
};
use rustls::internal::msgs::enums::{ECPointFormat, ExtensionType, PSKKeyExchangeMode};
use rustls::internal::msgs::handshake::ClientExtension;
use rustls::{craft, NamedGroup, ProtocolVersion, RootCertStore, SignatureScheme};
use static_init::dynamic;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;


macro_rules! static_ref {
    ($val:expr, $type:ty) => {{
        static X: $type = $val;
        X
    }};
}


#[dynamic]
pub static CUSTOM_EXTENSION: Vec<ExtensionSpec> = {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        Keep(Must(ExtensionType::ServerName)),
        Rustls(ClientExtension::ExtendedMasterSecretRequest),
        Craft(CraftExtension::RenegotiationInfo),
        Craft(CraftExtension::SupportedCurves(static_ref!(
            &[
                GreaseOrCurve::T(NamedGroup::X25519MLKEM768),
                GreaseOrCurve::T(NamedGroup::X25519),
                GreaseOrCurve::T(NamedGroup::secp256r1),
                GreaseOrCurve::T(NamedGroup::secp384r1),
                GreaseOrCurve::T(NamedGroup::secp521r1),
                GreaseOrCurve::T(NamedGroup::FFDHE2048),
                GreaseOrCurve::T(NamedGroup::FFDHE3072),
            ],
            &[GreaseOrCurve]
        ))),
        Rustls(ClientExtension::EcPointFormats(vec![
            ECPointFormat::Uncompressed,
        ])),
        Rustls(ClientExtension::SessionTicket()),
        Craft(CraftExtension::Protocols(&[b"h2", b"http/1.1"])),
        Rustls(ClientExtension::CertificateStatusRequest(OCSP_REQ.clone())),
        Craft(CraftExtension::FakeDelegatedCredentials(&[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
        ])),
        Craft(CraftExtension::KeyShare(static_ref!(
            &[
                GreaseOrCurve::T(NamedGroup::X25519),
                GreaseOrCurve::T(NamedGroup::secp256r1),
            ],
            &[GreaseOrCurve]
        ))),
        Craft(CraftExtension::SupportedVersions(static_ref!(
            &[
                GreaseOrVersion::T(ProtocolVersion::TLSv1_3),
                GreaseOrVersion::T(ProtocolVersion::TLSv1_2),
            ],
            &[GreaseOrVersion]
        ))),
        Rustls(ClientExtension::SignatureAlgorithms(
            FIREFOX_105_SIGNATURE_ALGO.to_vec(),
        )),
        Rustls(ClientExtension::PresharedKeyModes(vec![
            PSKKeyExchangeMode::PSK_DHE_KE,
        ])),
        Craft(CraftExtension::FakeRecordSizeLimit(0x4001)),
        Craft(CraftExtension::Padding),
        Keep(Optional(ExtensionType::PreSharedKey)),
    ]
};

#[dynamic]
pub static CUSTOM_FINGERPRINT: Fingerprint = Fingerprint {
    extensions: &CUSTOM_EXTENSION,
    cipher: &craft::CHROME_CIPHER,
    shuffle_extensions: false,
};

fn main() {
    fn request(fingerprint: &'static Fingerprint) {
        let mut root_store = RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
            .with_fingerprint(fingerprint.builder());

        let server_name = "tls.browserleaks.com".try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = TcpStream::connect("tls.browserleaks.com:443").unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(
            concat!(
                "GET / HTTP/1.1\r\n",
                "Host: tls.browserleaks.com\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext).unwrap();
        print!("{}", String::from_utf8_lossy(&plaintext))
    }

    // request(&rustls::craft::FIREFOX_105.test_alpn_http1);
    request(&CUSTOM_FINGERPRINT);
}