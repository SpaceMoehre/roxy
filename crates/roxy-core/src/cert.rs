//! TLS CA certificate generation and per-domain MITM leaf certificates.
//!
//! [`CertManager`] is the central entry-point for all certificate operations.
//! On first start it either loads an existing root CA from disk or generates a
//! new one.  When the proxy intercepts an HTTPS CONNECT tunnel it calls
//! [`CertManager::get_or_create_domain_cert`] to obtain a leaf certificate
//! signed by that root CA, enabling transparent man-in-the-middle inspection.
//!
//! Generated CA material is persisted under the configured storage directory as
//! `ca-cert.pem` and `ca-key.pem` so the user can import the root into their
//! system trust store once and all future sessions are automatically trusted.
//!
//! Domain leaf certificates are cached in a lock-free [`DashMap`] so
//! concurrent CONNECT tunnels to the same host do not regenerate the
//! certificate.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    date_time_ymd,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Serialisable snapshot of the root CA certificate material.
///
/// Returned by [`CertManager::regenerate_ca`] and used internally to persist
/// the CA to disk and export it to the API layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaCertificate {
    /// DER-encoded root certificate bytes.
    pub cert_der: Vec<u8>,
    /// PEM-encoded root certificate.
    pub cert_pem: String,
    /// PEM-encoded root CA private key.
    pub key_pem: String,
}

/// A per-domain leaf certificate signed by the roxy root CA.
///
/// Used by the TLS acceptor in
/// [`build_downstream_mitm_acceptor`](roxy_tls::server::build_downstream_mitm_acceptor)
/// to present a trusted certificate to the downstream client during MITM
/// interception.
#[derive(Clone, Debug)]
pub struct DomainCertificate {
    /// DER-encoded leaf certificate bytes.
    pub cert_der: Vec<u8>,
    /// DER-encoded leaf private key bytes.
    pub key_der: Vec<u8>,
}

/// Internal bundle holding the parsed rcgen objects alongside the serialised
/// public data.
struct RootCaMaterial {
    cert: Certificate,
    key: KeyPair,
    pub_data: CaCertificate,
}

/// Manages the proxy's root CA and per-domain leaf certificates.
///
/// Cheaply [`Clone`]-able — all interior state is behind `Arc`.
///
/// # Thread safety
///
/// * The root CA is protected by a [`RwLock`] so it can be regenerated at
///   runtime without stopping the proxy.
/// * Domain leaf certificates are cached in a lock-free [`DashMap`].
#[derive(Clone)]
pub struct CertManager {
    /// Filesystem directory where `ca-cert.pem` / `ca-key.pem` are stored.
    storage_dir: PathBuf,
    /// Current root CA material (read-heavy, write-rare).
    root: Arc<RwLock<RootCaMaterial>>,
    /// Domain → leaf cert cache.
    domain_cache: Arc<DashMap<String, DomainCertificate>>,
}

impl CertManager {
    /// Loads an existing root CA from `storage_dir`, or generates and persists
    /// a new one if none exists.
    ///
    /// The directory is created automatically if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error when the storage directory cannot be created, the
    /// existing PEM files cannot be read/parsed, or key generation fails.
    pub fn load_or_create(storage_dir: impl AsRef<Path>) -> Result<Self> {
        let storage_dir = storage_dir.as_ref().to_path_buf();
        fs::create_dir_all(&storage_dir)
            .with_context(|| format!("failed to create cert directory {:?}", storage_dir))?;

        let root = load_or_create_root_ca(&storage_dir)?;
        Ok(Self {
            storage_dir,
            root: Arc::new(RwLock::new(root)),
            domain_cache: Arc::new(DashMap::new()),
        })
    }

    /// Returns a clone of the DER-encoded root CA certificate.
    pub async fn export_ca_der(&self) -> Vec<u8> {
        self.root.read().await.pub_data.cert_der.clone()
    }

    /// Returns a clone of the PEM-encoded root CA certificate.
    pub async fn export_ca_pem(&self) -> String {
        self.root.read().await.pub_data.cert_pem.clone()
    }

    /// Generates a brand-new root CA, persists it to disk, and clears the
    /// domain leaf cache so subsequent CONNECT tunnels receive certificates
    /// signed by the new CA.
    ///
    /// # Errors
    ///
    /// Returns an error when key generation or filesystem I/O fails.
    pub async fn regenerate_ca(&self) -> Result<CaCertificate> {
        let root = generate_root_ca()?;
        persist_root_ca(&self.storage_dir, &root.pub_data)?;
        self.domain_cache.clear();
        let result = root.pub_data.clone();
        *self.root.write().await = root;
        Ok(result)
    }

    /// Returns a cached leaf certificate for `domain`, generating and caching
    /// a new one signed by the current root CA if none exists yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the domain string is invalid for certificate
    /// generation or when key generation fails.
    pub async fn get_or_create_domain_cert(&self, domain: &str) -> Result<DomainCertificate> {
        if let Some(cert) = self.domain_cache.get(domain) {
            return Ok(cert.clone());
        }

        let root = self.root.read().await;
        let cert = generate_leaf_cert(domain, &root.cert, &root.key)?;
        self.domain_cache.insert(domain.to_string(), cert.clone());
        Ok(cert)
    }
}

/// Attempts to load the root CA from PEM files on disk; falls back to
/// generating and persisting a new one.
fn load_or_create_root_ca(storage_dir: &Path) -> Result<RootCaMaterial> {
    let cert_pem_path = storage_dir.join("ca-cert.pem");
    let key_pem_path = storage_dir.join("ca-key.pem");

    if cert_pem_path.exists() && key_pem_path.exists() {
        let cert_pem = fs::read_to_string(&cert_pem_path)
            .with_context(|| format!("failed reading {:?}", cert_pem_path))?;
        let key_pem = fs::read_to_string(&key_pem_path)
            .with_context(|| format!("failed reading {:?}", key_pem_path))?;

        let key = KeyPair::from_pem(&key_pem).context("failed parsing CA private key pem")?;
        let params = root_params();
        let cert = params
            .self_signed(&key)
            .context("failed rebuilding deterministic root cert")?;
        let cert_der = cert.der().to_vec();

        let root = RootCaMaterial {
            cert,
            key,
            pub_data: CaCertificate {
                cert_der,
                cert_pem,
                key_pem,
            },
        };
        return Ok(root);
    }

    let root = generate_root_ca()?;
    persist_root_ca(storage_dir, &root.pub_data)?;
    Ok(root)
}

/// Writes the root CA PEM files to disk.
fn persist_root_ca(storage_dir: &Path, ca: &CaCertificate) -> Result<()> {
    let cert_pem_path = storage_dir.join("ca-cert.pem");
    let key_pem_path = storage_dir.join("ca-key.pem");
    fs::write(&cert_pem_path, &ca.cert_pem)
        .with_context(|| format!("failed writing {:?}", cert_pem_path))?;
    fs::write(&key_pem_path, &ca.key_pem)
        .with_context(|| format!("failed writing {:?}", key_pem_path))?;
    Ok(())
}

/// Builds deterministic [`CertificateParams`] for the root CA (fixed DN,
/// validity window 2024–2040, unconstrained CA basic constraint).
fn root_params() -> CertificateParams {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Roxy Proxy");
    dn.push(DnType::CommonName, "Roxy Local Root CA");

    let mut params = CertificateParams::new(vec!["roxy.local".to_string()])
        .expect("root certificate params should be valid");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2040, 1, 1);
    params
}

/// Generates a fresh root CA key-pair and self-signed certificate.
fn generate_root_ca() -> Result<RootCaMaterial> {
    let key = KeyPair::generate().context("failed generating CA keypair")?;
    let params = root_params();
    let cert = params
        .self_signed(&key)
        .context("failed creating root CA certificate")?;
    let pub_data = CaCertificate {
        cert_der: cert.der().to_vec(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    };

    Ok(RootCaMaterial {
        cert,
        key,
        pub_data,
    })
}

/// Generates a leaf certificate for `domain` signed by the given issuer.
fn generate_leaf_cert(
    domain: &str,
    issuer_cert: &Certificate,
    issuer_key: &KeyPair,
) -> Result<DomainCertificate> {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .with_context(|| format!("invalid domain for cert generation: {domain}"))?;
    params
        .distinguished_name
        .push(DnType::CommonName, domain.to_string());

    let leaf_key = KeyPair::generate().context("failed generating leaf keypair")?;
    let cert = params
        .signed_by(&leaf_key, issuer_cert, issuer_key)
        .context("failed signing leaf certificate")?;

    Ok(DomainCertificate {
        cert_der: cert.der().to_vec(),
        key_der: leaf_key.serialize_der(),
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn domain_cert_is_cached() {
        let temp = TempDir::new().expect("tempdir");
        let manager = CertManager::load_or_create(temp.path()).expect("manager");

        let first = manager
            .get_or_create_domain_cert("example.com")
            .await
            .expect("first cert");
        let second = manager
            .get_or_create_domain_cert("example.com")
            .await
            .expect("second cert");

        assert_eq!(first.cert_der, second.cert_der);
        assert_eq!(first.key_der, second.key_der);
    }

    #[tokio::test]
    async fn regenerate_changes_cert_material() {
        let temp = TempDir::new().expect("tempdir");
        let manager = CertManager::load_or_create(temp.path()).expect("manager");

        let before = manager.export_ca_der().await;
        manager.regenerate_ca().await.expect("regenerate");
        let after = manager.export_ca_der().await;

        assert_ne!(before, after);
    }
}
