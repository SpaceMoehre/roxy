//! roxy_core `cert` module.
//!
//! Exposes public types and functions used by the `roxy` runtime and API surface.

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

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents `CaCertificate`.
///
/// See also: [`CaCertificate`].
pub struct CaCertificate {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Clone, Debug)]
/// Represents `DomainCertificate`.
///
/// See also: [`DomainCertificate`].
pub struct DomainCertificate {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

struct RootCaMaterial {
    cert: Certificate,
    key: KeyPair,
    pub_data: CaCertificate,
}

#[derive(Clone)]
/// Represents `CertManager`.
///
/// See also: [`CertManager`].
pub struct CertManager {
    storage_dir: PathBuf,
    root: Arc<RwLock<RootCaMaterial>>,
    domain_cache: Arc<DashMap<String, DomainCertificate>>,
}

impl CertManager {
    /// Loads `or create`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
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

    /// Exports `ca der`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    pub async fn export_ca_der(&self) -> Vec<u8> {
        self.root.read().await.pub_data.cert_der.clone()
    }

    /// Exports `ca pem`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    pub async fn export_ca_pem(&self) -> String {
        self.root.read().await.pub_data.cert_pem.clone()
    }

    /// Executes `regenerate ca`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn regenerate_ca(&self) -> Result<CaCertificate> {
        let root = generate_root_ca()?;
        persist_root_ca(&self.storage_dir, &root.pub_data)?;
        self.domain_cache.clear();
        let result = root.pub_data.clone();
        *self.root.write().await = root;
        Ok(result)
    }

    /// Gets `or create domain cert`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
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

fn persist_root_ca(storage_dir: &Path, ca: &CaCertificate) -> Result<()> {
    let cert_pem_path = storage_dir.join("ca-cert.pem");
    let key_pem_path = storage_dir.join("ca-key.pem");
    fs::write(&cert_pem_path, &ca.cert_pem)
        .with_context(|| format!("failed writing {:?}", cert_pem_path))?;
    fs::write(&key_pem_path, &ca.key_pem)
        .with_context(|| format!("failed writing {:?}", key_pem_path))?;
    Ok(())
}

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
