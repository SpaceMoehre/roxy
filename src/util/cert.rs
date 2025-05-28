use ::time::OffsetDateTime;
use rcgen::DnValue::PrintableString;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::collections::HashMap;
use time::Duration;

use crate::CERT_MANAGER;

pub struct CertificateManager {
    ca_params: CertificateParams,
    ca_cert: Certificate,
    ca_key: KeyPair,
    certs: HashMap<String, (Certificate, KeyPair)>,
}
impl CertificateManager {
    pub fn new() -> Self {
        let (ca_params, ca_cert, ca_key) = generate_ca_cert();
        CertificateManager {
            ca_params,
            ca_cert,
            ca_key,
            certs: HashMap::new(),
        }
    }

    pub fn get_cert(&mut self, name: &str) -> Option<&(Certificate, KeyPair)> {
        if self.certs.get(name).is_none() {
            println!("Certificate for {} not found, generating new one.", name);
            self.generate_mitm_cert(name);
        }
        self.certs.get(name)
    }

    fn generate_mitm_cert(&mut self, name: &str) {
        let (cert, keypair) =
            generate_mitm_cert(&self.ca_params, &self.ca_cert, &self.ca_key, name);
        self.certs.insert(name.to_string(), (cert, keypair));
    }
}

pub fn generate_ca_cert() -> (CertificateParams, Certificate, KeyPair) {
    let mut params =
        CertificateParams::new(Vec::default()).expect("empty subject alt name can't produce error");
    let (yesterday, tomorrow) = validity_period();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(
        DnType::CountryName,
        PrintableString("BR".try_into().unwrap()),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ROXY");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.clone().self_signed(&key_pair).unwrap();
    (params, cert, key_pair)
}

pub fn generate_mitm_cert(
    ca: &CertificateParams,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    name: &str,
) -> (Certificate, KeyPair) {
    let _ = ca;
    let mut params = CertificateParams::new(vec![name.into()]).expect("we know the name is valid");
    let (yesterday, tomorrow) = validity_period();
    params.distinguished_name.push(DnType::CommonName, name);
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    (
        params.signed_by(&key_pair, ca_cert, ca_key).unwrap(),
        key_pair,
    )
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = Duration::new(86400, 0);
    let yesterday = OffsetDateTime::now_utc() - day;
    let tomorrow = OffsetDateTime::now_utc() + day;
    (yesterday, tomorrow)
}

pub async fn get_certificate(name: &str) -> Option<(Certificate, KeyPair)> {
    let manager = CERT_MANAGER.clone();
    println!("Certificate manager acquired");
    let mut cert_manager = manager.lock().await;
    println!("Certificate manager locked");
    cert_manager.get_cert(name).map(|(cert, keypair)| (cert.clone(), keypair.clone()))
}
