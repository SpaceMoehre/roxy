use ::time::OffsetDateTime;
use rcgen::DnValue::PrintableString;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use time::Duration;


pub async fn generate_ca_cert() -> (CertificateParams, Certificate, KeyPair) {
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
        .push(DnType::OrganizationName, "Crab widgits SE");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.clone().self_signed(&key_pair).unwrap();
    (params, cert, key_pair)
}

pub async fn generate_mitm_cert(
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
