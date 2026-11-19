/// Issue a short-lived server certificate for the loopback HTTPS fixture.
/// macOS also checks the validity period of locally issued TLS leaves.
pub fn loopback_certificates() -> (String, String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use std::time::{Duration, SystemTime};

    let mut ca = CertificateParams::default();
    ca.distinguished_name
        .push(DnType::CommonName, "prefixd readiness fixture CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let root = ca.self_signed(&ca_key).unwrap();

    let mut leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    let now = SystemTime::now();
    leaf.not_before = (now - Duration::from_secs(60)).into();
    leaf.not_after = (now + Duration::from_secs(3600)).into();
    leaf.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf_key = KeyPair::generate().unwrap();
    let certificate = leaf.signed_by(&leaf_key, &Issuer::new(ca, ca_key)).unwrap();
    (root.pem(), certificate.pem(), leaf_key.serialize_pem())
}
