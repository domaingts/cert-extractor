use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateMetadata {
    pub index: usize,
    pub role: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_until: String,
    pub validity_status: String,
    pub sha256_fingerprint: String,
    pub subject_alt_names: Vec<String>,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub is_ca: bool,
    pub der_size: usize,
    pub warnings: Vec<String>,
}

pub fn parse_certificate(index: usize, der: &[u8]) -> CertificateMetadata {
    let fingerprint = Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    let parsed = parse_x509_certificate(der);
    let Ok((_, certificate)) = parsed else {
        return CertificateMetadata {
            index,
            role: if index == 0 { "leaf" } else { "certificate" }.into(),
            subject: "Unable to parse certificate subject".into(),
            issuer: "Unable to parse certificate issuer".into(),
            serial_number: String::new(),
            valid_from: String::new(),
            valid_until: String::new(),
            validity_status: "unknown".into(),
            sha256_fingerprint: fingerprint,
            subject_alt_names: Vec::new(),
            signature_algorithm: String::new(),
            public_key_algorithm: String::new(),
            is_ca: false,
            der_size: der.len(),
            warnings: vec![
                "The certificate was captured but its metadata could not be parsed.".into(),
            ],
        };
    };

    let is_ca = certificate.is_ca();
    let self_issued = certificate.subject() == certificate.issuer();
    let role = if index == 0 {
        "leaf"
    } else if is_ca && self_issued {
        "presented_root"
    } else if is_ca {
        "intermediate"
    } else {
        "certificate"
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    let validity = certificate.validity();
    let validity_status = if now < validity.not_before.timestamp() {
        "not_yet_valid"
    } else if now > validity.not_after.timestamp() {
        "expired"
    } else {
        "valid"
    };

    let mut subject_alt_names = Vec::new();
    let mut warnings = Vec::new();
    match certificate.subject_alternative_name() {
        Ok(Some(extension)) => {
            for name in &extension.value.general_names {
                match name {
                    GeneralName::DNSName(value) => subject_alt_names.push(format!("DNS: {value}")),
                    GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                        subject_alt_names.push(format!(
                            "IP: {}",
                            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                        ));
                    }
                    GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                        let mut octets = [0_u8; 16];
                        octets.copy_from_slice(bytes);
                        subject_alt_names.push(format!("IP: {}", Ipv6Addr::from(octets)));
                    }
                    GeneralName::URI(value) => subject_alt_names.push(format!("URI: {value}")),
                    _ => {}
                }
            }
        }
        Ok(None) => {}
        Err(error) => warnings.push(format!(
            "Subject alternative names could not be parsed: {error}"
        )),
    }

    CertificateMetadata {
        index,
        role: role.into(),
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        serial_number: certificate.raw_serial_as_string(),
        valid_from: validity.not_before.to_string(),
        valid_until: validity.not_after.to_string(),
        validity_status: validity_status.into(),
        sha256_fingerprint: fingerprint,
        subject_alt_names,
        signature_algorithm: certificate.signature_algorithm.algorithm.to_id_string(),
        public_key_algorithm: certificate.public_key().algorithm.algorithm.to_id_string(),
        is_ca,
        der_size: der.len(),
        warnings,
    }
}
