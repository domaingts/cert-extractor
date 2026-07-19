use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Serialize;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::endpoint::Endpoint;
use crate::error::ApiError;

const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSummary {
    pub connected_address: String,
    pub tls_version: String,
    pub cipher_suite: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResult {
    pub status: String,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub struct TlsExtraction {
    pub certificates: Vec<Vec<u8>>,
    pub connection: ConnectionSummary,
    pub validation: ValidationResult,
}

#[derive(Debug)]
struct InspectionVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for InspectionVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn extract<F>(endpoint: &Endpoint, mut progress: F) -> Result<TlsExtraction, ApiError>
where
    F: FnMut(&str, String),
{
    progress("resolving_dns", format!("Resolving {}", endpoint.host));
    let addresses = timeout(
        DNS_TIMEOUT,
        lookup_host((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| {
        ApiError::new(
            "dns_timeout",
            "resolving_dns",
            "DNS resolution timed out.",
            None,
            true,
        )
    })?
    .map_err(|error| {
        ApiError::new(
            "dns_failed",
            "resolving_dns",
            "The hostname could not be resolved.",
            Some(error.to_string()),
            true,
        )
    })?;

    let mut unique: Vec<SocketAddr> = addresses.collect();
    unique.sort_unstable();
    unique.dedup();
    if unique.is_empty() {
        return Err(ApiError::new(
            "no_addresses",
            "resolving_dns",
            "The hostname did not resolve to an address.",
            None,
            true,
        ));
    }

    let mut last_error = None;
    let mut connected = None;
    for address in unique {
        progress("connecting", format!("Connecting to {address}"));
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                connected = Some((address, stream));
                break;
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some(format!("Connection to {address} timed out")),
        }
    }
    let (connected_address, tcp_stream) = connected.ok_or_else(|| {
        ApiError::new(
            "connection_failed",
            "connecting",
            "Could not connect to the server.",
            last_error,
            true,
        )
    })?;

    progress(
        "negotiating_tls",
        format!("Negotiating TLS with {connected_address}"),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(InspectionVerifier {
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| ApiError::internal("negotiating_tls", error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream = timeout(
        HANDSHAKE_TIMEOUT,
        connector.connect(endpoint.server_name.clone(), tcp_stream),
    )
    .await
    .map_err(|_| {
        ApiError::new(
            "tls_timeout",
            "negotiating_tls",
            "The TLS handshake timed out.",
            None,
            true,
        )
    })?
    .map_err(|error| {
        ApiError::new(
            "tls_protocol_failed",
            "negotiating_tls",
            "The server did not complete a usable TLS handshake.",
            Some(error.to_string()),
            true,
        )
    })?;

    let (_, connection) = tls_stream.get_ref();
    let peer_certificates = connection.peer_certificates().ok_or_else(|| {
        ApiError::new(
            "empty_certificate_chain",
            "capturing_chain",
            "The server did not present a certificate.",
            None,
            false,
        )
    })?;
    if peer_certificates.is_empty() {
        return Err(ApiError::new(
            "empty_certificate_chain",
            "capturing_chain",
            "The server did not present a certificate.",
            None,
            false,
        ));
    }

    let certificates: Vec<Vec<u8>> = peer_certificates
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    let connection_summary = ConnectionSummary {
        connected_address: connected_address.to_string(),
        tls_version: connection
            .protocol_version()
            .map(|version| format!("{version:?}"))
            .unwrap_or_else(|| "Unknown".into()),
        cipher_suite: connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite()))
            .unwrap_or_else(|| "Unknown".into()),
    };

    progress(
        "validating_certificate",
        "Checking the captured chain against the operating system trust store".into(),
    );
    let validation_endpoint = endpoint.clone();
    let validation_certificates: Vec<CertificateDer<'static>> = certificates
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let validation = match timeout(
        VALIDATION_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            validate_chain(&validation_endpoint, &validation_certificates)
        }),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => ValidationResult {
            status: "validation_failed".into(),
            message: "The certificate was extracted, but trust validation could not be completed. Export remains available for inspection.".into(),
            detail: Some(error.to_string()),
        },
        Err(_) => ValidationResult {
            status: "validation_failed".into(),
            message: "The certificate was extracted, but trust validation timed out. Export remains available for inspection.".into(),
            detail: None,
        },
    };

    Ok(TlsExtraction {
        certificates,
        connection: connection_summary,
        validation,
    })
}

fn validate_chain(endpoint: &Endpoint, certificates: &[CertificateDer<'_>]) -> ValidationResult {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let mut root_error_count = native.errors.len();
    for certificate in native.certs {
        if roots.add(certificate).is_err() {
            root_error_count += 1;
        }
    }

    let verifier = match WebPkiServerVerifier::builder(Arc::new(roots)).build() {
        Ok(verifier) => verifier,
        Err(error) => {
            return ValidationResult {
                status: "validation_failed".into(),
                message:
                    "The certificate was extracted, but trust validation could not be initialized."
                        .into(),
                detail: Some(error.to_string()),
            };
        }
    };

    let result = verifier.verify_server_cert(
        &certificates[0],
        &certificates[1..],
        &endpoint.server_name,
        &[],
        UnixTime::now(),
    );

    match result {
        Ok(_) => ValidationResult {
            status: "trusted".into(),
            message: "The server-presented chain is trusted for this hostname.".into(),
            detail: if root_error_count == 0 {
                None
            } else {
                Some(format!(
                    "Some operating system trust anchors could not be loaded: {root_error_count}"
                ))
            },
        },
        Err(error) => {
            let detail = error.to_string();
            let normalized = format!("{error:?} {detail}").to_ascii_lowercase();
            let (status, message) = if normalized.contains("notvalidforname")
                || normalized.contains("not valid for name")
            {
                (
                    "hostname_mismatch",
                    "The certificate is not valid for this hostname.",
                )
            } else if normalized.contains("notvalidyet") || normalized.contains("not valid yet") {
                ("not_yet_valid", "The certificate is not valid yet.")
            } else if normalized.contains("expired") {
                ("expired", "The certificate has expired.")
            } else if normalized.contains("revoked") {
                ("revoked", "The certificate has been revoked.")
            } else if normalized.contains("unknownissuer") || normalized.contains("unknown issuer")
            {
                (
                    "untrusted",
                    "The certificate chain is not trusted by the operating system.",
                )
            } else {
                (
                    "validation_failed",
                    "The extracted certificate chain did not pass trust validation.",
                )
            };
            ValidationResult {
                status: status.into(),
                message: format!("{message} Export remains available for inspection."),
                detail: Some(detail),
            }
        }
    }
}
