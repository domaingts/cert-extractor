use serde::{Deserialize, Serialize};
use tauri::{ipc::Channel, State};
use uuid::Uuid;

use crate::certificate::{parse_certificate, CertificateMetadata};
use crate::error::ApiError;
use crate::output::{c_expression_for_certificates, pem_for_certificates, select_certificates};
use crate::state::{AppState, ExtractionSession};
use crate::tls::{self, ValidationResult};
use crate::ui_message::UiMessage;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionRequest {
    pub hostname: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionProgress {
    pub sequence: u32,
    pub stage: String,
    pub message: UiMessage,
    pub technical_detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExtractionResult {
    pub session_id: Uuid,
    pub endpoint: String,
    pub connected_address: String,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub validation: ValidationResult,
    pub certificates: Vec<CertificateMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Pem,
    CExpression,
}

#[derive(Debug, Serialize)]
pub struct GeneratedExport {
    pub text: String,
    pub suggested_filename: String,
    pub format: String,
}

#[tauri::command]
pub async fn extract_certificates(
    request: ExtractionRequest,
    progress: Channel<ExtractionProgress>,
    state: State<'_, AppState>,
) -> Result<ExtractionResult, ApiError> {
    let _guard = state.extraction_guard.try_lock().map_err(|_| {
        ApiError::new(
            "busy",
            "validating_input",
            UiMessage::new("backend.error.extractionBusy"),
            None,
            true,
        )
    })?;

    *state.current_session.write().await = None;
    let mut sequence = 0_u32;
    let mut send_progress = |stage: &str, message: UiMessage| {
        sequence += 1;
        let _ = progress.send(ExtractionProgress {
            sequence,
            stage: stage.into(),
            message,
            technical_detail: None,
        });
    };

    send_progress(
        "validating_input",
        UiMessage::new("backend.progress.validatingAddress"),
    );
    let endpoint = crate::endpoint::Endpoint::parse(&request.hostname, request.port)?;
    let endpoint_display = endpoint.display();
    let extracted = tls::extract(&endpoint, &mut send_progress).await?;

    send_progress(
        "parsing_certificates",
        UiMessage::new("backend.progress.readingMetadata")
            .number("count", extracted.certificates.len()),
    );
    let metadata: Vec<CertificateMetadata> = extracted
        .certificates
        .iter()
        .enumerate()
        .map(|(index, certificate)| parse_certificate(index, certificate))
        .collect();
    let session_id = Uuid::new_v4();
    let session = ExtractionSession {
        id: session_id,
        endpoint: endpoint_display.clone(),
        certificates: extracted.certificates,
    };
    *state.current_session.write().await = Some(session);

    send_progress(
        "complete",
        UiMessage::new("backend.progress.captured").number("count", metadata.len()),
    );
    Ok(ExtractionResult {
        session_id,
        endpoint: endpoint_display,
        connected_address: extracted.connection.connected_address,
        tls_version: extracted.connection.tls_version,
        cipher_suite: extracted.connection.cipher_suite,
        validation: extracted.validation,
        certificates: metadata,
    })
}

#[tauri::command]
pub async fn generate_export(
    session_id: Uuid,
    certificate_indices: Vec<usize>,
    format: ExportFormat,
    state: State<'_, AppState>,
) -> Result<GeneratedExport, ApiError> {
    let session_guard = state.current_session.read().await;
    let session = session_guard.as_ref().ok_or_else(|| {
        ApiError::new(
            "stale_session",
            "generating_export",
            UiMessage::new("backend.error.noCurrentSession"),
            None,
            true,
        )
    })?;
    if session.id != session_id {
        return Err(ApiError::new(
            "stale_session",
            "generating_export",
            UiMessage::new("backend.error.staleSession"),
            None,
            true,
        ));
    }

    let selected = select_certificates(&session.certificates, &certificate_indices)?;
    let base_name = safe_filename(&session.endpoint);
    let export = match format {
        ExportFormat::Pem => GeneratedExport {
            text: pem_for_certificates(&selected),
            suggested_filename: format!("{base_name}.pem"),
            format: "pem".into(),
        },
        ExportFormat::CExpression => GeneratedExport {
            text: c_expression_for_certificates(&selected),
            suggested_filename: format!("{base_name}-certificate.txt"),
            format: "c_expression".into(),
        },
    };
    Ok(export)
}

fn safe_filename(endpoint: &str) -> String {
    let name: String = endpoint
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = name.trim_matches('-');
    if trimmed.is_empty() {
        "certificates".into()
    } else {
        trimmed.into()
    }
}
