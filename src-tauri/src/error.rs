use serde::Serialize;

use crate::ui_message::UiMessage;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub code: String,
    pub stage: String,
    pub message: Box<UiMessage>,
    pub technical_detail: Option<String>,
    pub retryable: bool,
}

impl ApiError {
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        message: UiMessage,
        technical_detail: Option<String>,
        retryable: bool,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            message: Box::new(message),
            technical_detail,
            retryable,
        }
    }

    pub fn invalid(code: &str, message_key: &str) -> Self {
        Self::new(
            code,
            "validating_input",
            UiMessage::new(message_key),
            None,
            false,
        )
    }

    pub fn internal(stage: &str, detail: impl Into<String>) -> Self {
        Self::new(
            "internal_error",
            stage,
            UiMessage::new("backend.error.internal"),
            Some(detail.into()),
            false,
        )
    }
}
