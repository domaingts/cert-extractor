use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub code: String,
    pub stage: String,
    pub message: String,
    pub detail: Option<String>,
    pub retryable: bool,
}

impl ApiError {
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        message: impl Into<String>,
        detail: Option<String>,
        retryable: bool,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            message: message.into(),
            detail,
            retryable,
        }
    }

    pub fn invalid(code: &str, message: impl Into<String>) -> Self {
        Self::new(code, "validating_input", message, None, false)
    }

    pub fn internal(stage: &str, detail: impl Into<String>) -> Self {
        Self::new(
            "internal_error",
            stage,
            "The operation could not be completed.",
            Some(detail.into()),
            false,
        )
    }
}
