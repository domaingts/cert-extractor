use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum UiMessageArg {
    Text(String),
    Number(i64),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiMessage {
    pub key: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, UiMessageArg>,
}

impl UiMessage {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            args: BTreeMap::new(),
        }
    }

    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.args
            .insert(name.into(), UiMessageArg::Text(value.into()));
        self
    }

    pub fn number(mut self, name: impl Into<String>, value: usize) -> Self {
        self.args
            .insert(name.into(), UiMessageArg::Number(value as i64));
        self
    }
}
