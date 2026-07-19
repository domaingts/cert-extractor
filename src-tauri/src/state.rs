use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ExtractionSession {
    pub id: Uuid,
    pub endpoint: String,
    pub certificates: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct AppState {
    pub current_session: RwLock<Option<ExtractionSession>>,
    pub extraction_guard: Arc<Mutex<()>>,
}
