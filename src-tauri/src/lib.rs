mod certificate;
mod commands;
mod endpoint;
mod error;
mod output;
mod state;
mod tls;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::extract_certificates,
            commands::generate_export
        ])
        .run(tauri::generate_context!())
        .expect("error while running Certificate Extractor");
}
