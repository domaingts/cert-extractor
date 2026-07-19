# Certificate Extractor

A Windows desktop application built with Rust and Tauri that inspects the certificate chain presented by a remote TLS server.

## Features

- Connect to a hostname or IP address on any TLS port.
- Show DNS, connection, TLS handshake, validation, and parsing progress.
- Display the leaf certificate and every intermediate certificate sent by the server.
- Inspect expired, self-signed, untrusted, and hostname-mismatched certificates with a prominent warning.
- Select individual certificates or export the full server-presented chain.
- Save canonical PEM with CRLF (`\r\n`) line endings.
- Copy or save a C-style concatenated string representation.

The app exports the **server-presented chain**. Most servers do not send their root certificate, and the app does not fabricate or download missing certificates.

## Output formats

### Standard PEM

The PEM exporter wraps Base64 at 64 characters and writes an actual CRLF after every line, including the final footer:

```pem
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
```

### C-style expression

Every PEM line is quoted, contains a literal `\r\n`, and is joined to the next line with `+`:

```c
"-----BEGIN CERTIFICATE-----\r\n" +
"MIIB...\r\n" +
"-----END CERTIFICATE-----\r\n"
```

The result is an expression fragment, without a variable declaration or semicolon.

## Trust and inspection behavior

Certificate extraction intentionally continues when PKI validation fails so administrators and developers can inspect broken endpoints. The TLS peer must still prove possession of the private key during the handshake, but certificate trust and hostname errors do not prevent chain capture. The result screen clearly distinguishes a trusted connection from an inspection result and shows the validation warning before export.

The app sends no HTTP request or application data to the remote service.

## Development prerequisites

### Windows

- Rust stable with the `x86_64-pc-windows-msvc` toolchain
- Microsoft C++ Build Tools and Windows SDK
- Microsoft Edge WebView2 Runtime
- Node.js 22 or newer and npm

See the [Tauri Windows prerequisites](https://v2.tauri.app/start/prerequisites/) for installation details.

## Development

```powershell
npm ci
npm run tauri dev
```

Run the frontend checks:

```powershell
npm run build
npm test
```

Run the Rust checks:

```powershell
cd src-tauri
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Build the Windows installer

```powershell
npm ci
npm run tauri build -- --bundles nsis
```

The NSIS installer is generated under `src-tauri/target/release/bundle/nsis/`. Public releases should sign the application and installer with an Authenticode code-signing certificate and a trusted timestamp.

## Security model

- All network access occurs in Rust, not in the WebView.
- The WebView receives only certificate metadata and generated export text.
- Captured DER certificates remain in memory and are replaced when a new extraction starts.
- Tauri capabilities permit only a save dialog, file writing to the selected destination, and clipboard text writing.
- Remote certificate values are rendered as text, never as HTML.
