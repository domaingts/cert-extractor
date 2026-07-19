---
name: verify
description: Runtime verification recipe for the Tauri certificate extractor GUI on Linux.
---

# Certificate Extractor runtime verification

## Launch headlessly

Install the Linux Tauri prerequisites, then start an X server and the real app:

```bash
Xvfb :99 -screen 0 1120x780x24
DISPLAY=:99 npm run tauri dev
```

The first Rust build may take several minutes. Wait for `Running target/debug/cert-extractor` and locate the window with:

```bash
DISPLAY=:99 xdotool search --name 'Certificate Extractor'
```

Use `xdotool windowfocus` rather than `windowactivate`; the minimal Xvfb session has no window manager supporting `_NET_ACTIVE_WINDOW`. Use `scrot` for evidence. Benign `libEGL`/`dconf` warnings are expected in this environment.

## Drive the important flows

1. Enter a public TLS host and port 443, click **Extract certificates**, and capture the progress and completed result states.
2. Confirm connection metadata, trust status, and separately selectable server-presented certificate cards.
3. Deselect a certificate and confirm the selected count changes.
4. Click **Copy C representation** and inspect the X clipboard with `xsel --clipboard --output`; verify quoted PEM lines contain literal `\\r\\n`, source lines use CRLF, and the final line has no `+`.
5. Click **Save PEM** and use the native dialog. Inspect the saved bytes to confirm 64-character Base64 wrapping, CRLF-only line endings, a final CRLF, and the selected certificate count.
6. Probe invalid input such as `https://example.com`; the app should show an inline `invalid_hostname` extraction error while retaining no stale result below it.

## Gotchas

- Separate focus, typing, and click commands when using `xdotool`; long chained commands can type shell tokens into the hostname field.
- Scroll with `xdotool key ctrl+Home` before capturing top-of-page errors.
- The native save dialog may keep its default filename even if automated replacement misses focus; search the working tree for the newly written file.
- Stop prior `tauri dev` instances before relaunching to avoid Cargo package/build lock waits and overlapping hot reloads.
