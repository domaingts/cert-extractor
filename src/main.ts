import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { save } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import {
  extractCertificates,
  generateExport,
  type CertificateInfo,
  type ExtractionProgress,
  type ExtractionResult,
  type ExportFormat,
} from "./api";
import "./styles.css";

const app = document.querySelector<HTMLElement>("#app");

if (!app) {
  throw new Error("Application root was not found.");
}

app.innerHTML = `
  <main class="shell">
    <header class="hero">
      <div class="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 32 32" role="img"><path d="M16 2.5 27 7v8.2c0 6.8-4.6 12.3-11 14.3-6.4-2-11-7.5-11-14.3V7l11-4.5Z"/><path d="m11.2 16 3.1 3.1 6.8-7"/></svg>
      </div>
      <div>
        <p class="eyebrow">TLS toolkit</p>
        <h1>Certificate Extractor</h1>
        <p class="hero-copy">Inspect a server's certificate chain, verify its trust, and export certificates for your project.</p>
      </div>
    </header>

    <section class="panel connection-panel" aria-labelledby="connection-heading">
      <div class="section-heading">
        <div>
          <p class="step-label">Step 1</p>
          <h2 id="connection-heading">Connect to a server</h2>
        </div>
        <span class="secure-note"><span aria-hidden="true">●</span> Direct TLS connection</span>
      </div>
      <form id="extract-form" novalidate>
        <div class="form-grid">
          <label class="field hostname-field">
            <span>Hostname</span>
            <input id="hostname" name="hostname" type="text" inputmode="url" autocomplete="url" placeholder="example.com" spellcheck="false" required aria-describedby="hostname-hint" />
            <small id="hostname-hint">Domain name or IP address</small>
          </label>
          <label class="field port-field">
            <span>Port</span>
            <input id="port" name="port" type="number" inputmode="numeric" value="443" min="1" max="65535" required />
          </label>
          <button id="extract-button" class="button button-primary extract-button" type="submit">
            <span class="button-icon" aria-hidden="true">↗</span>
            <span>Extract certificates</span>
          </button>
        </div>
      </form>
    </section>

    <section id="activity-panel" class="panel activity-panel" aria-labelledby="activity-heading" hidden>
      <div class="activity-topline">
        <div>
          <p class="step-label">Connection activity</p>
          <h2 id="activity-heading">Extracting certificate chain</h2>
        </div>
        <span id="elapsed-time" class="elapsed-time">0.0s</span>
      </div>
      <div class="progress-track" aria-hidden="true"><span id="progress-bar"></span></div>
      <div class="progress-copy">
        <span id="progress-indicator" class="progress-indicator" aria-hidden="true"></span>
        <div>
          <p id="progress-message">Preparing connection…</p>
          <p id="progress-detail" class="muted"></p>
        </div>
      </div>
    </section>

    <div id="error-banner" class="error-banner" role="alert" tabindex="-1" hidden>
      <span class="error-icon" aria-hidden="true">!</span>
      <div><strong>Extraction failed</strong><p id="error-message"></p></div>
      <button id="dismiss-error" type="button" aria-label="Dismiss error">×</button>
    </div>

    <div id="operation-status" class="sr-only" role="status" aria-live="polite"></div>

    <section id="results" class="results" aria-labelledby="results-heading" hidden>
      <div class="results-title-row">
        <div>
          <p class="step-label">Step 2</p>
          <h2 id="results-heading">Certificate chain</h2>
        </div>
        <span id="certificate-count" class="count-badge"></span>
      </div>

      <div class="panel summary-panel">
        <div id="trust-icon" class="trust-icon" aria-hidden="true"></div>
        <div class="trust-copy">
          <div class="trust-title-row">
            <h3 id="trust-title"></h3>
            <span id="trust-badge" class="trust-badge"></span>
          </div>
          <p id="trust-message"></p>
          <p id="trust-detail" class="muted"></p>
        </div>
        <dl class="connection-facts">
          <div><dt>Endpoint</dt><dd id="result-endpoint"></dd></div>
          <div><dt>Connected to</dt><dd id="result-address"></dd></div>
          <div><dt>TLS</dt><dd id="result-tls"></dd></div>
          <div><dt>Cipher suite</dt><dd id="result-cipher"></dd></div>
        </dl>
      </div>

      <div class="selection-toolbar" aria-label="Certificate selection controls">
        <p><strong id="selected-count">0 selected</strong><span>Choose certificates to export</span></p>
        <div class="selection-actions">
          <button id="select-all" class="text-button" type="button">Select all</button>
          <span aria-hidden="true"></span>
          <button id="select-none" class="text-button" type="button">Select none</button>
        </div>
      </div>

      <div id="certificate-list" class="certificate-list"></div>

      <div class="export-bar panel">
        <div>
          <h3>Export selected certificates</h3>
          <p id="export-hint">Choose one or more certificates above.</p>
        </div>
        <div class="export-actions">
          <button id="save-pem" class="button button-secondary" type="button">Save PEM</button>
          <button id="copy-c" class="button button-secondary" type="button">Copy C representation</button>
          <button id="export-c" class="button button-primary" type="button">Export C representation</button>
        </div>
      </div>
    </section>
  </main>
`;

function requiredElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Required element not found: ${selector}`);
  return element;
}

const form = requiredElement<HTMLFormElement>("#extract-form");
const hostnameInput = requiredElement<HTMLInputElement>("#hostname");
const portInput = requiredElement<HTMLInputElement>("#port");
const extractButton = requiredElement<HTMLButtonElement>("#extract-button");
const activityPanel = requiredElement<HTMLElement>("#activity-panel");
const activityHeading = requiredElement<HTMLElement>("#activity-heading");
const elapsedTime = requiredElement<HTMLElement>("#elapsed-time");
const progressBar = requiredElement<HTMLElement>("#progress-bar");
const progressIndicator = requiredElement<HTMLElement>("#progress-indicator");
const progressMessage = requiredElement<HTMLElement>("#progress-message");
const progressDetail = requiredElement<HTMLElement>("#progress-detail");
const errorBanner = requiredElement<HTMLElement>("#error-banner");
const errorMessage = requiredElement<HTMLElement>("#error-message");
const operationStatus = requiredElement<HTMLElement>("#operation-status");
const resultsSection = requiredElement<HTMLElement>("#results");
const certificateList = requiredElement<HTMLElement>("#certificate-list");
const selectedCount = requiredElement<HTMLElement>("#selected-count");
const exportHint = requiredElement<HTMLElement>("#export-hint");
const exportButtons = [
  requiredElement<HTMLButtonElement>("#save-pem"),
  requiredElement<HTMLButtonElement>("#copy-c"),
  requiredElement<HTMLButtonElement>("#export-c"),
];

let currentResult: ExtractionResult | null = null;
let extractionStartedAt = 0;
let elapsedTimer: number | undefined;
let lastProgressSequence = -1;

form.addEventListener("submit", (event) => void handleExtraction(event));
requiredElement<HTMLButtonElement>("#dismiss-error").addEventListener("click", hideError);
requiredElement<HTMLButtonElement>("#select-all").addEventListener("click", () => setAllSelected(true));
requiredElement<HTMLButtonElement>("#select-none").addEventListener("click", () => setAllSelected(false));
requiredElement<HTMLButtonElement>("#save-pem").addEventListener("click", () => void saveExport("pem"));
requiredElement<HTMLButtonElement>("#copy-c").addEventListener("click", () => void copyCExport());
requiredElement<HTMLButtonElement>("#export-c").addEventListener("click", () => void saveExport("c_expression"));

async function handleExtraction(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  hideError();

  const hostname = hostnameInput.value.trim();
  const port = Number(portInput.value);
  if (!hostname) {
    hostnameInput.setCustomValidity("Enter a hostname or IP address.");
    hostnameInput.reportValidity();
    return;
  }
  hostnameInput.setCustomValidity("");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    portInput.setCustomValidity("Enter a port from 1 to 65535.");
    portInput.reportValidity();
    return;
  }
  portInput.setCustomValidity("");

  setExtracting(true);
  currentResult = null;
  resultsSection.hidden = true;
  startElapsedTimer();
  updateProgress({ sequence: 0, stage: "starting", message: "Preparing secure connection…" });

  try {
    const result = await extractCertificates({ hostname, port }, updateProgress);
    currentResult = result;
    stopElapsedTimer();
    completeProgress();
    renderResult(result);
    operationStatus.textContent = `Extraction complete. ${result.certificates.length} certificates found.`;
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error: unknown) {
    stopElapsedTimer();
    activityPanel.hidden = true;
    showError(readError(error));
  } finally {
    setExtracting(false);
  }
}

function setExtracting(isExtracting: boolean): void {
  extractButton.disabled = isExtracting;
  hostnameInput.disabled = isExtracting;
  portInput.disabled = isExtracting;
  extractButton.classList.toggle("is-loading", isExtracting);
  extractButton.querySelector("span:last-child")!.textContent = isExtracting ? "Extracting…" : "Extract certificates";
}

function startElapsedTimer(): void {
  extractionStartedAt = performance.now();
  lastProgressSequence = -1;
  activityPanel.hidden = false;
  activityPanel.classList.remove("is-complete");
  progressIndicator.classList.remove("is-complete");
  progressBar.style.width = "8%";
  elapsedTime.textContent = "0.0s";
  window.clearInterval(elapsedTimer);
  elapsedTimer = window.setInterval(() => {
    elapsedTime.textContent = `${((performance.now() - extractionStartedAt) / 1000).toFixed(1)}s`;
  }, 100);
}

function stopElapsedTimer(): void {
  window.clearInterval(elapsedTimer);
  elapsedTimer = undefined;
  elapsedTime.textContent = `${((performance.now() - extractionStartedAt) / 1000).toFixed(1)}s`;
}

function updateProgress(progress: ExtractionProgress): void {
  if (progress.sequence < lastProgressSequence) return;
  lastProgressSequence = progress.sequence;
  activityHeading.textContent = humanizeStage(progress.stage);
  progressMessage.textContent = progress.message;
  progressDetail.textContent = progress.detail ?? "";
  progressDetail.hidden = !progress.detail;
  progressBar.style.width = `${Math.min(88, 14 + progress.sequence * 12)}%`;
  operationStatus.textContent = progress.detail ? `${progress.message} ${progress.detail}` : progress.message;
}

function completeProgress(): void {
  activityPanel.classList.add("is-complete");
  progressIndicator.classList.add("is-complete");
  activityHeading.textContent = "Certificate chain extracted";
  progressMessage.textContent = "Connection completed successfully";
  progressDetail.textContent = "";
  progressDetail.hidden = true;
  progressBar.style.width = "100%";
}

function renderResult(result: ExtractionResult): void {
  resultsSection.hidden = false;
  const validationTone = getValidationTone(result.validation.status);
  const trustIcon = requiredElement<HTMLElement>("#trust-icon");
  const trustBadge = requiredElement<HTMLElement>("#trust-badge");
  const trustTitle = requiredElement<HTMLElement>("#trust-title");

  trustIcon.className = `trust-icon tone-${validationTone}`;
  trustIcon.textContent = validationTone === "success" ? "✓" : validationTone === "warning" ? "!" : "×";
  trustBadge.className = `trust-badge tone-${validationTone}`;
  trustBadge.textContent = humanize(result.validation.status);
  trustTitle.textContent = validationTone === "success" ? "Certificate is trusted" : validationTone === "warning" ? "Certificate trust warning" : "Certificate is not trusted";
  requiredElement<HTMLElement>("#trust-message").textContent = result.validation.message;
  const trustDetail = requiredElement<HTMLElement>("#trust-detail");
  trustDetail.textContent = result.validation.detail ?? "";
  trustDetail.hidden = !result.validation.detail;

  setText("#result-endpoint", result.endpoint);
  setText("#result-address", result.connected_address);
  setText("#result-tls", result.tls_version);
  setText("#result-cipher", result.cipher_suite);
  setText("#certificate-count", `${result.certificates.length} certificate${result.certificates.length === 1 ? "" : "s"}`);

  certificateList.replaceChildren(...result.certificates.map(createCertificateCard));
  updateSelectionState();
}

function createCertificateCard(certificate: CertificateInfo): HTMLElement {
  const article = document.createElement("article");
  article.className = "certificate-card is-selected";

  const label = document.createElement("label");
  label.className = "certificate-select";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.checked = true;
  checkbox.dataset.certificateIndex = String(certificate.index);
  checkbox.setAttribute("aria-label", `Select certificate ${certificate.index + 1}: ${certificate.subject}`);
  checkbox.addEventListener("change", () => {
    article.classList.toggle("is-selected", checkbox.checked);
    updateSelectionState();
  });
  const checkmark = document.createElement("span");
  checkmark.className = "custom-checkbox";
  checkmark.setAttribute("aria-hidden", "true");
  label.append(checkbox, checkmark);

  const content = document.createElement("div");
  content.className = "certificate-content";
  const heading = document.createElement("div");
  heading.className = "certificate-heading";
  const headingText = document.createElement("div");
  const eyebrow = document.createElement("p");
  eyebrow.className = "certificate-role";
  eyebrow.textContent = `${certificate.role} · Certificate ${certificate.index + 1}`;
  const title = document.createElement("h3");
  title.textContent = certificate.subject;
  headingText.append(eyebrow, title);
  const validity = document.createElement("span");
  validity.className = `validity-badge validity-${validityTone(certificate.validity_status)}`;
  validity.textContent = humanize(certificate.validity_status);
  heading.append(headingText, validity);

  const details = document.createElement("dl");
  details.className = "certificate-details";
  addFact(details, "Issuer", certificate.issuer);
  addFact(details, "Valid from", formatDate(certificate.valid_from));
  addFact(details, "Valid until", formatDate(certificate.valid_until));
  addFact(details, "Serial number", certificate.serial_number, true);
  addFact(details, "Public key", certificate.public_key_algorithm);
  addFact(details, "Signature", certificate.signature_algorithm);
  addFact(details, "SHA-256 fingerprint", certificate.sha256_fingerprint, true, "wide");
  addFact(details, "DER size", formatBytes(certificate.der_size));
  addFact(details, "Certificate authority", certificate.is_ca ? "Yes" : "No");

  content.append(heading, details);
  if (certificate.subject_alt_names.length > 0) content.append(createNameList(certificate.subject_alt_names));
  if (certificate.warnings.length > 0) content.append(createWarnings(certificate.warnings));
  article.append(label, content);
  return article;
}

function addFact(list: HTMLDListElement, label: string, value: string, code = false, className = ""): void {
  const item = document.createElement("div");
  if (className) item.className = className;
  const term = document.createElement("dt");
  term.textContent = label;
  const detail = document.createElement("dd");
  detail.textContent = value || "—";
  if (code) detail.className = "code-value";
  item.append(term, detail);
  list.append(item);
}

function createNameList(names: string[]): HTMLElement {
  const section = document.createElement("div");
  section.className = "name-list";
  const title = document.createElement("h4");
  title.textContent = "Subject alternative names";
  const list = document.createElement("div");
  list.className = "tag-list";
  for (const name of names) {
    const tag = document.createElement("span");
    tag.textContent = name;
    list.append(tag);
  }
  section.append(title, list);
  return section;
}

function createWarnings(warnings: string[]): HTMLElement {
  const list = document.createElement("ul");
  list.className = "certificate-warnings";
  for (const warning of warnings) {
    const item = document.createElement("li");
    item.textContent = warning;
    list.append(item);
  }
  return list;
}

function selectedIndices(): number[] {
  return Array.from(certificateList.querySelectorAll<HTMLInputElement>('input[type="checkbox"]:checked')).map((checkbox) => Number(checkbox.dataset.certificateIndex));
}

function setAllSelected(selected: boolean): void {
  for (const checkbox of certificateList.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')) {
    checkbox.checked = selected;
    checkbox.closest(".certificate-card")?.classList.toggle("is-selected", selected);
  }
  updateSelectionState();
  operationStatus.textContent = selected ? "All certificates selected." : "All certificates deselected.";
}

function updateSelectionState(): void {
  const count = selectedIndices().length;
  selectedCount.textContent = `${count} selected`;
  exportHint.textContent = count > 0 ? `${count} certificate${count === 1 ? "" : "s"} will be included.` : "Choose one or more certificates above.";
  for (const button of exportButtons) button.disabled = count === 0;
}

async function saveExport(format: ExportFormat): Promise<void> {
  if (!currentResult) return;
  const indices = selectedIndices();
  if (indices.length === 0) return;
  setExportBusy(true);
  hideError();

  try {
    const generated = await generateExport(currentResult.session_id, indices, format);
    const path = await save({
      defaultPath: generated.suggested_filename,
      filters: [{ name: format === "pem" ? "PEM certificate" : "C source", extensions: format === "pem" ? ["pem", "crt"] : ["c", "h"] }],
    });
    if (!path) {
      operationStatus.textContent = "Export cancelled.";
      return;
    }
    await writeFile(path, new TextEncoder().encode(generated.text));
    operationStatus.textContent = `Export saved to ${path}.`;
  } catch (error: unknown) {
    showError(`Could not save the export. ${readError(error)}`, "Export failed");
  } finally {
    setExportBusy(false);
  }
}

async function copyCExport(): Promise<void> {
  if (!currentResult) return;
  const indices = selectedIndices();
  if (indices.length === 0) return;
  setExportBusy(true);
  hideError();

  try {
    const generated = await generateExport(currentResult.session_id, indices, "c_expression");
    await writeText(generated.text);
    operationStatus.textContent = "C representation copied to the clipboard.";
  } catch (error: unknown) {
    showError(`Could not copy the C representation. ${readError(error)}`, "Copy failed");
  } finally {
    setExportBusy(false);
  }
}

function setExportBusy(busy: boolean): void {
  for (const button of exportButtons) button.disabled = busy || selectedIndices().length === 0;
}

function showError(message: string, title = "Extraction failed"): void {
  errorBanner.querySelector("strong")!.textContent = title;
  errorMessage.textContent = message;
  errorBanner.hidden = false;
  operationStatus.textContent = `${title}: ${message}`;
  errorBanner.focus();
}

function hideError(): void {
  errorBanner.hidden = true;
  errorMessage.textContent = "";
}

function readError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch {
    return "An unexpected error occurred.";
  }
}

function setText(selector: string, value: string): void {
  requiredElement<HTMLElement>(selector).textContent = value || "—";
}

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function humanizeStage(stage: string): string {
  return stage ? humanize(stage) : "Extracting certificate chain";
}

function getValidationTone(status: string): "success" | "warning" | "danger" {
  const normalized = status.toLowerCase();
  if (["trusted", "valid", "success", "ok"].includes(normalized)) return "success";
  if (["warning", "unknown", "insecure"].includes(normalized)) return "warning";
  return "danger";
}

function validityTone(status: string): "success" | "warning" | "danger" {
  const normalized = status.toLowerCase();
  if (normalized === "valid") return "success";
  if (normalized === "unknown") return "warning";
  return "danger";
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}
