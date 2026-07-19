import { getCurrentWindow } from "@tauri-apps/api/window";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { save } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import {
  extractCertificates,
  generateExport,
  normalizeApiError,
  type CertificateInfo,
  type ExtractionProgress,
  type ExtractionResult,
  type ExportFormat,
  type NormalizedApiError,
} from "./api";
import {
  formatBytes,
  formatDate,
  formatNumber,
  getLocale,
  hasMessageKey,
  setLocale,
  t,
  tp,
  translateUiMessage,
  type AppLocale,
  type UiMessage,
} from "./i18n";
import type { MessageKey } from "./locales/en";
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
      <div class="hero-body">
        <div class="hero-heading-row">
          <div>
            <p class="eyebrow" data-i18n="app.eyebrow">TLS toolkit</p>
            <h1 data-i18n="app.title">Certificate Extractor</h1>
          </div>
          <label class="locale-control">
            <span data-i18n="locale.label">Language</span>
            <select id="locale-select">
              <option value="en">English</option>
              <option value="zh-CN">简体中文</option>
              <option value="zh-TW">繁體中文</option>
            </select>
          </label>
        </div>
        <p class="hero-copy" data-i18n="app.description">Inspect a server's certificate chain, verify its trust, and export certificates for your project.</p>
      </div>
    </header>

    <section class="panel connection-panel" aria-labelledby="connection-heading">
      <div class="section-heading">
        <div>
          <p class="step-label" data-i18n="connection.step">Step 1</p>
          <h2 id="connection-heading" data-i18n="connection.heading">Connect to a server</h2>
        </div>
        <span class="secure-note"><span aria-hidden="true">●</span><span data-i18n="connection.secure">Direct TLS connection</span></span>
      </div>
      <form id="extract-form" novalidate>
        <div class="form-grid">
          <label class="field hostname-field">
            <span data-i18n="connection.hostname">Hostname</span>
            <input id="hostname" name="hostname" type="text" inputmode="url" autocomplete="url" placeholder="example.com" spellcheck="false" required aria-describedby="hostname-hint" data-i18n-placeholder="connection.hostnamePlaceholder" />
            <small id="hostname-hint" data-i18n="connection.hostnameHint">Domain name or IP address</small>
          </label>
          <label class="field port-field">
            <span data-i18n="connection.port">Port</span>
            <input id="port" name="port" type="number" inputmode="numeric" value="443" min="1" max="65535" required />
          </label>
          <button id="extract-button" class="button button-primary extract-button" type="submit">
            <span class="button-icon" aria-hidden="true">↗</span>
            <span data-i18n="connection.extract">Extract certificates</span>
          </button>
        </div>
      </form>
    </section>

    <section id="activity-panel" class="panel activity-panel" aria-labelledby="activity-heading" hidden>
      <div class="activity-topline">
        <div>
          <p class="step-label" data-i18n="activity.label">Connection activity</p>
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
      <div><strong></strong><p id="error-message"></p><p id="error-detail" class="error-detail"></p></div>
      <button id="dismiss-error" type="button" aria-label="Dismiss error" data-i18n-aria-label="error.dismiss">×</button>
    </div>

    <div id="operation-status" class="sr-only" role="status" aria-live="polite"></div>

    <section id="results" class="results" aria-labelledby="results-heading" hidden>
      <div class="results-title-row">
        <div>
          <p class="step-label" data-i18n="results.step">Step 2</p>
          <h2 id="results-heading" data-i18n="results.heading">Certificate chain</h2>
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
          <p id="trust-technical-detail" class="muted technical-detail"></p>
        </div>
        <dl class="connection-facts">
          <div><dt data-i18n="results.endpoint">Endpoint</dt><dd id="result-endpoint"></dd></div>
          <div><dt data-i18n="results.connectedTo">Connected to</dt><dd id="result-address"></dd></div>
          <div><dt data-i18n="results.tls">TLS</dt><dd id="result-tls"></dd></div>
          <div><dt data-i18n="results.cipherSuite">Cipher suite</dt><dd id="result-cipher"></dd></div>
        </dl>
      </div>

      <div class="selection-toolbar" aria-label="Certificate selection controls" data-i18n-aria-label="selection.controls">
        <p><strong id="selected-count"></strong><span data-i18n="selection.choose">Choose certificates to export</span></p>
        <div class="selection-actions">
          <button id="select-all" class="text-button" type="button" data-i18n="selection.selectAll">Select all</button>
          <span aria-hidden="true"></span>
          <button id="select-none" class="text-button" type="button" data-i18n="selection.selectNone">Select none</button>
        </div>
      </div>

      <div id="certificate-list" class="certificate-list"></div>

      <div class="export-bar panel">
        <div>
          <h3 data-i18n="export.heading">Export selected certificates</h3>
          <p id="export-hint"></p>
        </div>
        <div class="export-actions">
          <button id="save-pem" class="button button-secondary" type="button" data-i18n="export.savePem">Save PEM</button>
          <button id="copy-c" class="button button-secondary" type="button" data-i18n="export.copyC">Copy C representation</button>
          <button id="export-c" class="button button-primary" type="button" data-i18n="export.saveC">Export C representation</button>
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

interface DisplayError {
  titleKey: MessageKey;
  messages: UiMessage[];
  technicalDetail?: string | null;
}

const form = requiredElement<HTMLFormElement>("#extract-form");
const hostnameInput = requiredElement<HTMLInputElement>("#hostname");
const portInput = requiredElement<HTMLInputElement>("#port");
const extractButton = requiredElement<HTMLButtonElement>("#extract-button");
const localeSelect = requiredElement<HTMLSelectElement>("#locale-select");
const activityPanel = requiredElement<HTMLElement>("#activity-panel");
const activityHeading = requiredElement<HTMLElement>("#activity-heading");
const elapsedTime = requiredElement<HTMLElement>("#elapsed-time");
const progressBar = requiredElement<HTMLElement>("#progress-bar");
const progressIndicator = requiredElement<HTMLElement>("#progress-indicator");
const progressMessage = requiredElement<HTMLElement>("#progress-message");
const progressDetail = requiredElement<HTMLElement>("#progress-detail");
const errorBanner = requiredElement<HTMLElement>("#error-banner");
const errorMessage = requiredElement<HTMLElement>("#error-message");
const errorDetail = requiredElement<HTMLElement>("#error-detail");
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
let currentProgress: ExtractionProgress | null = null;
let currentError: DisplayError | null = null;
let currentAnnouncement: UiMessage | null = null;
let extractionStartedAt = 0;
let elapsedTimer: number | undefined;
let lastProgressSequence = -1;
let extractionComplete = false;
let extracting = false;
let exportBusy = false;

form.addEventListener("submit", (event) => void handleExtraction(event));
localeSelect.addEventListener("change", () => {
  setLocale(localeSelect.value as AppLocale);
  applyLocale();
});
requiredElement<HTMLButtonElement>("#dismiss-error").addEventListener("click", hideError);
requiredElement<HTMLButtonElement>("#select-all").addEventListener("click", () => setAllSelected(true));
requiredElement<HTMLButtonElement>("#select-none").addEventListener("click", () => setAllSelected(false));
requiredElement<HTMLButtonElement>("#save-pem").addEventListener("click", () => void saveExport("pem"));
requiredElement<HTMLButtonElement>("#copy-c").addEventListener("click", () => void copyCExport());
requiredElement<HTMLButtonElement>("#export-c").addEventListener("click", () => void saveExport("c_expression"));

applyLocale();

async function handleExtraction(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  hideError();

  const hostname = hostnameInput.value.trim();
  const port = Number(portInput.value);
  if (!hostname) {
    hostnameInput.setCustomValidity(t("connection.hostnameRequired"));
    hostnameInput.reportValidity();
    return;
  }
  hostnameInput.setCustomValidity("");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    portInput.setCustomValidity(t("connection.portInvalid"));
    portInput.reportValidity();
    return;
  }
  portInput.setCustomValidity("");

  setExtracting(true);
  currentResult = null;
  resultsSection.hidden = true;
  startElapsedTimer();
  updateProgress({ sequence: 0, stage: "starting", message: { key: "activity.preparing" } });

  try {
    const result = await extractCertificates({ hostname, port }, updateProgress);
    currentResult = result;
    stopElapsedTimer();
    completeProgress();
    renderResult(result);
    announce({ key: "results.extractionComplete", args: { count: result.certificates.length } });
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error: unknown) {
    stopElapsedTimer();
    activityPanel.hidden = true;
    showNormalizedError(normalizeApiError(error), "error.extractionTitle");
  } finally {
    setExtracting(false);
  }
}

function applyLocale(): void {
  const locale = getLocale();
  document.documentElement.lang = locale;
  localeSelect.value = locale;
  for (const element of document.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const key = element.dataset.i18n;
    if (key && hasMessageKey(key)) element.textContent = t(key);
  }
  for (const element of document.querySelectorAll<HTMLInputElement>("[data-i18n-placeholder]")) {
    const key = element.dataset.i18nPlaceholder;
    if (key && hasMessageKey(key)) element.placeholder = t(key);
  }
  for (const element of document.querySelectorAll<HTMLElement>("[data-i18n-aria-label]")) {
    const key = element.dataset.i18nAriaLabel;
    if (key && hasMessageKey(key)) element.setAttribute("aria-label", t(key));
  }

  document.title = t("app.title");
  document.querySelector<HTMLMetaElement>('meta[name="description"]')?.setAttribute("content", t("app.metaDescription"));
  void getCurrentWindow().setTitle(t("app.title")).catch((error: unknown) => console.warn("Could not localize window title", error));

  setExtracting(extracting);
  refreshElapsedTime();
  if (extractionComplete) {
    renderCompletedProgress();
  } else if (currentProgress) {
    renderProgress(currentProgress);
  } else {
    activityHeading.textContent = t("activity.heading");
    progressMessage.textContent = t("activity.preparing");
  }
  if (currentResult) refreshResult(currentResult);
  if (currentError) renderError(currentError);
  if (currentAnnouncement) operationStatus.textContent = translateUiMessage(currentAnnouncement);
}

function setExtracting(isExtracting: boolean): void {
  extracting = isExtracting;
  extractButton.disabled = isExtracting;
  hostnameInput.disabled = isExtracting;
  portInput.disabled = isExtracting;
  localeSelect.disabled = false;
  extractButton.classList.toggle("is-loading", isExtracting);
  extractButton.querySelector("span:last-child")!.textContent = t(isExtracting ? "connection.extracting" : "connection.extract");
}

function startElapsedTimer(): void {
  extractionStartedAt = performance.now();
  lastProgressSequence = -1;
  extractionComplete = false;
  activityPanel.hidden = false;
  activityPanel.classList.remove("is-complete");
  progressIndicator.classList.remove("is-complete");
  progressBar.style.width = "8%";
  refreshElapsedTime();
  window.clearInterval(elapsedTimer);
  elapsedTimer = window.setInterval(refreshElapsedTime, 100);
}

function refreshElapsedTime(): void {
  const seconds = extractionStartedAt > 0 ? (performance.now() - extractionStartedAt) / 1000 : 0;
  elapsedTime.textContent = t("activity.elapsed", {
    seconds: formatNumber(Math.max(0, seconds), { minimumFractionDigits: 1, maximumFractionDigits: 1 }),
  });
}

function stopElapsedTimer(): void {
  window.clearInterval(elapsedTimer);
  elapsedTimer = undefined;
  refreshElapsedTime();
}

function updateProgress(progress: ExtractionProgress): void {
  if (progress.sequence < lastProgressSequence) return;
  lastProgressSequence = progress.sequence;
  currentProgress = progress;
  renderProgress(progress);
}

function renderProgress(progress: ExtractionProgress): void {
  const stageKey = `progress.stage.${progress.stage}`;
  activityHeading.textContent = hasMessageKey(stageKey) ? t(stageKey) : t("activity.heading");
  progressMessage.textContent = translateUiMessage(progress.message);
  progressDetail.textContent = progress.technicalDetail ? t("error.technicalDetail", { detail: progress.technicalDetail }) : "";
  progressDetail.hidden = !progress.technicalDetail;
  progressBar.style.width = `${Math.min(88, 14 + progress.sequence * 12)}%`;
  announce(progress.message);
}

function completeProgress(): void {
  extractionComplete = true;
  renderCompletedProgress();
}

function renderCompletedProgress(): void {
  activityPanel.classList.add("is-complete");
  progressIndicator.classList.add("is-complete");
  activityHeading.textContent = t("activity.completeHeading");
  progressMessage.textContent = t("activity.completeMessage");
  progressDetail.textContent = "";
  progressDetail.hidden = true;
  progressBar.style.width = "100%";
}

function renderResult(result: ExtractionResult): void {
  resultsSection.hidden = false;
  setText("#result-endpoint", result.endpoint);
  setText("#result-address", result.connected_address);
  certificateList.replaceChildren(...result.certificates.map(createCertificateCard));
  refreshResult(result);
}

function refreshResult(result: ExtractionResult): void {
  const validationTone = getValidationTone(result.validation.status);
  const trustIcon = requiredElement<HTMLElement>("#trust-icon");
  const trustBadge = requiredElement<HTMLElement>("#trust-badge");

  trustIcon.className = `trust-icon tone-${validationTone}`;
  trustIcon.textContent = validationTone === "success" ? "✓" : validationTone === "warning" ? "!" : "×";
  trustBadge.className = `trust-badge tone-${validationTone}`;
  trustBadge.textContent = validationStatus(result.validation.status);
  requiredElement<HTMLElement>("#trust-title").textContent = t(
    validationTone === "success" ? "validation.title.trusted" : validationTone === "warning" ? "validation.title.warning" : "validation.title.untrusted",
  );
  requiredElement<HTMLElement>("#trust-message").textContent = translateUiMessage(result.validation.message);
  const trustDetail = requiredElement<HTMLElement>("#trust-detail");
  trustDetail.textContent = result.validation.detailMessage ? translateUiMessage(result.validation.detailMessage) : "";
  trustDetail.hidden = !result.validation.detailMessage;
  const technicalDetail = requiredElement<HTMLElement>("#trust-technical-detail");
  technicalDetail.textContent = result.validation.technicalDetail ? t("error.technicalDetail", { detail: result.validation.technicalDetail }) : "";
  technicalDetail.hidden = !result.validation.technicalDetail;

  setText("#result-tls", result.tls_version ?? t("results.unavailable"));
  setText("#result-cipher", result.cipher_suite ?? t("results.unavailable"));
  requiredElement<HTMLElement>("#certificate-count").textContent = tp("results.certificateCount", result.certificates.length);

  for (const certificate of result.certificates) {
    const card = certificateList.querySelector<HTMLElement>(`[data-certificate-card="${certificate.index}"]`);
    if (card) localizeCertificateCard(card, certificate);
  }
  updateSelectionState();
}

function createCertificateCard(certificate: CertificateInfo): HTMLElement {
  const article = document.createElement("article");
  article.className = "certificate-card is-selected";
  article.dataset.certificateCard = String(certificate.index);

  const label = document.createElement("label");
  label.className = "certificate-select";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.checked = true;
  checkbox.dataset.certificateIndex = String(certificate.index);
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
  eyebrow.dataset.field = "role";
  const title = document.createElement("h3");
  title.dataset.field = "subject";
  headingText.append(eyebrow, title);
  const validity = document.createElement("span");
  validity.dataset.field = "validity";
  heading.append(headingText, validity);

  const details = document.createElement("dl");
  details.className = "certificate-details";
  addFact(details, "certificate.issuer", "issuer");
  addFact(details, "certificate.validFrom", "valid-from");
  addFact(details, "certificate.validUntil", "valid-until");
  addFact(details, "certificate.serialNumber", "serial-number", true);
  addFact(details, "certificate.publicKey", "public-key");
  addFact(details, "certificate.signature", "signature");
  addFact(details, "certificate.fingerprint", "fingerprint", true, "wide");
  addFact(details, "certificate.derSize", "der-size");
  addFact(details, "certificate.authority", "authority");

  content.append(heading, details);
  if (certificate.subject_alt_names.length > 0) content.append(createNameList(certificate.subject_alt_names));
  if (certificate.warnings.length > 0) content.append(createWarnings(certificate));
  article.append(label, content);
  localizeCertificateCard(article, certificate);
  return article;
}

function addFact(list: HTMLDListElement, labelKey: MessageKey, field: string, code = false, className = ""): void {
  const item = document.createElement("div");
  if (className) item.className = className;
  const term = document.createElement("dt");
  term.dataset.i18n = labelKey;
  const detail = document.createElement("dd");
  detail.dataset.field = field;
  if (code) detail.className = "code-value";
  item.append(term, detail);
  list.append(item);
}

function createNameList(names: string[]): HTMLElement {
  const section = document.createElement("div");
  section.className = "name-list";
  const title = document.createElement("h4");
  title.dataset.i18n = "certificate.subjectAltNames";
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

function createWarnings(certificate: CertificateInfo): HTMLElement {
  const list = document.createElement("ul");
  list.className = "certificate-warnings";
  certificate.warnings.forEach((_, index) => {
    const item = document.createElement("li");
    item.dataset.warningIndex = String(index);
    list.append(item);
  });
  return list;
}

function localizeCertificateCard(article: HTMLElement, certificate: CertificateInfo): void {
  for (const element of article.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const key = element.dataset.i18n;
    if (key && hasMessageKey(key)) element.textContent = t(key);
  }
  const subject = certificate.subject ?? t("certificate.subjectUnavailable");
  const issuer = certificate.issuer ?? t("certificate.issuerUnavailable");
  article.querySelector<HTMLInputElement>('input[type="checkbox"]')?.setAttribute(
    "aria-label",
    t("certificate.select", { number: formatNumber(certificate.index + 1), subject }),
  );
  setCardField(article, "role", `${certificateRole(certificate.role)} · ${t("certificate.number", { number: formatNumber(certificate.index + 1) })}`);
  setCardField(article, "subject", subject);
  const validity = article.querySelector<HTMLElement>('[data-field="validity"]');
  if (validity) {
    validity.className = `validity-badge validity-${validityTone(certificate.validity_status)}`;
    validity.textContent = certificateValidity(certificate.validity_status);
  }
  setCardField(article, "issuer", issuer);
  setCardField(article, "valid-from", formatDate(certificate.valid_from));
  setCardField(article, "valid-until", formatDate(certificate.valid_until));
  setCardField(article, "serial-number", certificate.serial_number || "—");
  setCardField(article, "public-key", certificate.public_key_algorithm || "—");
  setCardField(article, "signature", certificate.signature_algorithm || "—");
  setCardField(article, "fingerprint", certificate.sha256_fingerprint || "—");
  setCardField(article, "der-size", formatBytes(certificate.der_size));
  setCardField(article, "authority", t(certificate.is_ca ? "certificate.yes" : "certificate.no"));

  certificate.warnings.forEach((warning, index) => {
    const item = article.querySelector<HTMLElement>(`[data-warning-index="${index}"]`);
    if (!item) return;
    item.textContent = warning.technicalDetail
      ? `${translateUiMessage(warning.message)} ${t("error.technicalDetail", { detail: warning.technicalDetail })}`
      : translateUiMessage(warning.message);
  });
}

function setCardField(article: HTMLElement, field: string, value: string): void {
  const element = article.querySelector<HTMLElement>(`[data-field="${field}"]`);
  if (element) element.textContent = value;
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
  announce({ key: selected ? "selection.allSelected" : "selection.allDeselected" });
}

function updateSelectionState(): void {
  const count = selectedIndices().length;
  selectedCount.textContent = t("selection.selected", { count: formatNumber(count) });
  exportHint.textContent = count > 0 ? tp("selection.included", count) : t("selection.none");
  for (const button of exportButtons) button.disabled = exportBusy || count === 0;
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
      filters: [{ name: t(format === "pem" ? "export.filterPem" : "export.filterC"), extensions: format === "pem" ? ["pem", "crt"] : ["c", "h"] }],
    });
    if (!path) {
      announce({ key: "export.cancelled" });
      return;
    }
    await writeFile(path, new TextEncoder().encode(generated.text));
    announce({ key: "export.saved", args: { path } });
  } catch (error: unknown) {
    showOperationError({ key: "export.saveFailed" }, normalizeApiError(error), "error.exportTitle");
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
    announce({ key: "export.copied" });
  } catch (error: unknown) {
    showOperationError({ key: "export.copyFailed" }, normalizeApiError(error), "error.copyTitle");
  } finally {
    setExportBusy(false);
  }
}

function setExportBusy(busy: boolean): void {
  exportBusy = busy;
  updateSelectionState();
}

function showOperationError(prefix: UiMessage, normalized: NormalizedApiError, titleKey: MessageKey): void {
  const messages = [prefix];
  if (normalized.apiError) messages.push(normalized.apiError.message);
  showError({
    titleKey,
    messages,
    technicalDetail: normalized.apiError?.technicalDetail ?? normalized.technicalFallback,
  });
}

function showNormalizedError(normalized: NormalizedApiError, titleKey: MessageKey): void {
  showError({
    titleKey,
    messages: normalized.apiError ? [normalized.apiError.message] : [{ key: "error.unexpected" }],
    technicalDetail: normalized.apiError?.technicalDetail ?? normalized.technicalFallback,
  });
}

function showError(error: DisplayError): void {
  currentError = error;
  currentAnnouncement = null;
  renderError(error);
  errorBanner.hidden = false;
  errorBanner.focus();
}

function renderError(error: DisplayError): void {
  const title = t(error.titleKey);
  const message = error.messages.map(translateUiMessage).join(" ");
  errorBanner.querySelector("strong")!.textContent = title;
  errorMessage.textContent = message;
  errorDetail.textContent = error.technicalDetail ? t("error.technicalDetail", { detail: error.technicalDetail }) : "";
  errorDetail.hidden = !error.technicalDetail;
  operationStatus.textContent = `${title}: ${message}`;
}

function hideError(): void {
  currentError = null;
  errorBanner.hidden = true;
  errorMessage.textContent = "";
  errorDetail.textContent = "";
}

function announce(message: UiMessage): void {
  currentAnnouncement = message;
  operationStatus.textContent = translateUiMessage(message);
}

function setText(selector: string, value: string): void {
  requiredElement<HTMLElement>(selector).textContent = value || "—";
}

function validationStatus(status: string): string {
  const key = `validation.status.${status}`;
  return hasMessageKey(key) ? t(key) : t("validation.status.unknown");
}

function certificateRole(role: string): string {
  const key = `certificate.role.${role}`;
  return hasMessageKey(key) ? t(key) : t("certificate.role.certificate");
}

function certificateValidity(status: string): string {
  const key = `certificate.validity.${status}`;
  return hasMessageKey(key) ? t(key) : t("certificate.validity.unknown");
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
