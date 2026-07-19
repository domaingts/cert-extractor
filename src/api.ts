import { Channel, invoke } from "@tauri-apps/api/core";
import type { UiMessage } from "./i18n";

export type ValidationStatus = "trusted" | "warning" | "untrusted" | "unknown" | string;
export type ValidityStatus = "valid" | "expired" | "not_yet_valid" | "unknown" | string;
export type ExportFormat = "pem" | "c_expression";

export interface ExtractionRequest {
  hostname: string;
  port: number;
}

export interface ExtractionProgress {
  sequence: number;
  stage: string;
  message: UiMessage;
  technicalDetail?: string | null;
}

export interface CertificateWarning {
  message: UiMessage;
  technicalDetail?: string | null;
}

export interface CertificateInfo {
  index: number;
  role: string;
  subject: string | null;
  issuer: string | null;
  serial_number: string;
  valid_from: string;
  valid_until: string;
  validity_status: ValidityStatus;
  sha256_fingerprint: string;
  subject_alt_names: string[];
  signature_algorithm: string;
  public_key_algorithm: string;
  is_ca: boolean;
  der_size: number;
  warnings: CertificateWarning[];
}

export interface ValidationResult {
  status: ValidationStatus;
  message: UiMessage;
  detailMessage?: UiMessage | null;
  technicalDetail?: string | null;
}

export interface ExtractionResult {
  session_id: string;
  endpoint: string;
  connected_address: string;
  tls_version: string | null;
  cipher_suite: string | null;
  validation: ValidationResult;
  certificates: CertificateInfo[];
}

export interface ExportResult {
  text: string;
  suggested_filename: string;
  format: string;
}

export interface ApiErrorData {
  code: string;
  stage: string;
  message: UiMessage;
  technicalDetail?: string | null;
  retryable: boolean;
}

export interface NormalizedApiError {
  apiError: ApiErrorData | null;
  technicalFallback: string | null;
}

function isUiMessage(value: unknown): value is UiMessage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.key === "string" &&
    (candidate.args === undefined || (candidate.args !== null && typeof candidate.args === "object"));
}

function isApiErrorData(value: unknown): value is ApiErrorData {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.code === "string" &&
    typeof candidate.stage === "string" &&
    isUiMessage(candidate.message) &&
    typeof candidate.retryable === "boolean" &&
    (candidate.technicalDetail === undefined || candidate.technicalDetail === null || typeof candidate.technicalDetail === "string");
}

export function normalizeApiError(error: unknown): NormalizedApiError {
  if (isApiErrorData(error)) return { apiError: error, technicalFallback: null };
  if (typeof error === "string") {
    try {
      const parsed: unknown = JSON.parse(error);
      if (isApiErrorData(parsed)) return { apiError: parsed, technicalFallback: null };
    } catch {
      // Plain Tauri and JavaScript rejection strings are retained as technical detail.
    }
    return { apiError: null, technicalFallback: error };
  }
  if (error instanceof Error) return { apiError: null, technicalFallback: error.message };
  return { apiError: null, technicalFallback: null };
}

export async function extractCertificates(
  request: ExtractionRequest,
  onProgress: (progress: ExtractionProgress) => void,
): Promise<ExtractionResult> {
  const progressChannel = new Channel<ExtractionProgress>();
  progressChannel.onmessage = onProgress;

  return invoke<ExtractionResult>("extract_certificates", {
    request,
    progress: progressChannel,
  });
}

export function generateExport(
  sessionId: string,
  certificateIndices: number[],
  format: ExportFormat,
): Promise<ExportResult> {
  return invoke<ExportResult>("generate_export", {
    sessionId,
    certificateIndices,
    format,
  });
}
