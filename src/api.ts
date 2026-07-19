import { Channel, invoke } from "@tauri-apps/api/core";

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
  message: string;
  detail?: string | null;
}

export interface CertificateInfo {
  index: number;
  role: string;
  subject: string;
  issuer: string;
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
  warnings: string[];
}

export interface ValidationResult {
  status: ValidationStatus;
  message: string;
  detail?: string | null;
}

export interface ExtractionResult {
  session_id: string;
  endpoint: string;
  connected_address: string;
  tls_version: string;
  cipher_suite: string;
  validation: ValidationResult;
  certificates: CertificateInfo[];
}

export interface ExportResult {
  text: string;
  suggested_filename: string;
  format: string;
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
