import { beforeEach, describe, expect, it, vi } from "vitest";

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => {
  class Channel<T> {
    onmessage?: (message: T) => void;
  }

  return {
    Channel,
    invoke: invokeMock,
  };
});

import { extractCertificates, generateExport, normalizeApiError } from "./api";

const structuredError = {
  code: "dns_failed",
  stage: "resolving_dns",
  message: { key: "backend.error.dnsFailed" },
  technicalDetail: "lookup failed",
  retryable: true,
};

describe("Tauri API wrapper", () => {
  beforeEach(() => invokeMock.mockReset());

  it("passes the extraction request and progress channel", async () => {
    invokeMock.mockResolvedValue({ certificates: [] });
    const onProgress = vi.fn();

    await extractCertificates({ hostname: "example.com", port: 443 }, onProgress);

    expect(invokeMock).toHaveBeenCalledOnce();
    const [command, args] = invokeMock.mock.calls[0];
    expect(command).toBe("extract_certificates");
    expect(args.request).toEqual({ hostname: "example.com", port: 443 });
    expect(args.progress.onmessage).toBe(onProgress);
  });

  it("passes selected indices and the C expression format", async () => {
    invokeMock.mockResolvedValue({ text: "", suggested_filename: "certificate.txt", format: "c_expression" });

    await generateExport("session-id", [2, 0], "c_expression");

    expect(invokeMock).toHaveBeenCalledWith("generate_export", {
      sessionId: "session-id",
      certificateIndices: [2, 0],
      format: "c_expression",
    });
  });

  it("normalizes structured and JSON-encoded API errors", () => {
    expect(normalizeApiError(structuredError)).toEqual({ apiError: structuredError, technicalFallback: null });
    expect(normalizeApiError(JSON.stringify(structuredError))).toEqual({ apiError: structuredError, technicalFallback: null });
  });

  it("retains plain and JavaScript errors as technical fallbacks", () => {
    expect(normalizeApiError("plain failure")).toEqual({ apiError: null, technicalFallback: "plain failure" });
    expect(normalizeApiError(new Error("JavaScript failure"))).toEqual({ apiError: null, technicalFallback: "JavaScript failure" });
    expect(normalizeApiError({ nope: true })).toEqual({ apiError: null, technicalFallback: null });
  });
});
