import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  detectLocale,
  formatBytes,
  getLocale,
  normalizeLocale,
  setLocale,
  t,
  tp,
  translateUiMessage,
} from "./i18n";

describe("localization", () => {
  beforeEach(() => setLocale("en", false));

  it.each([
    ["en-US", "en"],
    ["zh-CN", "zh-CN"],
    ["zh-SG", "zh-CN"],
    ["zh-Hans", "zh-CN"],
    ["zh-TW", "zh-TW"],
    ["zh-HK", "zh-TW"],
    ["zh-Hant", "zh-TW"],
    ["zh-Hant-CN", "zh-TW"],
  ] as const)("normalizes %s to %s", (input, expected) => {
    expect(normalizeLocale(input)).toBe(expected);
  });

  it("uses a valid stored preference before browser languages", () => {
    expect(detectLocale(["zh-CN"], "zh-TW")).toBe("zh-TW");
    expect(detectLocale(["zh-CN"], "invalid")).toBe("zh-CN");
    expect(detectLocale(["fr-FR"], null)).toBe("en");
  });

  it("switches catalogs and interpolates named values", () => {
    setLocale("zh-CN", false);
    expect(getLocale()).toBe("zh-CN");
    expect(t("export.saved", { path: "C:\\cert.pem" })).toContain("C:\\cert.pem");
    expect(t("app.title")).toBe("证书提取器");
  });

  it("formats English plurals and Chinese counts", () => {
    expect(tp("results.certificateCount", 1)).toBe("1 certificate");
    expect(tp("results.certificateCount", 2)).toBe("2 certificates");
    setLocale("zh-TW", false);
    expect(tp("results.certificateCount", 2)).toBe("2 張憑證");
  });

  it("translates structured backend messages with numeric arguments", () => {
    setLocale("zh-CN", false);
    expect(translateUiMessage({ key: "backend.progress.captured", args: { count: 3 } })).toBe("已提取 3 个证书");
  });

  it("falls back safely for an unknown backend key", () => {
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    expect(translateUiMessage({ key: "backend.unknown" })).toBe("An unexpected error occurred.");
    expect(warning).toHaveBeenCalledOnce();
    warning.mockRestore();
  });

  it("formats byte quantities using the active locale", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
  });
});
