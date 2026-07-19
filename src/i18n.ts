import { en, type MessageKey } from "./locales/en";
import { zhCN } from "./locales/zh-CN";
import { zhTW } from "./locales/zh-TW";

export const supportedLocales = ["en", "zh-CN", "zh-TW"] as const;
export type AppLocale = (typeof supportedLocales)[number];
export type MessageArgs = Record<string, string | number>;
export interface UiMessage {
  key: string;
  args?: MessageArgs;
}

const LOCALE_STORAGE_KEY = "certificate-extractor.locale";
const catalogs = { en, "zh-CN": zhCN, "zh-TW": zhTW } as const;

function storedLocale(): AppLocale | null {
  try {
    const value = globalThis.localStorage?.getItem(LOCALE_STORAGE_KEY);
    return isAppLocale(value) ? value : null;
  } catch {
    return null;
  }
}

function browserLanguages(): string[] {
  if (typeof navigator === "undefined") return [];
  return [...(navigator.languages ?? []), navigator.language].filter(Boolean);
}

let activeLocale: AppLocale = detectLocale(browserLanguages(), storedLocale());

export function isAppLocale(value: unknown): value is AppLocale {
  return typeof value === "string" && supportedLocales.includes(value as AppLocale);
}

export function normalizeLocale(value: string): AppLocale | null {
  const normalized = value.trim().replaceAll("_", "-");
  if (!normalized) return null;
  const lower = normalized.toLowerCase();
  const subtags = lower.split("-");

  if (subtags[0] === "zh") {
    if (subtags.includes("hant")) return "zh-TW";
    if (subtags.includes("hans")) return "zh-CN";
    if (subtags.some((part) => ["tw", "hk", "mo"].includes(part))) return "zh-TW";
    if (subtags.some((part) => ["cn", "sg"].includes(part))) return "zh-CN";
    return "zh-CN";
  }
  if (subtags[0] === "en") return "en";
  return null;
}

export function detectLocale(languages: readonly string[], persisted: unknown = null): AppLocale {
  if (isAppLocale(persisted)) return persisted;
  for (const language of languages) {
    const match = normalizeLocale(language);
    if (match) return match;
  }
  return "en";
}

export function getLocale(): AppLocale {
  return activeLocale;
}

export function setLocale(locale: AppLocale, persist = true): void {
  activeLocale = locale;
  if (!persist) return;
  try {
    globalThis.localStorage?.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    // The app still switches language if WebView storage is unavailable.
  }
}

export function hasMessageKey(value: string): value is MessageKey {
  return Object.prototype.hasOwnProperty.call(en, value);
}

function interpolate(template: string, args: MessageArgs = {}): string {
  return template.replace(/{{\s*([\w.-]+)\s*}}/g, (placeholder, name: string) =>
    Object.prototype.hasOwnProperty.call(args, name) ? String(args[name]) : placeholder,
  );
}

export function t(key: MessageKey, args?: MessageArgs): string {
  return interpolate(catalogs[activeLocale][key] ?? en[key], args);
}

export function tp(base: string, count: number, args: MessageArgs = {}): string {
  const category = new Intl.PluralRules(activeLocale).select(count) === "one" ? "one" : "other";
  const key = `${base}.${category}`;
  const fallbackKey = `${base}.other`;
  if (hasMessageKey(key)) return t(key, { ...args, count: formatNumber(count) });
  if (hasMessageKey(fallbackKey)) return t(fallbackKey, { ...args, count: formatNumber(count) });
  return t("error.unexpected");
}

export function translateUiMessage(message: UiMessage | null | undefined): string {
  if (!message || typeof message.key !== "string") return t("error.unexpected");
  const count = message.args?.count;
  if (typeof count === "number") {
    const pluralKey = `${message.key}.${new Intl.PluralRules(activeLocale).select(count) === "one" ? "one" : "other"}`;
    if (hasMessageKey(pluralKey)) return t(pluralKey, { ...message.args, count: formatNumber(count) });
  }
  if (hasMessageKey(message.key)) return t(message.key, message.args);
  console.warn(`Unknown localization key: ${message.key}`);
  return t("error.unexpected");
}

export function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "—";
  return new Intl.DateTimeFormat(activeLocale, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function formatNumber(value: number, options?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(activeLocale, options).format(value);
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return t("format.bytes", { count: formatNumber(bytes) });
  return t("format.kilobytes", {
    count: formatNumber(bytes / 1024, { minimumFractionDigits: 1, maximumFractionDigits: 1 }),
  });
}
