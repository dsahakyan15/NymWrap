export type PageState = "ready" | "challenge" | "login" | "unsupported";
export interface PageSignals { url: string; title: string; text: string; hasPassword: boolean; hasChallenge: boolean }

export function pageState(signals: PageSignals): PageState {
  let url: URL;
  try { url = new URL(signals.url); } catch { return "unsupported"; }
  if (url.protocol !== "https:") return "unsupported";
  const content = `${signals.title}\n${signals.text}`.normalize("NFKC").toLowerCase();
  if (signals.hasChallenge || /captcha|recaptcha|hcaptcha|verify (you are|you're) human|unusual traffic|are you a robot|вы не робот|подтвердите.{0,20}человек|необычный трафик/.test(content) || url.pathname.startsWith("/sorry")) return "challenge";
  if (signals.hasPassword || /(^|\.)(accounts\.google\.com|auth\.openai\.com)$/.test(url.hostname) || /\/(login|signin|sign-in|auth)(\/|$)/.test(url.pathname)) return "login";
  if (!["www.youtube.com", "youtube.com", "myadcenter.google.com", "www.google.com"].includes(url.hostname)) return "unsupported";
  return "ready";
}

export function coverUrl(service: string, text: string): string {
  if (!text.trim() || text.length > 4096) throw new Error("invalid_cover_task");
  if (service === "google") return `https://www.google.com/search?q=${encodeURIComponent(text)}`;
  if (service === "youtube") return `https://www.youtube.com/results?search_query=${encodeURIComponent(text)}`;
  throw new Error("ai_web_automation_disabled");
}

export function snapshotTitles(titles: readonly string[]): string[] {
  return titles.map(t => t.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 1024)).filter(Boolean).slice(0, 30);
}
