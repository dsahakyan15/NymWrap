export type SearchPageState = "ready" | "loading" | "challenge" | "login" | "unsupported";
export interface SearchStep { service: "google" | "youtube"; expected: string; letter?: string; results: boolean }

// Fixed code serialized into the isolated extension world. Never evaluates page or task text.
export function searchPageStep(step: SearchStep): SearchPageState {
  const url = new URL(location.href);
  const host = step.service === "google" ? "www.google.com" : "www.youtube.com";
  if (url.protocol !== "https:" || url.hostname !== host || url.port || url.username || url.password) return "unsupported";
  const text = `${document.title}\n${document.body?.innerText.slice(0, 12000) ?? ""}`.normalize("NFKC").toLowerCase();
  if (document.querySelector('iframe[src*="recaptcha"], iframe[src*="hcaptcha"], [class*="g-recaptcha"], [id*="captcha"], [data-sitekey]')
    || /captcha|recaptcha|hcaptcha|verify (you are|you're) human|unusual traffic|are you a robot|вы не робот|подтвердите.{0,20}человек|необычный трафик/.test(text) || url.pathname.startsWith("/sorry")) return "challenge";
  if (document.querySelector('input[type="password"]') || /\/(login|signin|sign-in|auth)(\/|$)/.test(url.pathname)) return "login";
  if (document.visibilityState !== "visible") return "unsupported";
  if (document.readyState === "loading") return "loading";
  if (step.results) {
    return url.pathname === (step.service === "google" ? "/search" : "/results")
      && url.searchParams.get(step.service === "google" ? "q" : "search_query") === step.expected ? "ready" : "unsupported";
  }
  if (url.pathname !== "/") return "unsupported";
  const input = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(step.service === "google" ? 'textarea[name="q"], input[name="q"]' : 'input[name="search_query"], input#search');
  if (!input) return "loading";
  if (!["INPUT", "TEXTAREA"].includes(input.tagName) || input.disabled || input.readOnly || input.value !== step.expected) return "unsupported";
  if (step.letter !== undefined) {
    if (Array.from(step.letter).length !== 1 || Array.from(step.expected).length >= 512) return "unsupported";
    input.focus();
    input.value = step.expected + step.letter;
    input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: step.letter }));
    if (input.value !== step.expected + step.letter) return "unsupported";
  }
  return "ready";
}
