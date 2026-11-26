import type { Task } from "./protocol.js";
export type LocalService = Exclude<Task["service"], "google">;
export type LocalState = "ready" | "loading" | "challenge" | "login" | "unsupported";
export interface LocalStep {
  service: LocalService; origin: string; expected: string;
  phase: "compose" | "results" | "play" | "watch" | "submit" | "sent" | "stop";
  letter?: string;
}
export interface LocalReply { state: LocalState; video?: string; position?: number }

// Explicitly local: no DNS, credentials, fragment or page-selected origin.
export function localTarget(value: string, service: Task["service"]): string {
  const url = new URL(value);
  if (!["youtube", "chatgpt", "claude", "gemini"].includes(service)
    || url.protocol !== "https:" || url.hostname !== "127.0.0.1" || url.username || url.password
    || url.pathname !== `/drift-fixtures/${service}/` || url.search || url.hash
    || value !== `${url.origin}/drift-fixtures/${service}/`) throw Error("local_fixture_required");
  return url.origin;
}

// Serialized into the isolated world. Page/model strings remain text nodes and values.
export function localPageStep(step: LocalStep): LocalReply {
  const url = new URL(location.href), base = `/drift-fixtures/${step.service}/`;
  const origin = new URL(step.origin);
  if (origin.protocol !== "https:" || origin.hostname !== "127.0.0.1" || origin.origin !== step.origin
    || url.origin !== step.origin || url.username || url.password) return { state: "unsupported" };
  // Stopping already-started local media is allowed even on a challenge overlay.
  if (step.phase === "stop") {
    if (step.service !== "youtube" || url.pathname !== base + "watch") return { state: "unsupported" };
    for (const video of document.querySelectorAll<HTMLVideoElement>("video.html5-main-video")) video.pause();
    return { state: "ready" };
  }
  const text = `${document.title}\n${document.body?.innerText.slice(0, 12000) ?? ""}`.normalize("NFKC").toLowerCase();
  if (document.querySelector('iframe[src*="recaptcha"], iframe[src*="hcaptcha"], [class*="g-recaptcha"], [id*="captcha"], [data-sitekey]')
    || /captcha|recaptcha|hcaptcha|verify (you are|you're) human|unusual traffic|are you a robot|вы не робот|подтвердите.{0,20}человек|необычный трафик/.test(text)) return { state: "challenge" };
  if (document.querySelector('input[type="password"], input[autocomplete="username"], form[action*="login"], form[action*="signin"]')
    || /\/(login|signin|sign-in|auth)(\/|$)/.test(url.pathname)) return { state: "login" };
  if (document.visibilityState !== "visible") return { state: "unsupported" };
  if (document.readyState === "loading") return { state: "loading" };
  if (step.phase === "results") {
    if (step.service !== "youtube" || url.pathname !== base + "results" || url.searchParams.size !== 1
      || url.searchParams.get("search_query") !== step.expected) return { state: "unsupported" };
    const links = document.querySelectorAll<HTMLAnchorElement>('ytd-video-renderer a#video-title[href]');
    if (!links.length) return { state: "unsupported" };
    const video = new URL(links[0]!.href, url);
    const id = video.searchParams.get("v");
    return video.origin === step.origin && video.pathname === base + "watch" && !video.username && !video.password && !video.hash
      && video.searchParams.size === 1 && id && /^[A-Za-z0-9_-]{1,64}$/.test(id) ? { state: "ready", video: id } : { state: "unsupported" };
  }
  if (step.phase === "play" || step.phase === "watch") {
    if (step.service !== "youtube" || url.pathname !== base + "watch" || url.searchParams.size !== 1
      || !/^[A-Za-z0-9_-]{1,64}$/.test(url.searchParams.get("v") ?? "")) return { state: "unsupported" };
    const videos = document.querySelectorAll<HTMLVideoElement>("video.html5-main-video");
    if (videos.length !== 1) return { state: "unsupported" };
    const video = videos[0]!;
    if (video.error || video.ended || !Number.isFinite(video.currentTime) || video.playbackRate !== 1) return { state: "unsupported" };
    if (step.phase === "play") { const position = video.currentTime; void video.play().catch(() => {}); return { state: "ready", position }; }
    return video.paused ? { state: "unsupported" } : { state: "ready", position: video.currentTime };
  }
  if (url.pathname !== base || url.search || url.hash) return { state: "unsupported" };
  if (step.phase === "sent") {
    const selector = step.service === "chatgpt" ? '[data-message-author-role="user"]' : step.service === "claude" ? '[data-testid="user-message"]' : "user-query .query-text";
    const messages = document.querySelectorAll(selector);
    return messages.length === 1 && messages[0]!.textContent === step.expected ? { state: "ready" } : { state: "unsupported" };
  }
  const selector = step.service === "youtube" ? 'input[name="search_query"]' : step.service === "chatgpt" ? '#prompt-textarea[contenteditable="true"], textarea#prompt-textarea' : step.service === "claude" ? 'div[contenteditable="true"][role="textbox"]' : 'rich-textarea div[contenteditable="true"][role="textbox"]';
  const inputs = document.querySelectorAll<HTMLElement>(selector);
  if (inputs.length !== 1) return { state: "unsupported" };
  const input = inputs[0]!;
  if (!input.getClientRects().length) return { state: "unsupported" };
  const field = input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement ? input : undefined;
  if (field ? field.disabled || field.readOnly || field.value !== step.expected : !input.isContentEditable || input.textContent !== step.expected || input.getAttribute("aria-disabled") === "true") return { state: "unsupported" };
  if (step.phase === "submit") {
    if (step.service === "youtube") return { state: "unsupported" };
    const selector = step.service === "chatgpt" ? 'button[data-testid="send-button"]' : step.service === "claude" ? 'button[aria-label="Send message"]' : 'button[aria-label="Send"]';
    const buttons = document.querySelectorAll<HTMLButtonElement>(selector);
    if (buttons.length !== 1 || !buttons[0]!.getClientRects().length || buttons[0]!.disabled || buttons[0]!.getAttribute("aria-disabled") === "true") return { state: "unsupported" };
    buttons[0]!.click(); return { state: "ready" };
  }
  if (step.letter !== undefined) {
    if (Array.from(step.letter).length !== 1 || Array.from(step.expected).length >= 512) return { state: "unsupported" };
    input.focus();
    if (field) field.value = step.expected + step.letter;
    else input.append(document.createTextNode(step.letter));
    input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: step.letter }));
    if ((field ? field.value : input.textContent) !== step.expected + step.letter) return { state: "unsupported" };
  }
  return { state: "ready" };
}
