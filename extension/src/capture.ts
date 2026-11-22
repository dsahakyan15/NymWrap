import type { PageSignals } from "./safety.js";

export interface CapturedPage { signals: PageSignals; titles: string[] }

// Serialized by scripting.executeScript: keep this function self-contained.
// Page strings remain data; no page scripts, links or handlers are invoked.
export function readMirrorPage(): CapturedPage {
  const url = new URL(location.href);
  const supported = url.protocol === "https:" && !url.username && !url.password && !url.port
    && ["www.youtube.com", "youtube.com"].includes(url.hostname);
  return {
    signals: {
      url: location.href,
      title: supported ? document.title.slice(0, 1024) : "",
      text: supported ? document.body?.innerText.slice(0, 12000) ?? "" : "",
      hasPassword: supported && !!document.querySelector('input[type="password"]'),
      hasChallenge: supported && !!document.querySelector('iframe[src*="recaptcha"], iframe[src*="hcaptcha"], [class*="g-recaptcha"], [id*="captcha"], [data-sitekey]'),
    },
    titles: supported ? Array.from(document.querySelectorAll("ytd-rich-item-renderer #video-title, ytd-rich-item-renderer .yt-lockup-metadata-view-model__title"))
      .slice(0, 30).map(e => e.textContent ?? "") : [],
  };
}
