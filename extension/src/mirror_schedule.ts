import { pageState, snapshotTitles } from "./safety.js";
import type { CapturedPage } from "./capture.js";
import type { Command, Result } from "./protocol.js";

export const MIRROR_ORIGINS = ["https://www.youtube.com/*", "https://youtube.com/*"];
export const MIRROR_ALARM = "nymwrap-mirror-hourly-v1";
const DAY = 86400;
const codes = ["disabled", "ready", "saved", "no_tab", "empty", "paused", "locked", "unavailable", "captcha", "login", "permission_required"] as const;
export type ScheduleCode = typeof codes[number];
// Public settings/event metadata only. No page text, URLs, tasks or snapshots on disk.
export interface ScheduleState { enabled: boolean; last_attempt: number; last_saved: number; code: ScheduleCode }
interface Bridge { request(command: Command): Promise<Result>; close(): void }
export interface ScheduleHooks {
  load(): Promise<unknown>;
  save(state: ScheduleState): Promise<void>;
  permitted(): Promise<boolean>;
  bridge(): Bridge;
  tabs(): Promise<{ id?: number; url?: string; incognito?: boolean }[]>;
  capture(id: number): Promise<CapturedPage | undefined>;
  now(): number;
  eventId(): string;
}
const defaults = (): ScheduleState => ({ enabled: false, last_attempt: 0, last_saved: 0, code: "disabled" });
export function scheduleState(value: unknown): ScheduleState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return defaults();
  const v = value as Record<string, unknown>;
  if (Object.keys(v).sort().join() !== "code,enabled,last_attempt,last_saved" || typeof v.enabled !== "boolean"
    || ![v.last_attempt, v.last_saved].every(n => typeof n === "number" && Number.isSafeInteger(n) && n >= 0)
    || !codes.includes(v.code as ScheduleCode)) return defaults();
  return { enabled: v.enabled, last_attempt: v.last_attempt as number, last_saved: v.last_saved as number, code: v.code as ScheduleCode };
}
export function youtubeHome(value: string | undefined): boolean {
  try {
    const url = new URL(value ?? "");
    return url.protocol === "https:" && !url.port && !url.username && !url.password
      && ["www.youtube.com", "youtube.com"].includes(url.hostname) && url.pathname === "/";
  } catch { return false; }
}
export class MirrorScheduler {
  private state = defaults();
  private initialized: Promise<void> | undefined;
  private writes: Promise<void> = Promise.resolve();
  private generation = 0;
  private running = false;
  constructor(private hooks: ScheduleHooks) {}
  private async init() {
    this.initialized ??= this.hooks.load().then(v => { this.state = scheduleState(v); });
    await this.initialized;
  }
  private persist() {
    const value = { ...this.state };
    this.writes = this.writes.catch(() => {}).then(() => this.hooks.save(value));
    return this.writes;
  }
  async status(): Promise<ScheduleState> { await this.init(); return { ...this.state }; }
  async configure(enabled: boolean, code: ScheduleCode = enabled ? "ready" : "disabled") {
    await this.init();
    const generation = ++this.generation;
    const permitted = !enabled || await this.hooks.permitted();
    if (generation !== this.generation) return { ...this.state };
    if (!permitted) throw Error("mirror_permission_required");
    this.state = { ...this.state, enabled, code };
    await this.persist();
    return { ...this.state };
  }
  async tick(): Promise<void> {
    await this.init();
    if (this.running || !this.state.enabled) return;
    const at = Math.floor(this.hooks.now() / 60) * 60;
    if (!Number.isSafeInteger(at) || at <= 0) return;
    // A backward clock postpones work. Missed periods never cause a catch-up burst.
    if ((this.state.last_saved && at < this.state.last_saved + DAY)
      || (this.state.last_attempt && at < this.state.last_attempt + DAY)) return;
    this.running = true;
    const generation = this.generation;
    const active = () => generation === this.generation && this.state.enabled;
    const update = async (code: ScheduleCode) => {
      if (active()) { this.state.code = code; await this.persist(); }
    };
    let bridge: Bridge | undefined;
    try {
      if (!await this.hooks.permitted()) {
        if (active()) await this.configure(false, "permission_required");
        return;
      }
      if (!active()) return;
      bridge = this.hooks.bridge();
      const status = await bridge.request({ kind: "status" });
      if (!active()) return;
      if (status.kind !== "status") throw Error("invalid_bridge_reply");
      if (status.paused) { await update("paused"); return; }
      const tabs = await this.hooks.tabs();
      if (!active()) return;
      const tab = tabs.find(t => t.id !== undefined && !t.incognito && youtubeHome(t.url));
      if (tab?.id === undefined) { await update("no_tab"); return; }
      // Reserve the daily attempt before page access. Lost ACKs and worker restarts do not replay it.
      this.state.last_attempt = at;
      await this.persist();
      if (!active()) return;
      const page = await this.hooks.capture(tab.id);
      if (!active()) return;
      if (!page) throw Error("capture_failed");
      const safety = pageState(page.signals);
      if (safety === "challenge" || safety === "login") {
        // Disable first, even if the core disconnects before it can record the stop.
        await this.configure(false, safety === "challenge" ? "captcha" : "login");
        await bridge.request({ kind: "safety_stop", event_id: this.hooks.eventId(), reason: safety === "challenge" ? "captcha" : "login" });
        return;
      }
      if (safety !== "ready" || !youtubeHome(page.signals.url)) { await update("no_tab"); return; }
      const items = snapshotTitles(page.titles);
      if (!items.length) { await update("empty"); return; }
      // Pause, revocation or navigation can occur while the DOM was being read.
      if (!await this.hooks.permitted() || !active()) return;
      const latest = await bridge.request({ kind: "status" });
      if (!active()) return;
      if (latest.kind !== "status") throw Error("invalid_bridge_reply");
      if (latest.paused) { await update("paused"); return; }
      const result = await bridge.request({ kind: "snapshot", snapshot: { kind: "youtube_feed", items, captured_at: at } });
      if (result.kind !== "ack") throw Error("invalid_bridge_reply");
      if (active()) { this.state.last_saved = at; await update("saved"); }
    } catch (error) {
      await update(error instanceof Error && error.message === "workspace_locked" ? "locked" : "unavailable");
    } finally {
      bridge?.close();
      this.running = false;
    }
  }
}
