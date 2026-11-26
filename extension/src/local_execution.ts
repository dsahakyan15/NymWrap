import { task as validateTask, type Command, type Result } from "./protocol.js";
import { localTarget, type LocalService, type LocalStep, type LocalReply } from "./local_page.js";
export const LOCAL_ORIGINS = ["https://127.0.0.1/*"];
interface LocalHooks {
  bridge(): { request(command: Command): Promise<Result>; close(): void };
  permitted(): Promise<boolean>; create(url: string): Promise<number>; navigate(id: number, url: string): Promise<void>;
  close(id: number): Promise<void>;
  step(id: number, step: LocalStep): Promise<LocalReply>;
  wait(ms: number, signal: AbortSignal): Promise<void>; now(): number; random(): number; eventId(): string;
}
export class LocalExecutor {
  private controller: AbortController | undefined;
  constructor(private hooks: LocalHooks) {}
  get running() { return !!this.controller; }
  cancel() { this.controller?.abort(); }
  async run(value: unknown, target: string): Promise<void> {
    const task = validateTask(value), origin = localTarget(target, task.service);
    if (this.running) throw Error("request_in_progress");
    if (Array.from(task.text).length > 512) throw Error("manual_action_required");
    const service = task.service as LocalService, controller = new AbortController(); this.controller = controller;
    const started = this.hooks.now(); let token: string | undefined, tabId: number | undefined;
    let bridge: ReturnType<LocalHooks["bridge"]> | undefined;
    const active = () => { if (controller.signal.aborted || this.hooks.now() - started > 300000) throw Error("execution_interrupted"); };
    const request = async (command: Command) => { const result = await bridge!.request(command); active(); return result; };
    const ready = async () => {
      active(); if (!await this.hooks.permitted()) throw Error("permission_required"); active();
      const status = await request({ kind: "status" });
      if (status.kind !== "status") throw Error("invalid_bridge_reply");
      if (status.paused) throw Error("paused");
      if (status.mode !== "extension" || (service !== "youtube" && !status.ai_web_automation)) throw Error("manual_action_required");
      if (token && (await request({ kind: "validate_search", task, token })).kind !== "ack") throw Error("invalid_bridge_reply");
    };
    const delay = async (ms: number) => { await this.hooks.wait(ms, controller.signal); active(); };
    const random = (min: number, max: number) => { const n = this.hooks.random(); if (!Number.isFinite(n) || n < 0 || n >= 1) throw Error("invalid_random"); return min + Math.floor(n * (max - min + 1)); };
    try {
      bridge = this.hooks.bridge(); await ready();
      const grant = await request({ kind: "begin_search", task });
      if (grant.kind !== "execution") throw Error("invalid_bridge_reply");
      token = grant.token;
      await ready(); const id = await this.hooks.create(target); tabId = id; active();
      const inspect = async (phase: LocalStep["phase"], expected: string, letter?: string, loading = false): Promise<LocalReply> => {
        for (let i = 0; i < 50; ++i) {
          await ready(); const reply = await this.hooks.step(id, { service, origin, phase, expected, ...(letter === undefined ? {} : { letter }) }); active();
          if (reply.state === "challenge" || reply.state === "login") {
            await request({ kind: "safety_stop", event_id: this.hooks.eventId(), reason: reply.state === "challenge" ? "captcha" : "login" });
            throw Error("safety_stop");
          }
          if (reply.state === "ready") return reply;
          // Never retry a mutation, even if its acknowledgement was lost.
          if (reply.state !== "loading" || !loading) throw Error("execution_interrupted");
          await delay(200);
        }
        throw Error("execution_interrupted");
      };
      await inspect("compose", "", undefined, true);
      let prefix = "";
      for (const letter of task.text) { await delay(random(60, 180)); await inspect("compose", prefix, letter); prefix += letter; }
      await inspect("compose", prefix);
      let position = 0, videoStart = 0;
      if (service === "youtube") {
        await ready(); await this.hooks.navigate(id, `${target}results?search_query=${encodeURIComponent(task.text)}`);
        const result = await inspect("results", prefix, undefined, true);
        if (!result.video || !/^[A-Za-z0-9_-]{1,64}$/.test(result.video)) throw Error("execution_interrupted");
        await ready(); await this.hooks.navigate(id, `${target}watch?v=${encodeURIComponent(result.video)}`);
        const playing = await inspect("play", prefix, undefined, true);
        if(playing.position === undefined || !Number.isFinite(playing.position)) throw Error("execution_interrupted");
        videoStart = position = playing.position;
      } else await inspect("submit", prefix);
      let remaining = random(20000, 90000);
      while (remaining > 0) {
        const ms = Math.min(1000, remaining); await delay(ms);
        const result = await inspect(service === "youtube" ? "watch" : "sent", prefix);
        if (service === "youtube") {
          if (result.position === undefined || !Number.isFinite(result.position) || result.position < position) throw Error("execution_interrupted");
          position = result.position;
        }
        remaining -= ms;
      }
      if (service === "youtube" && position - videoStart < 19.5) throw Error("execution_interrupted");
      await ready(); if ((await request({ kind: "finish_search", task, token })).kind !== "ack") throw Error("invalid_bridge_reply");
    } catch (error) {
      if (token && bridge) try { await bridge.request({ kind: "pause", paused: true }); } catch { /* disconnected: stop locally */ }
      throw error;
    } finally {
      if(service === "youtube" && tabId !== undefined) {
        try {
          const stopped = await this.hooks.step(tabId, {service,origin,phase:"stop",expected:""});
          if(stopped.state !== "ready") await this.hooks.close(tabId);
        } catch { try { await this.hooks.close(tabId); } catch { /* already closed */ } }
      }
      bridge?.close(); this.controller = undefined;
    }
  }
}
