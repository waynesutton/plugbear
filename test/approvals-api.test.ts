// /api/approvals: local mode's approvals for a program on this Mac
// (Threadbear's runner), with the bearer key in secrets/approvals-key.
// Browsers are refused even with the key.

import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
import { request } from "node:http";
import { after, before, describe, it } from "node:test";

import { type Gateway, legacyClient, startGateway, stdioUpstream, textOf } from "./helpers.ts";

function rawGet(url: string, headers: Record<string, string>): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { headers }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("approvals API (local mode)", () => {
  let gateway: Gateway;
  let key: string;
  const hold = async (text: string) => {
    const client = await legacyClient(gateway, "codex");
    const held = await client.callTool({ name: "fake__send_message", arguments: { to: "ana", text } });
    await client.close();
    return /id (ap_[A-Za-z0-9_-]+)/.exec(textOf(held))![1]!;
  };
  const api = (path: string, init: RequestInit = {}, auth = key) =>
    fetch(`${gateway.url}${path}`, {
      ...init,
      headers: { authorization: `Bearer ${auth}`, "content-type": "application/json", ...(init.headers ?? {}) },
    });

  before(async () => {
    gateway = await startGateway({ upstreams: [stdioUpstream()], holdMs: 50, server: { mode: "local" } });
    key = readFileSync(gateway.layout.approvalsKey, "utf8").trim();
  });

  after(async () => {
    await gateway?.close();
  });

  it("writes a 0600 key and says so in /health", async () => {
    assert.match(key, /^[0-9a-f]{64}$/);
    assert.equal(statSync(gateway.layout.approvalsKey).mode & 0o777, 0o600);
    const health = (await (await fetch(`${gateway.url}/health`)).json()) as { approvalsApi?: number };
    assert.equal(health.approvalsApi, 1);
  });

  it("refuses a missing or wrong key", async () => {
    assert.equal((await fetch(`${gateway.url}/api/approvals`)).status, 401);
    assert.equal((await api("/api/approvals", {}, "0".repeat(64))).status, 401);
    assert.equal((await api("/api/approvals", {}, key.slice(1))).status, 401);
  });

  it("refuses anything a browser sends, even with the key", async () => {
    for (const headers of [{ origin: "http://127.0.0.1:8795" }, { "sec-fetch-site": "same-origin" }]) {
      assert.equal((await api("/api/approvals", { headers })).status, 403, JSON.stringify(headers));
    }
  });

  it("refuses another Host", async () => {
    const port = new URL(gateway.url).port;
    const evil = await rawGet(`${gateway.url}/api/approvals`, { host: `evil.example:${port}`, authorization: `Bearer ${key}` });
    assert.equal(evil.status, 403);
  });

  it("lists a held call with its arguments and page", async () => {
    const id = await hold("list me");
    const body = (await (await api("/api/approvals")).json()) as { approvals: Array<Record<string, unknown>> };
    const call = body.approvals.find((a) => a.id === id)!;
    assert.equal(call.status, "pending");
    assert.equal(call.agent, "codex");
    assert.equal(call.tool, "fake__send_message");
    assert.equal(call.upstreamTool, "send_message");
    assert.deepEqual(call.args, { to: "ana", text: "list me" });
    assert.equal(call.url, `${gateway.url}/approvals/${id}`);
    const one = (await (await api(`/api/approvals/${id}`)).json()) as { status: string };
    assert.equal(one.status, "pending");
  });

  it("approves and declines, once", async () => {
    const yes = await hold("approve me");
    const approved = await api(`/api/approvals/${yes}`, { method: "POST", body: JSON.stringify({ decision: "approve" }) });
    assert.equal(approved.status, 200);
    assert.equal(((await approved.json()) as { status: string }).status, "approved");
    assert.equal(gateway.approvals.get(yes)?.status, "approved");
    const again = await api(`/api/approvals/${yes}`, { method: "POST", body: JSON.stringify({ decision: "decline" }) });
    assert.equal(again.status, 409);
    assert.equal(gateway.approvals.get(yes)?.status, "approved");

    const no = await hold("decline me");
    const declined = await api(`/api/approvals/${no}`, { method: "POST", body: JSON.stringify({ decision: "decline", note: "not now" }) });
    assert.equal(declined.status, 200);
    assert.equal(gateway.approvals.get(no)?.status, "declined");
    const listed = (await (await api("/api/approvals")).json()) as { approvals: Array<{ id: string }> };
    assert.ok(!listed.approvals.some((a) => a.id === yes || a.id === no));
  });

  it("answers 404 and 400 for an unknown id or a bad body", async () => {
    assert.equal((await api("/api/approvals/ap_nope")).status, 404);
    assert.equal((await api("/api/approvals/ap_nope", { method: "POST", body: JSON.stringify({ decision: "approve" }) })).status, 404);
    const id = await hold("bad body");
    assert.equal((await api(`/api/approvals/${id}`, { method: "POST", body: "nope" })).status, 400);
    assert.equal((await api(`/api/approvals/${id}`, { method: "POST", body: JSON.stringify({ decision: "allow" }) })).status, 400);
    assert.equal(gateway.approvals.get(id)?.status, "pending");
  });
});

describe("approvals API (tailscale mode)", () => {
  let gateway: Gateway;

  before(async () => {
    gateway = await startGateway({ upstreams: [stdioUpstream()], server: { mode: "tailscale", publicUrl: "https://mac.example.ts.net:8443", adminLogins: ["a@example.com"] } });
  });

  after(async () => {
    await gateway?.close();
  });

  it("isn't there, and /health doesn't offer it", async () => {
    const health = (await (await fetch(`${gateway.url}/health`)).json()) as { approvalsApi?: number };
    assert.equal(health.approvalsApi, undefined);
    assert.notEqual((await fetch(`${gateway.url}/api/approvals`, { headers: { authorization: "Bearer x" } })).status, 200);
  });
});
