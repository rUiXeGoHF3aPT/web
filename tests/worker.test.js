import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker/src.js";

const origin = "https://example.github.io";
const secret = "1234567890abcdefghijklmnopqrstuvwxyz";
function setup() {
  const values = new Map(), options = [];
  const env = { SITE_ORIGIN: origin, ADMIN_TOKEN: secret, VISITS: {
    async put(key, value, opt) { values.set(key, opt.metadata); options.push(opt); },
    async list({ prefix, limit, cursor }) {
      const keys = [...values.keys()].filter(k => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0, slice = keys.slice(start, start + limit);
      return { keys: slice.map(name => ({ name, metadata: values.get(name) })), list_complete: start + limit >= keys.length, cursor: String(start + limit) };
    },
  } };
  return { env, values, options };
}
function request(path, method = "GET", opts = {}) {
  return new Request(`https://worker.example${path}`, { method, headers: opts.headers || {}, ...(opts.body === undefined ? {} : { body: opts.body }) });
}
const visit = (path = "/app/") => request("/api/visit", "POST", { headers: { Origin: origin, "CF-Connecting-IP": "203.0.113.4" }, body: JSON.stringify({ path }) });
const get = (token = secret, cursor = "") => request(`/api/visits${cursor ? `?cursor=${cursor}` : ""}`, "GET", { headers: { Origin: origin, Authorization: `Bearer ${token}` } });

test("records IP and pathname privately with a 30-day expiry", async () => {
  const { env, values, options } = setup();
  let res = await worker.fetch(visit(), env);
  assert.equal(res.status, 201); assert.equal(res.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal(values.size, 1); assert.equal(options[0].expirationTtl, 2592000);
  assert.equal((await worker.fetch(get("bad"), env)).status, 401);
  res = await worker.fetch(get(), env);
  const data = await res.json(); assert.equal(data.visits[0].ip, "203.0.113.4"); assert.equal(data.visits[0].path, "/app/"); assert.equal(data.cursor, null);
  assert.equal(res.headers.get("Cache-Control"), "no-store");
});
test("denies cross-origin access, malformed visits, large bodies and absent tokens", async () => {
  const { env, values } = setup();
  assert.equal((await worker.fetch(request("/api/visit", "POST", { headers: { Origin: "https://attacker.example" }, body: "{}" }), env)).status, 403);
  assert.equal((await worker.fetch(visit("/page?secret=1"), env)).status, 400);
  assert.equal((await worker.fetch(request("/api/visit", "POST", { headers: { Origin: origin, "CF-Connecting-IP": "203.0.113.1" }, body: "x".repeat(2049) }), env)).status, 413);
  assert.equal((await worker.fetch(request("/api/visits"), env)).status, 401);
  assert.equal((await worker.fetch(get(), { ...env, ADMIN_TOKEN: "short" })).status, 401);
  assert.equal(values.size, 0);
});
test("CORS preflight and log pagination", async () => {
  const { env } = setup();
  const preflight = await worker.fetch(request("/api/visit", "OPTIONS", { headers: { Origin: origin } }), env);
  assert.equal(preflight.status, 204); assert.equal(preflight.headers.get("Access-Control-Allow-Origin"), origin);
  for (let i = 0; i < 52; i++) assert.equal((await worker.fetch(visit(`/page-${i}`), env)).status, 201);
  const first = await (await worker.fetch(get(), env)).json();
  assert.equal(first.visits.length, 50); assert.ok(first.cursor);
  const second = await (await worker.fetch(get(secret, first.cursor), env)).json();
  assert.equal(second.visits.length, 2); assert.equal(second.cursor, null);
  assert.equal(new Set([...first.visits, ...second.visits].map(v => v.path)).size, 52);
});
