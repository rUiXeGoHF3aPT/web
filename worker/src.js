const TTL = 30 * 24 * 60 * 60;
const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

function cors(origin, env) {
  return origin && origin === env.SITE_ORIGIN ? {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    Vary: "Origin",
  } : {};
}
function json(data, status, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...headers, "Content-Type": "application/json; charset=utf-8", ...extra } });
}
async function authorized(request, env) {
  const supplied = request.headers.get("Authorization") || "";
  if (!env.ADMIN_TOKEN || env.ADMIN_TOKEN.length < 32 || !supplied.startsWith("Bearer ")) return false;
  const encoder = new TextEncoder();
  const [actual, expected] = await Promise.all([supplied.slice(7), env.ADMIN_TOKEN].map(value => crypto.subtle.digest("SHA-256", encoder.encode(value))));
  const a = new Uint8Array(actual), b = new Uint8Array(expected);
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin"), extra = cors(origin, env);
    if (origin && origin !== env.SITE_ORIGIN) return json({ error: "Origin not allowed" }, 403);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers, ...extra } });
    const url = new URL(request.url);
    if (url.pathname === "/api/visit" && request.method === "POST") {
      // Browser requests must originate from the configured site.
      if (!origin || !env.SITE_ORIGIN) return json({ error: "Origin required" }, 403, extra);
      if (Number(request.headers.get("Content-Length") || 0) > 2048) return json({ error: "Request too large" }, 413, extra);
      let body;
      try {
        const reader = request.body?.getReader();
        if (!reader) return json({ error: "Invalid JSON" }, 400, extra);
        const chunks = []; let size = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 2048) { await reader.cancel(); return json({ error: "Request too large" }, 413, extra); }
          chunks.push(value);
        }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        body = JSON.parse(new TextDecoder().decode(bytes));
      } catch { return json({ error: "Invalid JSON" }, 400, extra); }
      const ip = request.headers.get("CF-Connecting-IP");
      if (!ip || !body || typeof body.path !== "string" || !body.path.startsWith("/") || body.path.length > 180 || /[?#\x00-\x1f]/.test(body.path)) return json({ error: "Invalid visit" }, 400, extra);
      const now = Date.now();
      // Inverted time makes KV's ascending listing put the newest visits first.
      const key = `visit:${String(9999999999999 - now).padStart(13, "0")}:${crypto.randomUUID()}`;
      const metadata = { time: new Date(now).toISOString(), ip, path: body.path };
      await env.VISITS.put(key, "", { expirationTtl: TTL, metadata });
      return json({ ok: true }, 201, extra);
    }
    if (url.pathname === "/api/visits" && request.method === "GET") {
      if (!await authorized(request, env)) return json({ error: "Unauthorized" }, 401, extra);
      const cursor = url.searchParams.get("cursor");
      if (cursor && cursor.length > 2048) return json({ error: "Invalid cursor" }, 400, extra);
      const list = await env.VISITS.list({ prefix: "visit:", limit: 50, ...(cursor ? { cursor } : {}) });
      const visits = list.keys.map(key => key.metadata).filter(Boolean);
      return json({ visits, cursor: list.list_complete ? null : list.cursor }, 200, extra);
    }
    return json({ error: "Not found" }, 404, extra);
  },
};
