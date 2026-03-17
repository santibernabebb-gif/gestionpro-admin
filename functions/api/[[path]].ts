export const onRequest: PagesFunction = async (context) => {
  const { request, env } = context;
  const u = new URL(request.url);

  // ── DEBUG identity ─────────────────────────────────────────────────────────
  if (u.pathname === "/api/debug-identity") {
    const cookie = request.headers.get("cookie") || "";
    const userAgent = request.headers.get("user-agent") || "";
    let result: any = null;
    try {
      const r = await fetch("https://gestionpro-admin.pages.dev/cdn-cgi/access/get-identity", {
        headers: { cookie, "user-agent": userAgent },
      });
      result = { status: r.status, body: await r.text() };
    } catch (e: any) { result = { error: String(e) }; }
    return new Response(JSON.stringify({ origin: u.origin, result }, null, 2), {
      headers: { "content-type": "application/json" },
    });
  }

  // ── DEBUG activate ─────────────────────────────────────────────────────────
  // Llama directamente al worker de Activate con la firma y muestra la respuesta
  if (u.pathname === "/api/debug-activate") {
    const email = "soporte.gestionproapp@gmail.com";
    const targetPath = "/admin/user";
    const search = "?query=test-debug-123";
    const ts = Date.now().toString();
    const dataToSign = `${ts}:${email}:GET:${targetPath}:${search}`;
    const sig = await hmacSha256Hex(env.ADMIN_PROXY_SECRET, dataToSign);

    const targetUrl = "https://recetassaludablespro.santibernabebb.workers.dev" + targetPath + search;

    let workerRes: any = null;
    try {
      const r = await fetch(targetUrl, {
        method: "GET",
        headers: {
          "content-type": "application/json",
          "x-admin-email": email,
          "x-admin-ts": ts,
          "x-admin-sig": sig,
        },
      });
      workerRes = { status: r.status, body: await r.text() };
    } catch (e: any) { workerRes = { error: String(e) }; }

    return new Response(JSON.stringify({
      dataToSign,
      sig,
      secretPresent: !!env.ADMIN_PROXY_SECRET,
      secretLength: (env.ADMIN_PROXY_SECRET || "").length,
      workerRes,
    }, null, 2), {
      headers: { "content-type": "application/json" },
    });
  }
  // ── FIN DEBUG ──────────────────────────────────────────────────────────────

  const who = await fetchIdentityFromAccess(request);
  const email = (who?.email || "").toLowerCase();
  const allowed = "soporte.gestionproapp@gmail.com";
  if (email !== allowed) {
    return new Response("Unauthorized", { status: 401 });
  }

  const incomingPath = u.pathname.replace(/^\/api/, "");

  const routeTable: Record<string, { methods: Set<string>; worker: "gestionpro" | "activate"; targetPath: string }> = {
    "/admin/user":        { methods: new Set(["GET"]),  worker: "gestionpro", targetPath: "/admin/user" },
    "/admin/add-credits": { methods: new Set(["POST"]), worker: "gestionpro", targetPath: "/admin/add-credits" },
    "/admin/reconcile":   { methods: new Set(["POST"]), worker: "gestionpro", targetPath: "/admin/reconcile" },
    "/admin/reset-user":  { methods: new Set(["POST"]), worker: "gestionpro", targetPath: "/admin/reset-user" },
    "/admin/purchasers":  { methods: new Set(["GET"]),  worker: "gestionpro", targetPath: "/admin/purchasers" },
    "/admin/api-logs":    { methods: new Set(["GET"]),  worker: "gestionpro", targetPath: "/admin/api-logs" },
    "/activate/user":       { methods: new Set(["GET"]),  worker: "activate", targetPath: "/admin/user" },
    "/activate/add-tokens": { methods: new Set(["POST"]), worker: "activate", targetPath: "/admin/add-tokens" },
    "/activate/reconcile":  { methods: new Set(["POST"]), worker: "activate", targetPath: "/admin/reconcile" },
    "/activate/reset-user": { methods: new Set(["POST"]), worker: "activate", targetPath: "/admin/reset-user" },
    "/activate/purchasers": { methods: new Set(["GET"]),  worker: "activate", targetPath: "/admin/purchasers" },
    "/activate/api-logs":   { methods: new Set(["GET"]),  worker: "activate", targetPath: "/admin/api-logs" },
  };

  const matched = routeTable[incomingPath];
  if (!matched || !matched.methods.has(request.method)) {
    return new Response("Not Found", { status: 404 });
  }

  const workerBase = matched.worker === "gestionpro"
    ? "https://mi-api-presupuestos-v5.santibernabebb.workers.dev"
    : "https://recetassaludablespro.santibernabebb.workers.dev";

  const targetUrl = workerBase + matched.targetPath + u.search;

  const ts = Date.now().toString();
  const dataToSign = `${ts}:${email}:${request.method}:${matched.targetPath}:${u.search}`;
  const sig = await hmacSha256Hex(env.ADMIN_PROXY_SECRET, dataToSign);

  const headers = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const accept = request.headers.get("accept");
  if (accept) headers.set("accept", accept);
  headers.set("x-admin-email", email);
  headers.set("x-admin-ts", ts);
  headers.set("x-admin-sig", sig);

  const body = request.method === "GET" || request.method === "HEAD"
    ? undefined
    : await request.arrayBuffer();

  return fetch(targetUrl, { method: request.method, headers, body });
};

async function fetchIdentityFromAccess(request: Request) {
  const cookie    = request.headers.get("cookie") || "";
  const userAgent = request.headers.get("user-agent") || "";
  const PAGES_ORIGIN = "https://gestionpro-admin.pages.dev";
  const tryFetch = async (origin: string) => {
    try {
      const r = await fetch(`${origin}/cdn-cgi/access/get-identity`, {
        headers: { cookie, "user-agent": userAgent },
      });
      if (!r.ok) return null;
      return await r.json();
    } catch { return null; }
  };
  const fromFixed = await tryFetch(PAGES_ORIGIN);
  if (fromFixed?.email) return fromFixed;
  const u = new URL(request.url);
  if (u.origin !== PAGES_ORIGIN) {
    const fromRequest = await tryFetch(u.origin);
    if (fromRequest?.email) return fromRequest;
  }
  return null;
}

async function hmacSha256Hex(secret: string, message: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}



