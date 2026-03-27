export const onRequest: PagesFunction = async (context) => {
  const { request, env } = context; 

  // 1) Identidad real desde Cloudflare Access usando la cookie
  const who = await fetchIdentityFromAccess(request);
  const email = (who?.email || "").toLowerCase();

  const allowed = "soporte.gestionproapp@gmail.com";
  if (email !== allowed) {
    return new Response("Unauthorized", { status: 401 });
  }

  // 2) Allowlist estricta de rutas / métodos
  const u = new URL(request.url);
  const targetPath = u.pathname.replace(/^\/api/, "");

  const allowedRoutes: Record<string, Set<string>> = {
    "/admin/user": new Set(["GET"]),
    "/admin/add-credits": new Set(["POST"]),
    "/admin/reconcile": new Set(["POST"]),
    "/admin/reset-user": new Set(["POST"]),
    "/admin/purchasers": new Set(["GET"]),
    "/admin/api-logs": new Set(["GET"]),
    "/admin/history": new Set(["GET", "POST"]),
  };

  const allowedMethods = allowedRoutes[targetPath];
  if (!allowedMethods || !allowedMethods.has(request.method)) {
    return new Response("Not Found", { status: 404 });
  }

  // 3) Historial local — se gestiona directo en Pages (D1 binding) sin pasar por el Worker
  if (targetPath === "/admin/history") {
    const db = (env as any)["gestionpro-db"];
    if (!db) return new Response(JSON.stringify({ ok: false, error: "D1_BINDING_MISSING" }), { status: 500, headers: { "Content-Type": "application/json" } });

    if (request.method === "GET") {
      const rows = await db.prepare(
        "SELECT query, searched_at FROM admin_history ORDER BY searched_at DESC LIMIT 100"
      ).all();
      return new Response(JSON.stringify({ ok: true, items: rows.results || [] }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    if (request.method === "POST") {
      const body = await request.json() as { query?: string; alias?: string; updateAlias?: boolean };
      const q = String(body?.query || "").trim().slice(0, 200);
      const alias = String(body?.alias || "").trim().slice(0, 100);
      if (!q) return new Response(JSON.stringify({ ok: false, error: "MISSING_QUERY" }), { status: 400, headers: { "Content-Type": "application/json" } });

      // Si solo actualiza el alias sin cambiar la búsqueda
      if (body?.updateAlias) {
        await db.prepare("UPDATE admin_history SET alias = ? WHERE query = ?").bind(alias, q).run();
        return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
      }

      // Guardar búsqueda — si ya existe conserva el alias que tenía
      const existing = await db.prepare("SELECT alias FROM admin_history WHERE query = ?").bind(q).first() as { alias?: string } | null;
      const keepAlias = existing?.alias || alias;
      await db.prepare("DELETE FROM admin_history WHERE query = ?").bind(q).run();
      await db.prepare("INSERT INTO admin_history (query, alias, searched_at) VALUES (?, ?, datetime('now'))").bind(q, keepAlias).run();
      // Mantener solo los últimos 100
      await db.prepare(
        "DELETE FROM admin_history WHERE id NOT IN (SELECT id FROM admin_history ORDER BY searched_at DESC LIMIT 100)"
      ).run();
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    }
  }

  // 4) Proxy firmado hacia el Worker
  const targetUrl =
    "https://mi-api-presupuestos-v5.santibernabebb.workers.dev" +
    targetPath +
    u.search;

  const ts = Date.now().toString();
  const dataToSign = `${ts}:${email}:${request.method}:${targetPath}:${u.search}`;
  const sig = await hmacSha256Hex(env.ADMIN_PROXY_SECRET, dataToSign);

  // Reenviamos solo headers seguros (evita inyección desde el cliente)
  const headers = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const accept = request.headers.get("accept");
  if (accept) headers.set("accept", accept);

  headers.set("x-admin-email", email);
  headers.set("x-admin-ts", ts);
  headers.set("x-admin-sig", sig);

  const body =
    request.method === "GET" || request.method === "HEAD"
      ? undefined
      : await request.arrayBuffer();

  return fetch(targetUrl, { method: request.method, headers, body });
};

async function fetchIdentityFromAccess(request: Request) {
  const cookie = request.headers.get("cookie") || "";
  const u = new URL(request.url);
  const identityUrl = `${u.origin}/cdn-cgi/access/get-identity`;

  const r = await fetch(identityUrl, {
    headers: {
      cookie,
      "user-agent": request.headers.get("user-agent") || "",
    },
  });

  if (!r.ok) return null;
  try {
    return await r.json();
  } catch {
    return null;
  }
}

async function hmacSha256Hex(secret: string, message: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

