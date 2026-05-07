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

  // Permitir todas las rutas /admin/* — el worker tiene su propia autenticación
  if (!targetPath.startsWith("/admin/")) {
    return new Response("Not Found", { status: 404 });
  }

  // 3) Historial local — se gestiona directo en Pages (D1 binding) sin pasar por el Worker
  if (targetPath === "/admin/history") {
    const db = (env as any)["gestionpro-db"];
    if (!db) {
      return new Response(JSON.stringify({ ok: false, error: "D1_BINDING_MISSING" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (request.method === "GET") {
      const rows = await db.prepare(
        "SELECT query, alias, searched_at FROM admin_history ORDER BY searched_at DESC LIMIT 100"
      ).all();
      return new Response(JSON.stringify({ ok: true, items: rows.results || [] }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (request.method === "POST") {
      const body = await request.json() as { query?: string; alias?: string; updateAlias?: boolean };
      const q = String(body?.query || "").trim().slice(0, 200);
      const alias = String(body?.alias || "").trim().slice(0, 100);
      if (!q) {
        return new Response(JSON.stringify({ ok: false, error: "MISSING_QUERY" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Si solo actualiza el alias sin cambiar la búsqueda
      if (body?.updateAlias) {
        await db.prepare("UPDATE admin_history SET alias = ? WHERE query = ?").bind(alias, q).run();
        return new Response(JSON.stringify({ ok: true }), {
          headers: { "Content-Type": "application/json" },
        });
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
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }
  }


  // 3b) Actividad de usuarios — lectura directa desde D1 para el panel admin
  if (targetPath === "/admin/activity-summary") {
    const db = (env as any)["gestionpro-db"];
    if (!db) {
      return new Response(JSON.stringify({ ok: false, error: "D1_BINDING_MISSING" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405 });

    try {
      const byEvent = await db.prepare(
        `SELECT event_type,
                COUNT(*) AS total,
                COUNT(DISTINCT COALESCE(user_id, device_id, email, id)) AS unique_actors
         FROM user_events
         GROUP BY event_type
         ORDER BY total DESC`
      ).all();

      const totalsRow = await db.prepare(
        `SELECT
          (SELECT COUNT(*) FROM users) AS users,
          (SELECT COUNT(DISTINCT COALESCE(user_id, device_id, email)) FROM user_events WHERE event_type = 'LOGIN_OK') AS usersWithLogin,
          (SELECT COUNT(DISTINCT COALESCE(user_id, device_id, email)) FROM user_events WHERE event_type = 'IA_USED') AS usersWithIa,
          (SELECT COUNT(DISTINCT COALESCE(user_id, device_id, email)) FROM user_events WHERE event_type = 'PDF_UPLOAD_OK') AS usersWithPdfOk,
          (SELECT COUNT(*) FROM user_events WHERE event_type = 'PRESUPUESTO_SAVED') AS presupuestosSaved,
          (SELECT COUNT(*) FROM user_events WHERE event_type = 'FACTURA_SAVED') AS facturasSaved,
          (SELECT COUNT(*) FROM user_events WHERE event_type = 'PDF_UPLOAD_ERROR') AS pdfUploadErrors,
          (SELECT COUNT(*) FROM user_events WHERE created_at >= datetime('now','-24 hours')) AS eventsLast24h`
      ).first();

      return new Response(JSON.stringify({ ok: true, totals: totalsRow || {}, byEvent: byEvent.results || [] }), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (e: any) {
      return new Response(JSON.stringify({ ok: false, error: "ACTIVITY_QUERY_FAILED", detail: String(e?.message || e) }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  if (targetPath === "/admin/user-events") {
    const db = (env as any)["gestionpro-db"];
    if (!db) {
      return new Response(JSON.stringify({ ok: false, error: "D1_BINDING_MISSING" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405 });

    const limitRaw = parseInt(u.searchParams.get("limit") || "100", 10);
    const limit = Math.max(1, Math.min(500, Number.isFinite(limitRaw) ? limitRaw : 100));
    const eventType = (u.searchParams.get("eventType") || "").trim();
    const emailFilter = (u.searchParams.get("email") || "").trim().toLowerCase();
    const deviceId = (u.searchParams.get("deviceId") || "").trim();
    const userId = (u.searchParams.get("userId") || "").trim();

    const where: string[] = [];
    const params: any[] = [];

    if (eventType) { where.push("event_type = ?"); params.push(eventType); }
    if (emailFilter) { where.push("LOWER(COALESCE(email,'')) LIKE ?"); params.push(`%${emailFilter}%`); }
    if (deviceId) { where.push("device_id = ?"); params.push(deviceId); }
    if (userId) { where.push("user_id = ?"); params.push(userId); }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    try {
      const rows = await db.prepare(
        `SELECT id, user_id, device_id, email, event_type, entity_type, entity_id, details, created_at
         FROM user_events
         ${whereSql}
         ORDER BY created_at DESC
         LIMIT ?`
      ).bind(...params, limit).all();

      return new Response(JSON.stringify({ ok: true, events: rows.results || [] }), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (e: any) {
      return new Response(JSON.stringify({ ok: false, error: "USER_EVENTS_QUERY_FAILED", detail: String(e?.message || e) }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  // 4) Proxy firmado hacia el Worker, con selector de entorno
  const envParam = (u.searchParams.get("env") || "prod").toLowerCase();

  const WORKER_BASE_URL_PROD =
    ((env as any).WORKER_BASE_URL_PROD as string | undefined) ||
    "https://mi-api-presupuestos-v5.santibernabebb.workers.dev";

  const WORKER_BASE_URL_TEST =
    ((env as any).WORKER_BASE_URL_TEST as string | undefined) ||
    "https://verifactugestionpro.santibernabebb.workers.dev";

  const baseUrl = envParam === "test" ? WORKER_BASE_URL_TEST : WORKER_BASE_URL_PROD;
  const targetUrl = baseUrl + targetPath + u.search;

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
