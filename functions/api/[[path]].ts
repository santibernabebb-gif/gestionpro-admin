export const onRequest: PagesFunction = async (context) => {
  const { request, env } = context;

  const who = await fetchIdentityFromAccess(request);
  const email = (who?.email || "").toLowerCase();
  const allowed = "soporte.gestionproapp@gmail.com";
  if (email !== allowed) {
    return new Response("Unauthorized", { status: 401 });
  }

  const u = new URL(request.url);
  const incomingPath = u.pathname.replace(/^\/api/, "");

  const routeTable: Record<string, { methods: Set<string>; worker: "gestionpro" | "activate"; targetPath: string }> = {
    "/admin/user": { methods: new Set(["GET"]), worker: "gestionpro", targetPath: "/admin/user" },
    "/admin/add-credits": { methods: new Set(["POST"]), worker: "gestionpro", targetPath: "/admin/add-credits" },
    "/admin/reconcile": { methods: new Set(["POST"]), worker: "gestionpro", targetPath: "/admin/reconcile" },
    "/admin/reset-user": { methods: new Set(["POST"]), worker: "gestionpro", targetPath: "/admin/reset-user" },
    "/admin/purchasers": { methods: new Set(["GET"]), worker: "gestionpro", targetPath: "/admin/purchasers" },
    "/admin/api-logs": { methods: new Set(["GET"]), worker: "gestionpro", targetPath: "/admin/api-logs" },

    "/activate/user": { methods: new Set(["GET"]), worker: "activate", targetPath: "/admin/user" },
    "/activate/add-tokens": { methods: new Set(["POST"]), worker: "activate", targetPath: "/admin/add-tokens" },
    "/activate/reconcile": { methods: new Set(["POST"]), worker: "activate", targetPath: "/admin/reconcile" },
    "/activate/reset-user": { methods: new Set(["POST"]), worker: "activate", targetPath: "/admin/reset-user" },
    "/activate/purchasers": { methods: new Set(["GET"]), worker: "activate", targetPath: "/admin/purchasers" },
    "/activate/api-logs": { methods: new Set(["GET"]), worker: "activate", targetPath: "/admin/api-logs" },
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

