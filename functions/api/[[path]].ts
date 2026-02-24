export const onRequest: PagesFunction = async (context) => {
  const { request, env } = context;

  // 1) Identidad real desde Cloudflare Access usando la cookie del usuario
  const who = await fetchIdentityFromAccess(request);
  const email = (who?.email || "").toLowerCase();

  const allowed = "soporte.gestionproapp@gmail.com";
  if (email !== allowed) {
    return new Response("Unauthorized", { status: 401 });
  }

  // 2) Proxy firmado hacia el Worker
  const u = new URL(request.url);
  const targetPath = u.pathname.replace(/^\/api/, "");
  const targetUrl =
    "https://mi-api-presupuestos-v5.santibernabebb.workers.dev" +
    targetPath +
    u.search;

  const ts = Date.now().toString();
  const dataToSign = `${ts}:${email}:${request.method}:${targetPath}:${u.search}`;
  const sig = await hmacSha256Hex(env.ADMIN_PROXY_SECRET, dataToSign);

  const headers = new Headers(request.headers);
  headers.set("x-admin-email", email);
  headers.set("x-admin-ts", ts);
  headers.set("x-admin-sig", sig);
  headers.delete("host");
  headers.delete("content-length");

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
