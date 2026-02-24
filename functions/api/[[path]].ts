export const onRequest: PagesFunction = async (context) => {
  const { request, env } = context;

  // Access headers (Pages Functions los ve porque es el origin)
  const email =
    request.headers.get("cf-access-authenticated-user-email") ||
    request.headers.get("Cf-Access-Authenticated-User-Email") ||
    "";

  const allowed = "soporte.gestionproapp@gmail.com";
  if (email.toLowerCase() !== allowed) {
    return new Response("Unauthorized", { status: 401 });
  }

  // Reescritura: /api/admin/user -> /admin/user
  const url = new URL(request.url);
  const targetPath = url.pathname.replace(/^\/api/, "");
  const targetUrl =
    "https://mi-api-presupuestos-v5.santibernabebb.workers.dev" +
    targetPath +
    url.search;

  // Firma HMAC
  const ts = Date.now().toString();
  const dataToSign = `${ts}:${email}:${request.method}:${targetPath}:${url.search}`;
  const sig = await hmacSha256Hex(env.ADMIN_PROXY_SECRET, dataToSign);

  const headers = new Headers(request.headers);
  headers.set("x-admin-email", email);
  headers.set("x-admin-ts", ts);
  headers.set("x-admin-sig", sig);
  headers.delete("host");

  const body =
    request.method === "GET" || request.method === "HEAD"
      ? undefined
      : await request.arrayBuffer();

  return fetch(targetUrl, {
    method: request.method,
    headers,
    body,
  });
};

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
