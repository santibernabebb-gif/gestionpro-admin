export const onRequest: PagesFunction = async (context) => {
  const { request, env } = context;

  // 1) Obtener identidad real desde Cloudflare Access usando la cookie del usuario
  const who = await fetchIdentityFromAccess(request);
  const email = (who?.email || "").toLowerCase();

  const allowed = "soporte.gestionproapp@gmail.com";
  if (email !== allowed) {
    return new Response("Unauthorized", { status: 401 });
  }

  // 2) Proxy hacia el Worker firmando la petición
  const url = new URL(request.url);

  // /api/admin/user -> /admin/user
  const targetPath = url.pathname.replace(/^\/api/, "");
  const targetUrl =
    "https://mi-api-presupuestos-v5.santibernabebb.workers.dev" +
    targetPath +
    url.search;

  const ts = Date.now().toString();
  const dataToSign = `${ts}:${email}:${request.method}:${targetPath}:${url.search}`;
  const sig = await hmacSha256Hex(env.ADMIN_PROXY_SECRET, dataToSign);

  const headers = new Headers(request.headers);
  headers.set("x-admin-email", email);
  headers.set("x-admin-ts", ts);
  headers.set("x-admin-sig", sig);

  // Limpieza
  headers.delete("host");
  headers.delete("content-length");

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

async function fetchIdentityFromAccess(request: Request) {
  // Reenviamos cookies para que Access pueda identificar al usuario
  const cookie = request.headers.get("cookie") || "";

  // Usamos el mismo host que está sirviendo Pages
  const u = new URL(request.url);
  const identityUrl = `${u.origin}/cdn-cgi/access/get-identity`;

  const r = await fetch(identityUrl, {
    headers: {
      cookie,
      // algunos navegadores/entornos agradecen pasar user-agent
      "user-agent": request.headers.get("user-agent") || "",
    },
  });

  if (!r.ok) return null;

  try {
    return await r.json(); // { email, name, ... }
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
