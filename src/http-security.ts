// HTTP & WebSocket Security Utilities per AGENTS.md Sections 63 & 64

export const CSRF_COOKIE = '__Host-edgejump_csrf';

export function readCookie(request: Request, name: string): string | null {
  const cookies = request.headers.get('Cookie')?.split(';') ?? [];
  return cookies.map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(`${name}=`))?.slice(name.length + 1) ?? null;
}

export function issueCsrfToken(request: Request): Response {
  const existing = readCookie(request, CSRF_COOKIE);
  const token = existing && /^[a-f0-9]{64}$/.test(existing) ? existing :
    Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, '0')).join('');
  return jsonResponse({ csrfToken: token }, 200, {
    'Set-Cookie': `${CSRF_COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict`,
  });
}

export function validateCsrfToken(request: Request): boolean {
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method.toUpperCase())) return true;
  const cookie = readCookie(request, CSRF_COOKIE);
  const header = request.headers.get('X-CSRF-Token');
  if (!cookie || !header || !/^[a-f0-9]{64}$/.test(cookie) || header.length !== cookie.length) return false;
  let mismatch = 0;
  for (let index = 0; index < cookie.length; index++) mismatch |= cookie.charCodeAt(index) ^ header.charCodeAt(index);
  return mismatch === 0;
}

export function isProductionHttp(request: Request): boolean {
  const proto = request.headers.get('X-Forwarded-Proto')?.toLowerCase();
  return proto === 'http';
}

export function httpsRedirect(request: Request): Response {
  const url = new URL(request.url);
  url.protocol = 'https:';
  return Response.redirect(url.toString(), 301);
}

export function hasValidWebSocketOrigin(request: Request): boolean {
  const origin = request.headers.get('Origin');
  if (!origin) return false;
  try {
    const originUrl = new URL(origin);
    const requestUrl = new URL(request.url);
    return originUrl.origin === requestUrl.origin;
  } catch {
    return false;
  }
}

export function validateCsrfOrigin(request: Request): boolean {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  // Safe methods do not mutate state
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return true;

  const origin = request.headers.get('Origin');
  if (!origin) {
    // If no Origin, verify Sec-Fetch-Site is same-origin
    const fetchSite = request.headers.get('Sec-Fetch-Site');
    if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
      return false;
    }
    // Block cross-site if neither Origin nor valid fetch site is present
    return false;
  }

  try {
    const originUrl = new URL(origin);
    return originUrl.origin === url.origin;
  } catch {
    return false;
  }
}

export function secureHeaders(response: Response): Response {
  if (response.status === 101) return response;
  const headers = new Headers(response.headers);

  // Security Headers per Section 64
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: https:; frame-ancestors 'none';"
  );

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  const allHeaders: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    ...headers,
  };
  return secureHeaders(new Response(JSON.stringify(data), { status, headers: allHeaders }));
}

export function jsonError(message: string, status = 400, details?: unknown): Response {
  return jsonResponse({ error: message, details }, status);
}
