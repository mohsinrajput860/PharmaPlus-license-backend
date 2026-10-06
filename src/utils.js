/**
 * Shared utilities: CORS headers, response helpers
 */

export function corsHeaders(env) {
  const origin = env?.CORS_ORIGIN || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

export function withCors(response, env) {
  const headers = new Headers(response.headers);
  const ch = corsHeaders(env);
  Object.entries(ch).forEach(([k, v]) => headers.set(k, v));
  return new Response(response.body, {
    status: response.status,
    headers,
  });
}

export function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function errorResponse(status, message) {
  return jsonResponse({ success: false, error: message }, status);
}

/** Parse JSON body safely */
export async function parseBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

/** Simple SHA-256 hex digest */
export async function sha256(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Default feature flags object */
export function defaultFeatures() {
  return {
    mobile_app:     1,
    cloud_backup:   1,
    reports:        1,
    purchases:      1,
    expenses:       1,
    returns_module: 1,
    suppliers:      1,
    multi_user:     1,
    lan_sync:       1,
  };
}
