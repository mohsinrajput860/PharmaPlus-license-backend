/**
 * Admin Authentication
 * — Simple email+password login -> JWT (HS256 via Web Crypto)
 * — JWT verify on every protected route
 */

import { sha256, jsonResponse, errorResponse, parseBody } from './utils.js';

const JWT_EXPIRY_SECONDS = 60 * 60 * 8; // 8 hours

// ── Minimal JWT implementation using Web Crypto (no npm deps needed) ─────────

function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getJwtKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign', 'verify']
  );
}

async function signJWT(payload, secret) {
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body   = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const msg    = `${header}.${body}`;
  const key    = await getJwtKey(secret);
  const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return `${msg}.${base64url(sig)}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const msg = `${header}.${body}`;
    const key = await getJwtKey(secret);

    // Decode base64url signature
    const sigBuf = Uint8Array.from(
      atob(sig.replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(msg));
    if (!valid) return null;

    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null; // expired
    return payload;
  } catch {
    return null;
  }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

export async function handleAdminLogin(request, env) {
  const body = await parseBody(request);
  const { email, password } = body;

  if (!email || !password) {
    return errorResponse(400, 'Email and password required');
  }

  // Check credentials
  const expectedEmail = env.ADMIN_EMAIL || 'madevstudiox@gmail.com';
  const passwordHash  = await sha256(password + 'pharmaplus_admin_salt');

  if (email.toLowerCase() !== expectedEmail.toLowerCase()) {
    return errorResponse(401, 'Invalid credentials');
  }

  if (passwordHash !== env.ADMIN_PASSWORD_HASH) {
    return errorResponse(401, 'Invalid credentials');
  }

  const secret = env.JWT_SECRET;
  if (!secret) return errorResponse(500, 'JWT_SECRET not configured');

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: email,
    role: 'admin',
    iat: now,
    exp: now + JWT_EXPIRY_SECONDS,
  };

  const token = await signJWT(payload, secret);

  // Store token hash in DB for revocation support
  const tokenHash = await sha256(token);
  await env.DB.prepare(
    'INSERT INTO admin_sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)'
  ).bind(tokenHash, Date.now(), (now + JWT_EXPIRY_SECONDS) * 1000).run();

  return jsonResponse({
    success: true,
    token,
    expiresAt: (now + JWT_EXPIRY_SECONDS) * 1000,
    adminEmail: email,
  });
}

export async function verifyAdminJWT(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';

  if (!token) return { valid: false };

  const secret = env.JWT_SECRET;
  if (!secret) return { valid: false };

  const payload = await verifyJWT(token, secret);
  if (!payload) return { valid: false };

  // Check DB revocation
  const tokenHash = await sha256(token);
  const session = await env.DB.prepare(
    'SELECT revoked FROM admin_sessions WHERE token_hash = ?'
  ).bind(tokenHash).first();

  if (session?.revoked) return { valid: false };

  return { valid: true, payload };
}
