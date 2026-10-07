/**
 * PharmaPlus License Backend — SINGLE FILE VERSION
 * Paste this entire file into Cloudflare Worker editor
 *
 * Required Environment Variables (set in Worker Settings → Variables):
 *   ADMIN_EMAIL          = madevstudiox@gmail.com
 *   ADMIN_PASSWORD_HASH  = cafb4ee9a46034b7f7d21adf3ea17c1ad081b80077d456d9c97ea27b613fd1b5
 *   JWT_SECRET           = any-random-64-char-string
 *   CORS_ORIGIN          = https://pharma-plus-dashboard.vercel.app
 *
 * Required D1 Binding (set in Worker Settings → Bindings):
 *   Variable name: DB
 *   D1 database:   pharma-license-db
 */

// ── Utilities ─────────────────────────────────────────────────────────────────
const PUBLIC_PATHS = [
  '/api/license/verify',
  '/api/license/register',
  '/api/license/ping',
  '/api/license/trial-request',
  '/api/health',
];

function corsHeaders(env, requestPath) {
  // Public endpoints (called by desktop Electron app) always allow *
  const isPublic = PUBLIC_PATHS.some(p => requestPath?.startsWith(p));
  return {
    'Access-Control-Allow-Origin': isPublic ? '*' : (env?.CORS_ORIGIN || '*'),
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}
function withCors(response, env, requestPath) {
  const headers = new Headers(response.headers);
  Object.entries(corsHeaders(env, requestPath)).forEach(([k, v]) => headers.set(k, v));
  return new Response(response.body, { status: response.status, headers });
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}
function errorResponse(status, message) {
  return jsonResponse({ success: false, error: message }, status);
}
async function parseBody(request) {
  try { return await request.json(); } catch { return {}; }
}
async function sha256(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function defaultFeatures() {
  return { mobile_app: 1, cloud_backup: 1, reports: 1, purchases: 1, expenses: 1, returns_module: 1, suppliers: 1, multi_user: 1, lan_sync: 1 };
}

// ── JWT (no npm deps) ─────────────────────────────────────────────────────────
function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
async function getJwtKey(secret) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
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
    const key = await getJwtKey(secret);
    const sigBuf = Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ── Auth handlers ─────────────────────────────────────────────────────────────
async function handleAdminLogin(request, env) {
  const { email, password } = await parseBody(request);
  if (!email || !password) return errorResponse(400, 'Email and password required');
  const expectedEmail = env.ADMIN_EMAIL || 'madevstudiox@gmail.com';
  const passwordHash  = await sha256(password + 'pharmaplus_admin_salt');
  if (email.toLowerCase() !== expectedEmail.toLowerCase()) return errorResponse(401, 'Invalid credentials');
  if (passwordHash !== env.ADMIN_PASSWORD_HASH) return errorResponse(401, 'Invalid credentials');
  if (!env.JWT_SECRET) return errorResponse(500, 'JWT_SECRET not configured');
  const now = Math.floor(Date.now() / 1000);
  const token = await signJWT({ sub: email, role: 'admin', iat: now, exp: now + 28800 }, env.JWT_SECRET);
  const tokenHash = await sha256(token);
  await env.DB.prepare('INSERT INTO admin_sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)').bind(tokenHash, Date.now(), (now + 28800) * 1000).run();
  return jsonResponse({ success: true, token, expiresAt: (now + 28800) * 1000, adminEmail: email });
}
async function verifyAdminJWT(request, env) {
  const auth  = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token || !env.JWT_SECRET) return { valid: false };
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return { valid: false };
  const tokenHash = await sha256(token);
  const session = await env.DB.prepare('SELECT revoked FROM admin_sessions WHERE token_hash = ?').bind(tokenHash).first();
  if (session?.revoked) return { valid: false };
  return { valid: true, payload };
}

// ── License public handlers ───────────────────────────────────────────────────
async function handleVerify(request, env) {
  const { hwid, app_version } = await parseBody(request);
  if (!hwid || hwid.length < 8) return errorResponse(400, 'Invalid HWID');
  const machine = await env.DB.prepare('SELECT * FROM machines WHERE hwid = ?').bind(hwid).first();
  if (!machine) return jsonResponse({ authorized: false, reason: 'NOT_REGISTERED', features: defaultFeatures() });
  if (machine.status === 'revoked')  return jsonResponse({ authorized: false, reason: 'REVOKED', shop_name: machine.shop_name, features: defaultFeatures() });
  if (machine.status === 'inactive') return jsonResponse({ authorized: false, reason: 'INACTIVE', shop_name: machine.shop_name, features: defaultFeatures() });
  if (!machine.is_permanent && machine.license_expiry && Date.now() > machine.license_expiry) {
    await env.DB.prepare("UPDATE machines SET status='inactive' WHERE hwid=?").bind(hwid).run();
    return jsonResponse({ authorized: false, reason: 'EXPIRED', shop_name: machine.shop_name, expiry_date: machine.license_expiry, features: defaultFeatures() });
  }
  const featRow = await env.DB.prepare('SELECT * FROM machine_features WHERE hwid = ?').bind(hwid).first();
  const features = featRow ? { mobile_app: featRow.mobile_app, cloud_backup: featRow.cloud_backup, reports: featRow.reports, purchases: featRow.purchases, expenses: featRow.expenses, returns_module: featRow.returns_module, suppliers: featRow.suppliers, multi_user: featRow.multi_user, lan_sync: featRow.lan_sync } : defaultFeatures();
  await env.DB.prepare('UPDATE machines SET last_seen=?, open_count=open_count+1, app_version=? WHERE hwid=?').bind(Date.now(), app_version || '', hwid).run();
  return jsonResponse({ authorized: true, status: machine.status, shop_name: machine.shop_name, is_permanent: machine.is_permanent === 1, expiry_date: machine.license_expiry, features });
}
async function handleRegister(request, env) {
  const { hwid, shop_name, owner_name, phone, city, app_version } = await parseBody(request);
  if (!hwid || hwid.length < 8) return errorResponse(400, 'Invalid HWID');
  const existing = await env.DB.prepare('SELECT hwid, status FROM machines WHERE hwid = ?').bind(hwid).first();
  if (existing) return jsonResponse({ success: true, already_registered: true, status: existing.status });
  const now = Date.now();
  await env.DB.prepare("INSERT INTO machines (hwid,shop_name,owner_name,phone,city,status,created_at,last_seen,app_version) VALUES (?,?,?,?,?,'inactive',?,?,?)").bind(hwid, shop_name||'New Store', owner_name||'', phone||'', city||'', now, now, app_version||'').run();
  await env.DB.prepare("INSERT INTO machine_features (hwid,mobile_app,cloud_backup,reports,purchases,expenses,returns_module,suppliers,multi_user,lan_sync) VALUES (?,1,1,1,1,1,1,1,1,1)").bind(hwid).run();
  await env.DB.prepare("INSERT INTO license_logs (hwid,action,detail) VALUES (?,'registered',?)").bind(hwid, `New machine: ${shop_name||'Unknown'}`).run();
  return jsonResponse({ success: true, already_registered: false, status: 'inactive' });
}
async function handlePing(request, env) {
  const { hwid, app_version } = await parseBody(request);
  if (!hwid) return errorResponse(400, 'HWID required');
  await env.DB.prepare('UPDATE machines SET last_seen=?, app_version=COALESCE(?,app_version) WHERE hwid=?').bind(Date.now(), app_version||null, hwid).run();
  return jsonResponse({ success: true });
}

// ── Admin handlers ────────────────────────────────────────────────────────────
async function logAction(hwid, action, detail, env) {
  try { await env.DB.prepare("INSERT INTO license_logs (hwid,action,detail,performed_by) VALUES (?,?,?,'admin')").bind(hwid, action, detail).run(); } catch {}
}

async function listMachines(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const status = url.searchParams.get('status') || '';
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '100'), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0');
  let q = 'SELECT m.*, mf.mobile_app, mf.cloud_backup, mf.reports, mf.purchases, mf.expenses, mf.returns_module, mf.suppliers, mf.multi_user, mf.lan_sync FROM machines m LEFT JOIN machine_features mf ON m.hwid=mf.hwid WHERE 1=1';
  const p = [];
  if (search) { q += ' AND (m.shop_name LIKE ? OR m.hwid LIKE ? OR m.owner_name LIKE ? OR m.city LIKE ?)'; const s=`%${search}%`; p.push(s,s,s,s); }
  if (status) { q += ' AND m.status=?'; p.push(status); }
  q += ' ORDER BY m.created_at DESC LIMIT ? OFFSET ?'; p.push(limit, offset);
  const result = await env.DB.prepare(q).bind(...p).all();
  let cq = 'SELECT COUNT(*) as total FROM machines WHERE 1=1'; const cp = [];
  if (search) { cq += ' AND (shop_name LIKE ? OR hwid LIKE ? OR owner_name LIKE ? OR city LIKE ?)'; const s=`%${search}%`; cp.push(s,s,s,s); }
  if (status) { cq += ' AND status=?'; cp.push(status); }
  const count = await env.DB.prepare(cq).bind(...cp).first();
  return jsonResponse({ success: true, machines: result.results, total: count?.total||0, limit, offset });
}

async function getMachine(hwid, env) {
  const machine = await env.DB.prepare('SELECT m.*, mf.mobile_app, mf.cloud_backup, mf.reports, mf.purchases, mf.expenses, mf.returns_module, mf.suppliers, mf.multi_user, mf.lan_sync FROM machines m LEFT JOIN machine_features mf ON m.hwid=mf.hwid WHERE m.hwid=?').bind(hwid).first();
  if (!machine) return errorResponse(404, 'Machine not found');
  const logs = await env.DB.prepare('SELECT * FROM license_logs WHERE hwid=? ORDER BY created_at DESC LIMIT 20').bind(hwid).all();
  return jsonResponse({ success: true, machine, logs: logs.results });
}

async function authorizeMachine(hwid, request, env) {
  const { days } = await parseBody(request);
  const existing = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid=?').bind(hwid).first();
  if (!existing) return errorResponse(404, 'Machine not found');
  const permanent = (!days || days === 0) ? 1 : 0;
  const expiry    = permanent ? null : Date.now() + (parseInt(days) * 86400000);
  await env.DB.prepare('UPDATE machines SET status=?, license_expiry=?, is_permanent=? WHERE hwid=?').bind('active', expiry, permanent, hwid).run();
  const detail = permanent ? 'Permanent license granted' : `License authorized for ${days} days`;
  await logAction(hwid, 'authorized', detail, env);
  return jsonResponse({ success: true, message: detail, expiry_date: expiry, is_permanent: permanent===1 });
}

async function revokeMachine(hwid, env) {
  const existing = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid=?').bind(hwid).first();
  if (!existing) return errorResponse(404, 'Machine not found');
  await env.DB.prepare("UPDATE machines SET status='revoked', license_expiry=NULL, is_permanent=0 WHERE hwid=?").bind(hwid).run();
  await logAction(hwid, 'revoked', 'License revoked by admin', env);
  return jsonResponse({ success: true, message: 'License revoked' });
}

async function grantTrial(hwid, env) {
  const existing = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid=?').bind(hwid).first();
  if (!existing) return errorResponse(404, 'Machine not found');
  const expiry = Date.now() + (7 * 86400000);
  await env.DB.prepare("UPDATE machines SET status='trial', license_expiry=?, is_permanent=0 WHERE hwid=?").bind(expiry, hwid).run();
  await logAction(hwid, 'trial', '7-day trial granted', env);
  return jsonResponse({ success: true, message: '7-day trial granted', expiry_date: expiry });
}

async function updateFeatures(hwid, request, env) {
  const body = await parseBody(request);
  const existing = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid=?').bind(hwid).first();
  if (!existing) return errorResponse(404, 'Machine not found');
  await env.DB.prepare('INSERT INTO machine_features (hwid,mobile_app,cloud_backup,reports,purchases,expenses,returns_module,suppliers,multi_user,lan_sync) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(hwid) DO UPDATE SET mobile_app=excluded.mobile_app, cloud_backup=excluded.cloud_backup, reports=excluded.reports, purchases=excluded.purchases, expenses=excluded.expenses, returns_module=excluded.returns_module, suppliers=excluded.suppliers, multi_user=excluded.multi_user, lan_sync=excluded.lan_sync')
    .bind(hwid, body.mobile_app??1, body.cloud_backup??1, body.reports??1, body.purchases??1, body.expenses??1, body.returns_module??1, body.suppliers??1, body.multi_user??1, body.lan_sync??1).run();
  await logAction(hwid, 'feature_updated', `Features updated`, env);
  return jsonResponse({ success: true, message: 'Feature flags updated' });
}

async function updateMachine(hwid, request, env) {
  const { shop_name, owner_name, phone, city, notes } = await parseBody(request);
  await env.DB.prepare('UPDATE machines SET shop_name=COALESCE(?,shop_name), owner_name=COALESCE(?,owner_name), phone=COALESCE(?,phone), city=COALESCE(?,city), notes=COALESCE(?,notes) WHERE hwid=?')
    .bind(shop_name||null, owner_name||null, phone||null, city||null, notes??null, hwid).run();
  return jsonResponse({ success: true, message: 'Updated' });
}

async function deleteMachine(hwid, env) {
  await env.DB.prepare('DELETE FROM machines WHERE hwid=?').bind(hwid).run();
  return jsonResponse({ success: true, message: 'Deleted' });
}

async function getMachineLogs(hwid, env) {
  const logs = await env.DB.prepare('SELECT * FROM license_logs WHERE hwid=? ORDER BY created_at DESC LIMIT 50').bind(hwid).all();
  return jsonResponse({ success: true, logs: logs.results });
}

async function getStats(env) {
  const now = Date.now();
  const [total, active, trial, revoked, inactive, expiring, recentReg, recentActive, pendingTrials] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) as c FROM machines").first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status='active'").first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status='trial'").first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status='revoked'").first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status='inactive'").first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status='active' AND is_permanent=0 AND license_expiry IS NOT NULL AND license_expiry BETWEEN ? AND ?").bind(now, now+604800000).first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE created_at > ?").bind(now-604800000).first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE last_seen > ?").bind(now-86400000).first(),
    env.DB.prepare("SELECT COUNT(*) as c FROM trial_requests WHERE status='pending'").first().catch(()=>({c:0})),
  ]);
  return jsonResponse({ success: true, stats: { total: total?.c||0, active: active?.c||0, trial: trial?.c||0, revoked: revoked?.c||0, inactive: inactive?.c||0, expiring_soon: expiring?.c||0, recent_reg_7d: recentReg?.c||0, active_24h: recentActive?.c||0, pending_trial_requests: pendingTrials?.c||0 } });
}

// ── Trial Request handlers ────────────────────────────────────────────────────

async function handleTrialRequest(request, env) {
  const { hwid, phone, shop_name, owner_name, city, app_version } = await parseBody(request);
  if (!hwid || hwid.length < 8) return errorResponse(400, 'Invalid HWID');
  if (!phone || phone.trim().length < 7) return errorResponse(400, 'Valid phone number required');

  try {
    // Create trial_requests table if not exists (safe guard)
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS trial_requests (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid        TEXT NOT NULL,
        phone       TEXT NOT NULL,
        shop_name   TEXT DEFAULT '',
        app_version TEXT DEFAULT '',
        status      TEXT NOT NULL DEFAULT 'pending',
        created_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        resolved_at INTEGER
      )
    `).run();

    // Check if already has active/pending request
    const existing = await env.DB.prepare(
      "SELECT id, status FROM trial_requests WHERE hwid = ? ORDER BY created_at DESC LIMIT 1"
    ).bind(hwid).first();

    if (existing?.status === 'pending') {
      return jsonResponse({ success: true, already_pending: true, message: 'Request already submitted. Please wait for approval.' });
    }

    // Check if machine already has active license
    const machine = await env.DB.prepare('SELECT status FROM machines WHERE hwid = ?').bind(hwid).first();
    if (machine?.status === 'active' || machine?.status === 'trial') {
      return jsonResponse({ success: false, error: 'This machine already has an active license.' });
    }

    // Insert request
    await env.DB.prepare(
      "INSERT INTO trial_requests (hwid, phone, shop_name, app_version) VALUES (?, ?, ?, ?)"
    ).bind(hwid, phone.trim(), shop_name || 'Unknown Store', app_version || '').run();

    // Also register/update machine record
    const machineExists = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid = ?').bind(hwid).first();
    if (!machineExists) {
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO machines (hwid, shop_name, owner_name, phone, city, status, created_at, last_seen) VALUES (?,?,?,?,?,'inactive',?,?)"
      ).bind(hwid, shop_name||'Unknown Store', owner_name||'', phone.trim(), city||'', now, now).run();
      await env.DB.prepare(
        "INSERT INTO machine_features (hwid,mobile_app,cloud_backup,reports,purchases,expenses,returns_module,suppliers,multi_user,lan_sync) VALUES (?,1,1,1,1,1,1,1,1,1)"
      ).bind(hwid).run();
    } else {
      await env.DB.prepare(
        "UPDATE machines SET phone=?, shop_name=COALESCE(NULLIF(?,''),shop_name), owner_name=COALESCE(NULLIF(?,''),owner_name), city=COALESCE(NULLIF(?,''),city) WHERE hwid=?"
      ).bind(phone.trim(), shop_name||'', owner_name||'', city||'', hwid).run();
    }

    return jsonResponse({ success: true, already_pending: false, message: 'Trial request submitted successfully. You will be notified.' });

  } catch (err) {
    console.error('trial-request error:', err);
    return errorResponse(500, err.message);
  }
}

async function listTrialRequests(request, env) {
  try {
    const url    = new URL(request.url);
    const status = url.searchParams.get('status') || 'pending';

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS trial_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, hwid TEXT NOT NULL, phone TEXT NOT NULL,
        shop_name TEXT DEFAULT '', app_version TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000), resolved_at INTEGER
      )
    `).run();

    const q = status === 'all'
      ? "SELECT tr.*, m.city, m.owner_name FROM trial_requests tr LEFT JOIN machines m ON tr.hwid=m.hwid ORDER BY tr.created_at DESC LIMIT 50"
      : "SELECT tr.*, m.city, m.owner_name FROM trial_requests tr LEFT JOIN machines m ON tr.hwid=m.hwid WHERE tr.status=? ORDER BY tr.created_at DESC LIMIT 50";

    const rows = status === 'all'
      ? await env.DB.prepare(q).all()
      : await env.DB.prepare(q).bind(status).all();

    return jsonResponse({ success: true, requests: rows.results });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

async function handleTrialAction(id, action, env) {
  try {
    const req = await env.DB.prepare('SELECT * FROM trial_requests WHERE id = ?').bind(parseInt(id)).first();
    if (!req) return errorResponse(404, 'Request not found');

    if (action === 'approve') {
      // Grant 7-day trial to machine
      const expiry = Date.now() + (7 * 86400000);

      const machineExists = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid = ?').bind(req.hwid).first();
      if (machineExists) {
        await env.DB.prepare("UPDATE machines SET status='trial', license_expiry=?, is_permanent=0, phone=? WHERE hwid=?")
          .bind(expiry, req.phone, req.hwid).run();
      } else {
        const now = Date.now();
        await env.DB.prepare("INSERT INTO machines (hwid, shop_name, phone, status, license_expiry, is_permanent, created_at, last_seen) VALUES (?,?,?,'trial',?,0,?,?)")
          .bind(req.hwid, req.shop_name, req.phone, expiry, now, now).run();
        await env.DB.prepare("INSERT INTO machine_features (hwid) VALUES (?)").bind(req.hwid).run();
      }

      await env.DB.prepare("UPDATE trial_requests SET status='approved', resolved_at=? WHERE id=?")
        .bind(Date.now(), parseInt(id)).run();
      await env.DB.prepare("INSERT INTO license_logs (hwid, action, detail) VALUES (?,'trial','7-day trial approved via request. Phone: '||?)")
        .bind(req.hwid, req.phone).run();

      return jsonResponse({ success: true, message: 'Trial approved. Machine will unlock on next app startup.' });

    } else if (action === 'reject') {
      await env.DB.prepare("UPDATE trial_requests SET status='rejected', resolved_at=? WHERE id=?")
        .bind(Date.now(), parseInt(id)).run();
      return jsonResponse({ success: true, message: 'Request rejected.' });
    }

    return errorResponse(400, 'Invalid action');
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── Main Router ───────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(env, path) });
    const method = request.method;

    try {
      // Public routes — always CORS *
      if (path === '/api/license/verify'        && method === 'POST') return withCors(await handleVerify(request, env), env, path);
      if (path === '/api/license/register'      && method === 'POST') return withCors(await handleRegister(request, env), env, path);
      if (path === '/api/license/ping'          && method === 'POST') return withCors(await handlePing(request, env), env, path);
      if (path === '/api/license/trial-request' && method === 'POST') return withCors(await handleTrialRequest(request, env), env, path);
      if (path === '/api/health')                                      return withCors(jsonResponse({ status: 'ok', service: 'pharma-license-api', ts: Date.now() }), env, path);

      // Admin login
      if (path === '/api/admin/login' && method === 'POST') return withCors(await handleAdminLogin(request, env), env);

      // Protected admin routes
      if (path.startsWith('/api/admin/')) {
        const auth = await verifyAdminJWT(request, env);
        if (!auth.valid) return withCors(errorResponse(401, 'Unauthorized'), env);

        if (path === '/api/admin/stats' && method === 'GET') return withCors(await getStats(env), env);
        if (path === '/api/admin/machines' && method === 'GET') return withCors(await listMachines(request, env), env);

        // Trial requests
        if (path === '/api/admin/trial-requests' && method === 'GET')  return withCors(await listTrialRequests(request, env), env);
        const trialMatch = path.match(/^\/api\/admin\/trial-requests\/(\d+)\/(approve|reject)$/);
        if (trialMatch && method === 'POST') return withCors(await handleTrialAction(trialMatch[1], trialMatch[2], env), env);

        const m = path.match(/^\/api\/admin\/machines\/([^/]+)(\/.*)?$/);
        if (m) {
          const hwid = decodeURIComponent(m[1]);
          const sub  = m[2] || '';
          if (sub===''          && method==='GET')    return withCors(await getMachine(hwid, env), env);
          if (sub===''          && method==='PUT')    return withCors(await updateMachine(hwid, request, env), env);
          if (sub===''          && method==='DELETE') return withCors(await deleteMachine(hwid, env), env);
          if (sub==='/authorize'&& method==='POST')   return withCors(await authorizeMachine(hwid, request, env), env);
          if (sub==='/revoke'   && method==='POST')   return withCors(await revokeMachine(hwid, env), env);
          if (sub==='/trial'    && method==='POST')   return withCors(await grantTrial(hwid, env), env);
          if (sub==='/features' && method==='PUT')    return withCors(await updateFeatures(hwid, request, env), env);
          if (sub==='/logs'     && method==='GET')    return withCors(await getMachineLogs(hwid, env), env);
        }
        return withCors(errorResponse(404, 'Not found'), env);
      }

      return withCors(errorResponse(404, 'Not found'), env);
    } catch (err) {
      console.error('Error:', err);
      return withCors(errorResponse(500, 'Internal error: ' + err.message), env);
    }
  }
};
