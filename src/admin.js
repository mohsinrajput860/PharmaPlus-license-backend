/**
 * Admin API Handlers — all require JWT auth (enforced in index.js)
 */

import { jsonResponse, errorResponse, parseBody, defaultFeatures } from './utils.js';

// ── GET /api/admin/machines ───────────────────────────────────────────────────
export async function listMachines(request, env) {
  try {
    const url    = new URL(request.url);
    const search = url.searchParams.get('search') || '';
    const status = url.searchParams.get('status') || '';
    const limit  = Math.min(parseInt(url.searchParams.get('limit') || '100'), 200);
    const offset = parseInt(url.searchParams.get('offset') || '0');

    let query = `
      SELECT m.*, mf.mobile_app, mf.cloud_backup, mf.reports, mf.purchases,
             mf.expenses, mf.returns_module, mf.suppliers, mf.multi_user, mf.lan_sync
      FROM machines m
      LEFT JOIN machine_features mf ON m.hwid = mf.hwid
      WHERE 1=1
    `;
    const params = [];

    if (search) {
      query += ` AND (m.shop_name LIKE ? OR m.hwid LIKE ? OR m.owner_name LIKE ? OR m.city LIKE ?)`;
      const s = `%${search}%`;
      params.push(s, s, s, s);
    }
    if (status) {
      query += ` AND m.status = ?`;
      params.push(status);
    }

    query += ` ORDER BY m.created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await env.DB.prepare(query).bind(...params).all();

    // Count total
    let countQ = 'SELECT COUNT(*) as total FROM machines WHERE 1=1';
    const countP = [];
    if (search) {
      countQ += ` AND (shop_name LIKE ? OR hwid LIKE ? OR owner_name LIKE ? OR city LIKE ?)`;
      const s = `%${search}%`;
      countP.push(s, s, s, s);
    }
    if (status) { countQ += ' AND status = ?'; countP.push(status); }
    const countResult = await env.DB.prepare(countQ).bind(...countP).first();

    return jsonResponse({
      success: true,
      machines: result.results,
      total: countResult?.total || 0,
      limit, offset,
    });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── GET /api/admin/machines/:hwid ─────────────────────────────────────────────
export async function getMachine(hwid, env) {
  try {
    const machine = await env.DB.prepare(
      `SELECT m.*, mf.mobile_app, mf.cloud_backup, mf.reports, mf.purchases,
              mf.expenses, mf.returns_module, mf.suppliers, mf.multi_user, mf.lan_sync
       FROM machines m
       LEFT JOIN machine_features mf ON m.hwid = mf.hwid
       WHERE m.hwid = ?`
    ).bind(hwid).first();

    if (!machine) return errorResponse(404, 'Machine not found');

    const logs = await env.DB.prepare(
      'SELECT * FROM license_logs WHERE hwid = ? ORDER BY created_at DESC LIMIT 20'
    ).bind(hwid).all();

    return jsonResponse({ success: true, machine, logs: logs.results });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── PUT /api/admin/machines/:hwid ─────────────────────────────────────────────
export async function updateMachine(hwid, request, env) {
  try {
    const body = await parseBody(request);
    const { shop_name, owner_name, phone, city, notes } = body;

    await env.DB.prepare(
      `UPDATE machines SET
        shop_name  = COALESCE(?, shop_name),
        owner_name = COALESCE(?, owner_name),
        phone      = COALESCE(?, phone),
        city       = COALESCE(?, city),
        notes      = COALESCE(?, notes)
       WHERE hwid = ?`
    ).bind(shop_name || null, owner_name || null, phone || null, city || null, notes ?? null, hwid).run();

    return jsonResponse({ success: true, message: 'Machine info updated' });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── DELETE /api/admin/machines/:hwid ─────────────────────────────────────────
export async function deleteMachine(hwid, env) {
  try {
    await env.DB.prepare('DELETE FROM machines WHERE hwid = ?').bind(hwid).run();
    return jsonResponse({ success: true, message: 'Machine deleted' });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── POST /api/admin/machines/:hwid/authorize ──────────────────────────────────
export async function authorizeMachine(hwid, request, env) {
  try {
    const body = await parseBody(request);
    const { days } = body; // null/0 = permanent, number = days from now

    let expiry     = null;
    let permanent  = 0;
    let status     = 'active';

    if (!days || days === 0) {
      permanent = 1;
      expiry    = null;
    } else {
      expiry = Date.now() + (parseInt(days) * 24 * 60 * 60 * 1000);
    }

    const existing = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid = ?').bind(hwid).first();
    if (!existing) return errorResponse(404, 'Machine not found');

    await env.DB.prepare(
      `UPDATE machines SET status = ?, license_expiry = ?, is_permanent = ? WHERE hwid = ?`
    ).bind(status, expiry, permanent, hwid).run();

    const detail = permanent
      ? 'Permanent license granted'
      : `License authorized for ${days} days (expires: ${new Date(expiry).toLocaleDateString('en-PK')})`;

    await logAction(hwid, 'authorized', detail, env);

    return jsonResponse({
      success: true,
      message: detail,
      expiry_date: expiry,
      is_permanent: permanent === 1,
    });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── POST /api/admin/machines/:hwid/revoke ─────────────────────────────────────
export async function revokeMachine(hwid, env) {
  try {
    const existing = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid = ?').bind(hwid).first();
    if (!existing) return errorResponse(404, 'Machine not found');

    await env.DB.prepare(
      "UPDATE machines SET status = 'revoked', license_expiry = NULL, is_permanent = 0 WHERE hwid = ?"
    ).bind(hwid).run();

    await logAction(hwid, 'revoked', 'License revoked by admin', env);

    return jsonResponse({ success: true, message: 'License revoked. App will lock on next check.' });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── POST /api/admin/machines/:hwid/trial ──────────────────────────────────────
export async function grantTrial(hwid, env) {
  try {
    const existing = await env.DB.prepare('SELECT hwid, status FROM machines WHERE hwid = ?').bind(hwid).first();
    if (!existing) return errorResponse(404, 'Machine not found');

    const expiry = Date.now() + (7 * 24 * 60 * 60 * 1000);

    await env.DB.prepare(
      "UPDATE machines SET status = 'trial', license_expiry = ?, is_permanent = 0 WHERE hwid = ?"
    ).bind(expiry, hwid).run();

    await logAction(hwid, 'trial', `7-day trial granted (expires: ${new Date(expiry).toLocaleDateString('en-PK')})`, env);

    return jsonResponse({
      success: true,
      message: '7-day trial granted',
      expiry_date: expiry,
    });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── PUT /api/admin/machines/:hwid/features ────────────────────────────────────
export async function updateFeatures(hwid, request, env) {
  try {
    const body = await parseBody(request);
    const existing = await env.DB.prepare('SELECT hwid FROM machines WHERE hwid = ?').bind(hwid).first();
    if (!existing) return errorResponse(404, 'Machine not found');

    // Upsert feature flags
    await env.DB.prepare(`
      INSERT INTO machine_features (hwid, mobile_app, cloud_backup, reports, purchases, expenses, returns_module, suppliers, multi_user, lan_sync)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(hwid) DO UPDATE SET
        mobile_app     = excluded.mobile_app,
        cloud_backup   = excluded.cloud_backup,
        reports        = excluded.reports,
        purchases      = excluded.purchases,
        expenses       = excluded.expenses,
        returns_module = excluded.returns_module,
        suppliers      = excluded.suppliers,
        multi_user     = excluded.multi_user,
        lan_sync       = excluded.lan_sync
    `).bind(
      hwid,
      body.mobile_app     ?? 1,
      body.cloud_backup   ?? 1,
      body.reports        ?? 1,
      body.purchases      ?? 1,
      body.expenses       ?? 1,
      body.returns_module ?? 1,
      body.suppliers      ?? 1,
      body.multi_user     ?? 1,
      body.lan_sync       ?? 1,
    ).run();

    const changed = Object.entries(body)
      .map(([k, v]) => `${k}=${v ? 'ON' : 'OFF'}`)
      .join(', ');

    await logAction(hwid, 'feature_updated', `Features updated: ${changed}`, env);

    return jsonResponse({ success: true, message: 'Feature flags updated' });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── GET /api/admin/machines/:hwid/logs ───────────────────────────────────────
export async function getMachineLogs(hwid, env) {
  try {
    const logs = await env.DB.prepare(
      'SELECT * FROM license_logs WHERE hwid = ? ORDER BY created_at DESC LIMIT 50'
    ).bind(hwid).all();

    return jsonResponse({ success: true, logs: logs.results });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── GET /api/admin/stats ──────────────────────────────────────────────────────
export async function getStats(env) {
  try {
    const now = Date.now();

    const [total, active, trial, expired, revoked, inactive, expiringSoon] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) as c FROM machines").first(),
      env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status = 'active'").first(),
      env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status = 'trial'").first(),
      env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status = 'inactive' OR (license_expiry IS NOT NULL AND license_expiry < ?)").bind(now).first(),
      env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status = 'revoked'").first(),
      env.DB.prepare("SELECT COUNT(*) as c FROM machines WHERE status = 'inactive'").first(),
      // Expiring in next 7 days
      env.DB.prepare(
        "SELECT COUNT(*) as c FROM machines WHERE status = 'active' AND is_permanent = 0 AND license_expiry IS NOT NULL AND license_expiry BETWEEN ? AND ?"
      ).bind(now, now + 7 * 24 * 60 * 60 * 1000).first(),
    ]);

    // Recent registrations (last 7 days)
    const recentReg = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM machines WHERE created_at > ?"
    ).bind(now - 7 * 24 * 60 * 60 * 1000).first();

    // Machines active in last 24h
    const recentActive = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM machines WHERE last_seen > ?"
    ).bind(now - 24 * 60 * 60 * 1000).first();

    return jsonResponse({
      success: true,
      stats: {
        total:           total?.c || 0,
        active:          active?.c || 0,
        trial:           trial?.c || 0,
        expired:         expired?.c || 0,
        revoked:         revoked?.c || 0,
        inactive:        inactive?.c || 0,
        expiring_soon:   expiringSoon?.c || 0,
        recent_reg_7d:   recentReg?.c || 0,
        active_24h:      recentActive?.c || 0,
      }
    });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}

// ── Internal: log an action ───────────────────────────────────────────────────
async function logAction(hwid, action, detail, env) {
  try {
    await env.DB.prepare(
      "INSERT INTO license_logs (hwid, action, detail, performed_by) VALUES (?, ?, ?, 'admin')"
    ).bind(hwid, action, detail).run();
  } catch (e) {
    console.error('Log write failed:', e);
  }
}
