/**
 * Public License Routes — called by Electron app on every startup
 *
 * POST /api/license/verify   — main gate: is this HWID licensed?
 * POST /api/license/register — first-time registration of a new machine
 * POST /api/license/ping     — heartbeat update (last_seen, open_count, app_version)
 */

import { jsonResponse, errorResponse, parseBody, defaultFeatures } from './utils.js';

// ── POST /api/license/verify ──────────────────────────────────────────────────
export async function handleVerify(request, env) {
  const body = await parseBody(request);
  const { hwid, app_version } = body;

  if (!hwid || hwid.length < 8) {
    return errorResponse(400, 'Invalid HWID');
  }

  try {
    // Fetch machine record
    const machine = await env.DB.prepare(
      'SELECT * FROM machines WHERE hwid = ?'
    ).bind(hwid).first();

    if (!machine) {
      return jsonResponse({
        authorized: false,
        reason: 'NOT_REGISTERED',
        features: defaultFeatures(),
      });
    }

    // Status check
    if (machine.status === 'revoked') {
      return jsonResponse({
        authorized: false,
        reason: 'REVOKED',
        shop_name: machine.shop_name,
        features: defaultFeatures(),
      });
    }

    if (machine.status === 'inactive') {
      return jsonResponse({
        authorized: false,
        reason: 'INACTIVE',
        shop_name: machine.shop_name,
        features: defaultFeatures(),
      });
    }

    // Expiry check (skip if permanent)
    if (!machine.is_permanent && machine.license_expiry) {
      if (Date.now() > machine.license_expiry) {
        // Auto-update status to inactive if expired
        await env.DB.prepare(
          "UPDATE machines SET status = 'inactive' WHERE hwid = ?"
        ).bind(hwid).run();

        return jsonResponse({
          authorized: false,
          reason: 'EXPIRED',
          shop_name: machine.shop_name,
          expiry_date: machine.license_expiry,
          features: defaultFeatures(),
        });
      }
    }

    // Fetch feature flags
    const featRow = await env.DB.prepare(
      'SELECT * FROM machine_features WHERE hwid = ?'
    ).bind(hwid).first();

    const features = featRow ? {
      mobile_app:     featRow.mobile_app,
      cloud_backup:   featRow.cloud_backup,
      reports:        featRow.reports,
      purchases:      featRow.purchases,
      expenses:       featRow.expenses,
      returns_module: featRow.returns_module,
      suppliers:      featRow.suppliers,
      multi_user:     featRow.multi_user,
      lan_sync:       featRow.lan_sync,
    } : defaultFeatures();

    // Update last_seen + open_count + app_version in background
    env.ctx?.waitUntil(
      env.DB.prepare(
        'UPDATE machines SET last_seen = ?, open_count = open_count + 1, app_version = ? WHERE hwid = ?'
      ).bind(Date.now(), app_version || machine.app_version || '', hwid).run()
    );

    return jsonResponse({
      authorized: true,
      status: machine.status,
      shop_name: machine.shop_name,
      is_permanent: machine.is_permanent === 1,
      expiry_date: machine.license_expiry,
      features,
    });

  } catch (err) {
    console.error('verify error:', err);
    return errorResponse(500, 'License check failed: ' + err.message);
  }
}

// ── POST /api/license/register ────────────────────────────────────────────────
export async function handleRegister(request, env) {
  const body = await parseBody(request);
  const { hwid, shop_name, owner_name, phone, city, app_version } = body;

  if (!hwid || hwid.length < 8) {
    return errorResponse(400, 'Invalid HWID');
  }

  try {
    // Check if already registered
    const existing = await env.DB.prepare(
      'SELECT hwid, status FROM machines WHERE hwid = ?'
    ).bind(hwid).first();

    if (existing) {
      // Already registered — return current status (don't reset)
      return jsonResponse({
        success: true,
        already_registered: true,
        status: existing.status,
        message: 'Machine already registered',
      });
    }

    const now = Date.now();

    // Create machine record (starts as inactive — admin must authorize)
    await env.DB.prepare(`
      INSERT INTO machines (hwid, shop_name, owner_name, phone, city, status, created_at, last_seen, app_version)
      VALUES (?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
    `).bind(
      hwid,
      shop_name || 'New Store',
      owner_name || '',
      phone || '',
      city || '',
      now, now,
      app_version || ''
    ).run();

    // Create default feature flags
    await env.DB.prepare(`
      INSERT INTO machine_features (hwid, mobile_app, cloud_backup, reports, purchases, expenses, returns_module, suppliers, multi_user, lan_sync)
      VALUES (?, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    `).bind(hwid).run();

    // Log it
    await env.DB.prepare(
      "INSERT INTO license_logs (hwid, action, detail) VALUES (?, 'registered', ?)"
    ).bind(hwid, `New machine registered: ${shop_name || 'Unknown'}`).run();

    return jsonResponse({
      success: true,
      already_registered: false,
      status: 'inactive',
      message: 'Registered successfully. Waiting for admin authorization.',
    });

  } catch (err) {
    console.error('register error:', err);
    return errorResponse(500, 'Registration failed: ' + err.message);
  }
}

// ── POST /api/license/ping ────────────────────────────────────────────────────
export async function handlePing(request, env) {
  const body = await parseBody(request);
  const { hwid, app_version } = body;

  if (!hwid) return errorResponse(400, 'HWID required');

  try {
    await env.DB.prepare(
      'UPDATE machines SET last_seen = ?, app_version = COALESCE(?, app_version) WHERE hwid = ?'
    ).bind(Date.now(), app_version || null, hwid).run();

    return jsonResponse({ success: true });
  } catch (err) {
    return errorResponse(500, err.message);
  }
}
