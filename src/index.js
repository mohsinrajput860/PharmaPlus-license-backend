/**
 * PharmaPlus License Management API
 * Cloudflare Worker + D1 Database
 *
 * Routes:
 *   PUBLIC  (called by Electron app on every startup)
 *     POST /api/license/verify         — verify HWID license + return feature flags
 *     POST /api/license/register       — first-time machine registration
 *     POST /api/license/ping           — heartbeat (last_seen + open_count update)
 *
 *   ADMIN   (called by React dashboard, requires Bearer JWT)
 *     POST /api/admin/login            — get JWT token
 *     GET  /api/admin/machines         — list all machines
 *     GET  /api/admin/machines/:hwid   — single machine detail
 *     PUT  /api/admin/machines/:hwid   — update shop info / notes
 *     POST /api/admin/machines/:hwid/authorize   — grant/extend license
 *     POST /api/admin/machines/:hwid/revoke      — revoke license
 *     POST /api/admin/machines/:hwid/trial       — grant 7-day trial
 *     PUT  /api/admin/machines/:hwid/features    — update feature flags
 *     DELETE /api/admin/machines/:hwid           — delete machine record
 *     GET  /api/admin/machines/:hwid/logs        — activity log for machine
 *     GET  /api/admin/stats                      — dashboard stats
 *     POST /api/admin/logout                     — revoke current JWT
 */

import { handleAdminLogin, verifyAdminJWT } from './auth.js';
import { corsHeaders, withCors, errorResponse, jsonResponse } from './utils.js';
import { handleVerify, handleRegister, handlePing } from './license.js';
import {
  listMachines, getMachine, updateMachine, deleteMachine,
  authorizeMachine, revokeMachine, grantTrial,
  updateFeatures, getMachineLogs, getStats
} from './admin.js';

export default {
  async fetch(request, env, ctx) {
    // ── CORS preflight ──────────────────────────────────────────────────────
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // ── Public Routes (no auth) ───────────────────────────────────────────
      if (path === '/api/license/verify' && method === 'POST') {
        return withCors(await handleVerify(request, env), env);
      }
      if (path === '/api/license/register' && method === 'POST') {
        return withCors(await handleRegister(request, env), env);
      }
      if (path === '/api/license/ping' && method === 'POST') {
        return withCors(await handlePing(request, env), env);
      }

      // ── Admin Login (no auth needed) ──────────────────────────────────────
      if (path === '/api/admin/login' && method === 'POST') {
        return withCors(await handleAdminLogin(request, env), env);
      }

      // ── Protected Admin Routes ────────────────────────────────────────────
      if (path.startsWith('/api/admin/')) {
        const authResult = await verifyAdminJWT(request, env);
        if (!authResult.valid) {
          return withCors(errorResponse(401, 'Unauthorized — invalid or expired token'), env);
        }

        // /api/admin/stats
        if (path === '/api/admin/stats' && method === 'GET') {
          return withCors(await getStats(env), env);
        }

        // /api/admin/logout
        if (path === '/api/admin/logout' && method === 'POST') {
          return withCors(await revokeSession(request, env), env);
        }

        // /api/admin/machines
        if (path === '/api/admin/machines' && method === 'GET') {
          return withCors(await listMachines(request, env), env);
        }

        // /api/admin/machines/:hwid and sub-routes
        const machineMatch = path.match(/^\/api\/admin\/machines\/([^/]+)(\/.*)?$/);
        if (machineMatch) {
          const hwid = decodeURIComponent(machineMatch[1]);
          const sub  = machineMatch[2] || '';

          if (sub === '' && method === 'GET')    return withCors(await getMachine(hwid, env), env);
          if (sub === '' && method === 'PUT')    return withCors(await updateMachine(hwid, request, env), env);
          if (sub === '' && method === 'DELETE') return withCors(await deleteMachine(hwid, env), env);

          if (sub === '/authorize' && method === 'POST') return withCors(await authorizeMachine(hwid, request, env), env);
          if (sub === '/revoke'    && method === 'POST') return withCors(await revokeMachine(hwid, env), env);
          if (sub === '/trial'     && method === 'POST') return withCors(await grantTrial(hwid, env), env);
          if (sub === '/features'  && method === 'PUT')  return withCors(await updateFeatures(hwid, request, env), env);
          if (sub === '/logs'      && method === 'GET')  return withCors(await getMachineLogs(hwid, env), env);
        }

        return withCors(errorResponse(404, 'Admin route not found'), env);
      }

      // ── Health check ──────────────────────────────────────────────────────
      if (path === '/api/health') {
        return withCors(jsonResponse({ status: 'ok', service: 'pharma-license-api', ts: Date.now() }), env);
      }

      return withCors(errorResponse(404, 'Not found'), env);

    } catch (err) {
      console.error('Unhandled error:', err);
      return withCors(errorResponse(500, 'Internal server error: ' + err.message), env);
    }
  }
};

async function revokeSession(request, env) {
  try {
    const auth = request.headers.get('Authorization') || '';
    const token = auth.replace('Bearer ', '').trim();
    if (!token) return errorResponse(400, 'No token');
    const hash = await hashToken(token);
    await env.DB.prepare('UPDATE admin_sessions SET revoked = 1 WHERE token_hash = ?').bind(hash).run();
    return jsonResponse({ success: true });
  } catch (e) {
    return errorResponse(500, e.message);
  }
}

async function hashToken(token) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(token));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
