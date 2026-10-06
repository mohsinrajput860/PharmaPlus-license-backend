# PharmaPlus License Backend — Cloudflare Workers Setup

## Step 1: Install Wrangler CLI
```bash
npm install -g wrangler
wrangler login
```

## Step 2: Create D1 Database
```bash
wrangler d1 create pharma-license-db
```
Copy the `database_id` from output and paste into `wrangler.toml` → `database_id`.

## Step 3: Run Database Schema
```bash
cd pharma-license-backend
npm install
npm run db:init:remote
```

## Step 4: Set Secrets (one-time)
```bash
# Your admin login password hash — run this in Node.js to generate:
# require('crypto').createHash('sha256').update('YOUR_PASSWORD' + 'pharmaplus_admin_salt').digest('hex')

wrangler secret put ADMIN_PASSWORD_HASH
# paste the hash when prompted

wrangler secret put JWT_SECRET
# paste any random 64-char string e.g: openssl rand -hex 32
```

## Step 5: Set CORS Origin
Edit `wrangler.toml` and change `CORS_ORIGIN` to your Vercel dashboard URL:
```toml
[vars]
CORS_ORIGIN = "https://your-dashboard.vercel.app"
```

## Step 6: Deploy
```bash
npm run deploy
```
Your API URL will be: `https://pharma-license-backend.<your-subdomain>.workers.dev`

## Step 7: Test
```
GET https://pharma-license-backend.xxx.workers.dev/api/health
```
Should return: `{ "status": "ok" }`

---

## API Quick Reference

### Public (called by app)
| Method | Route | Description |
|--------|-------|-------------|
| POST | /api/license/verify | Verify HWID + get features |
| POST | /api/license/register | First-time machine registration |
| POST | /api/license/ping | Heartbeat update |

### Admin (requires Bearer JWT)
| Method | Route | Description |
|--------|-------|-------------|
| POST | /api/admin/login | Get JWT token |
| GET | /api/admin/machines | List all machines |
| GET | /api/admin/stats | Dashboard statistics |
| POST | /api/admin/machines/:hwid/authorize | Grant license (body: {days: 30}) |
| POST | /api/admin/machines/:hwid/revoke | Revoke license |
| POST | /api/admin/machines/:hwid/trial | Grant 7-day trial |
| PUT | /api/admin/machines/:hwid/features | Toggle features |
| PUT | /api/admin/machines/:hwid | Edit store info |
| DELETE | /api/admin/machines/:hwid | Delete record |
