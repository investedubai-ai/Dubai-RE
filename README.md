# InvesteDubai — RE Intelligence Platform v3.0

Rebuilt for Vercel. No local proxy required.

## Project Structure

```
/api/proxy.js       — General proxy for external APIs (DubaiPulse, Telegram, Bayut)
/api/anthropic.js   — Anthropic AI calls (key stays server-side)
/api/dld.js         — DDA iPaaS integration (DLD OAuth + dataset queries)
/public/index.html  — Main platform UI
/vercel.json        — Routing config
/.env.example       — Environment variable template
```

## Deploy to Vercel

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "InvesteDubai v3.0 — Vercel rebuild"
git remote add origin https://github.com/YOUR_USERNAME/investedubai.git
git push -u origin main
```

### 2. Import to Vercel
- Go to vercel.com → New Project → Import your GitHub repo
- Framework: Other
- Root directory: leave blank (or /)

### 3. Set Environment Variables
In Vercel Dashboard → Project → Settings → Environment Variables, add:

| Variable | Value |
|---|---|
| `ANTHROPIC_API_KEY` | sk-ant-... |
| `DDA_SECURITY_IDENTIFIER` | From DDA team |
| `DDA_CLIENT_ID` | From DDA team |
| `DDA_CLIENT_SECRET` | From DDA team |
| `DDA_USE_STAGING` | false (or true for testing) |

### 4. Deploy
Vercel auto-deploys on every push to main.

## DLD API — DDA iPaaS

Three serverless actions exposed at `/api/dld`:

| Action | Description |
|---|---|
| `?action=token` | Test auth — confirms credentials work |
| `?action=health&entity=X&dataset=Y` | Check if dataset exists |
| `?action=query&entity=X&dataset=Y&[params]` | Query a dataset |
| `?action=probe` | Auto-probe 15 likely DLD dataset names |

### Query Parameters
All optional: `filter`, `page`, `pageSize`, `limit`, `order_by`, `order_dir`, `offset`, `column`

### Rate Limits (DDA)
- 60 requests/minute
- 200K requests/day  
- 30 second timeout
- Token valid 1 hour (auto-refreshed by server)

## Local Development

```bash
npm i -g vercel
vercel dev
```
Creates a local server that runs the serverless functions — identical to production.
Copy `.env.example` to `.env.local` and fill in your values.
