// /api/dld.js
// DDA iPaaS integration — hardened against abuse and API limit violations
//
// PROTECTIONS:
//   1. Per-IP rate limiter     — 20 req/min per caller (DDA allows 60 total)
//   2. Global rate limiter     — 50 req/min across all callers (10 headroom under DDA's 60)
//   3. Daily request counter   — hard stop at 180K/day (20K headroom under DDA's 200K)
//   4. Concurrent request cap  — max 3 in-flight DDA calls at any time
//   5. Request queue           — excess requests wait, not fail (up to 10 queued)
//   6. Per-request timeout     — 28s (2s under DDA's 30s cutoff)
//   7. Response size guard     — reject responses > 7.5MB (under DDA's 8MB limit)
//   8. Input sanitisation      — entity/dataset/filter validated before use
//   9. Retry with backoff      — on 429 or 503, retry up to 2x with exponential delay
//  10. Probe debounce          — probe locked for 60s after each run
//  11. Token refresh guard     — single in-flight token fetch (no thundering herd)
//  12. pageSize cap            — clamps to 200 max (protects response size)

const BASE_URL   = 'https://apis.data.dubai';
const STG_URL    = 'https://stg-apis.data.dubai';
const TOKEN_PATH = '/secure/sdg/ssis/gatewayoauthtoken/1.0.0/getAccessToken';

const LIMITS = {
  PER_IP_PER_MIN:   20,
  GLOBAL_PER_MIN:   50,
  DAILY_MAX:        180000,
  MAX_CONCURRENT:   3,
  MAX_QUEUED:       10,
  REQUEST_TIMEOUT:  28000,
  MAX_RESPONSE_MB:  7.5,
  MAX_PAGE_SIZE:    200,
  PROBE_COOLDOWN:   60000,
};

// In-memory state
let cachedToken   = null;
let tokenExpiry   = 0;
let tokenFetching = false;
let tokenWaiters  = [];

const globalWindow = [];
const ipWindows    = {};

let dailyCount     = 0;
let dailyResetDate = '';

let inFlight  = 0;
const waitQueue = [];

let probeLastRun = 0;

// ─── Helpers ────────────────────────────────────────────────────────────────

function dubaiDateStr() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Dubai' });
}

class RateLimitError extends Error { constructor(msg) { super(msg); this.type = 'rate_limit'; } }
class ValidationError extends Error { constructor(msg) { super(msg); this.type = 'validation'; } }

function checkAndIncrementDaily() {
  const today = dubaiDateStr();
  if (today !== dailyResetDate) { dailyCount = 0; dailyResetDate = today; }
  if (dailyCount >= LIMITS.DAILY_MAX) {
    throw new RateLimitError(`Daily DDA limit reached (${LIMITS.DAILY_MAX.toLocaleString()}/day). Resets midnight Dubai time.`);
  }
  dailyCount++;
}

function slidingWindowCheck(arr, limit, windowMs = 60000) {
  const now = Date.now();
  const cutoff = now - windowMs;
  while (arr.length && arr[0] < cutoff) arr.shift();
  if (arr.length >= limit) return false;
  arr.push(now);
  return true;
}

function checkRateLimits(ip) {
  if (!slidingWindowCheck(globalWindow, LIMITS.GLOBAL_PER_MIN)) {
    throw new RateLimitError(`Global rate limit hit (${LIMITS.GLOBAL_PER_MIN} req/min). Wait a moment.`);
  }
  if (ip) {
    if (!ipWindows[ip]) ipWindows[ip] = [];
    if (!slidingWindowCheck(ipWindows[ip], LIMITS.PER_IP_PER_MIN)) {
      throw new RateLimitError(`Too many requests from your connection (${LIMITS.PER_IP_PER_MIN} req/min max).`);
    }
  }
}

function acquireSlot() {
  return new Promise((resolve, reject) => {
    if (inFlight < LIMITS.MAX_CONCURRENT) { inFlight++; return resolve(); }
    if (waitQueue.length >= LIMITS.MAX_QUEUED) {
      return reject(new RateLimitError(`Request queue full (${LIMITS.MAX_QUEUED} waiting). Try again shortly.`));
    }
    waitQueue.push({ resolve, reject });
  });
}

function releaseSlot() {
  inFlight = Math.max(0, inFlight - 1);
  if (waitQueue.length > 0) { const next = waitQueue.shift(); inFlight++; next.resolve(); }
}

function sanitiseName(val, field) {
  if (!val || typeof val !== 'string') throw new ValidationError(`${field} is required`);
  const clean = val.trim().toLowerCase();
  if (!/^[a-z0-9_-]{1,80}$/.test(clean)) {
    throw new ValidationError(`Invalid ${field}: letters, numbers, hyphens, underscores only (max 80 chars)`);
  }
  return clean;
}

function sanitiseFilter(val) {
  if (!val) return '';
  const s = val.trim();
  if (s.length > 200) throw new ValidationError('Filter too long (max 200 chars)');
  if (/[;<>{}()\[\]\\]/.test(s)) throw new ValidationError('Filter contains invalid characters');
  return s;
}

function clampPageSize(val) {
  const n = parseInt(val, 10);
  if (isNaN(n) || n < 1) return 50;
  return Math.min(n, LIMITS.MAX_PAGE_SIZE);
}

// ─── Token management (thundering herd protection) ──────────────────────────

async function getToken(baseUrl, securityId, clientId, clientSecret) {
  const now = Date.now();
  if (cachedToken && now < tokenExpiry) return cachedToken;
  if (tokenFetching) {
    return new Promise((resolve, reject) => tokenWaiters.push({ resolve, reject }));
  }
  tokenFetching = true;
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch(`${baseUrl}${TOKEN_PATH}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-DDA-SecurityApplicationIdentifier': securityId,
      },
      body: JSON.stringify({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }),
      signal: ctrl.signal,
    });
    clearTimeout(tid);
    if (!resp.ok) {
      const t = await resp.text();
      throw new Error(`Token fetch failed (${resp.status}): ${t.slice(0, 200)}`);
    }
    const data = await resp.json();
    if (!data.access_token) throw new Error('No access_token in auth response');
    cachedToken = data.access_token;
    tokenExpiry = now + ((data.expires_in || 3600) - 300) * 1000;
    tokenWaiters.forEach(w => w.resolve(cachedToken));
    return cachedToken;
  } catch (err) {
    cachedToken = null; tokenExpiry = 0;
    tokenWaiters.forEach(w => w.reject(err));
    throw err;
  } finally {
    tokenFetching = false; tokenWaiters = [];
  }
}

// ─── Fetch with timeout + size guard + retry ────────────────────────────────

async function ddaFetch(url, token, retries = 2) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, 1000 * attempt));
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), LIMITS.REQUEST_TIMEOUT);
    try {
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal: ctrl.signal });
      clearTimeout(tid);
      if ((resp.status === 429 || resp.status === 503) && attempt < retries) {
        lastErr = new Error(`DDA returned ${resp.status} — retrying`);
        continue;
      }
      const cl = parseInt(resp.headers.get('content-length') || '0', 10);
      if (cl > LIMITS.MAX_RESPONSE_MB * 1024 * 1024) {
        throw new Error(`Response too large (${(cl/1024/1024).toFixed(1)}MB). Use a smaller pageSize.`);
      }
      const text = await resp.text();
      if (text.length > LIMITS.MAX_RESPONSE_MB * 1024 * 1024) {
        throw new Error(`Response body too large (${(text.length/1024/1024).toFixed(1)}MB). Use a smaller pageSize.`);
      }
      let data;
      try { data = JSON.parse(text); } catch { data = { raw: text.slice(0, 500) }; }
      return { ok: resp.ok, status: resp.status, data };
    } catch (err) {
      clearTimeout(tid);
      lastErr = err.name === 'AbortError'
        ? new Error(`DDA request timed out after ${LIMITS.REQUEST_TIMEOUT / 1000}s`)
        : err;
      if (attempt >= retries) throw lastErr;
    }
  }
  throw lastErr;
}

// ─── Main handler ────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  res.setHeader('Access-Control-Allow-Origin', '*');

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket?.remoteAddress || 'unknown';

  const securityId   = process.env.DDA_SECURITY_IDENTIFIER;
  const clientId     = process.env.DDA_CLIENT_ID;
  const clientSecret = process.env.DDA_CLIENT_SECRET;
  const useStaging   = process.env.DDA_USE_STAGING === 'true';
  const baseUrl      = useStaging ? STG_URL : BASE_URL;

  if (!securityId || !clientId || !clientSecret) {
    return res.status(500).json({
      ok: false, error: 'DDA credentials not configured',
      missing: {
        DDA_SECURITY_IDENTIFIER: !securityId,
        DDA_CLIENT_ID:           !clientId,
        DDA_CLIENT_SECRET:       !clientSecret,
      },
    });
  }

  const { action } = req.query;
  if (!action) return res.status(400).json({ ok: false, error: 'action parameter required' });

  // ── token — no rate limit cost ────────────────────────────────────────────
  if (action === 'token') {
    try {
      const token = await getToken(baseUrl, securityId, clientId, clientSecret);
      return res.status(200).json({
        ok: true,
        token_preview:    token.slice(0, 12) + '...',
        expires_in:       Math.round((tokenExpiry - Date.now()) / 1000),
        daily_used:       dailyCount,
        daily_limit:      LIMITS.DAILY_MAX,
        daily_remaining:  LIMITS.DAILY_MAX - dailyCount,
      });
    } catch (err) { return res.status(401).json({ ok: false, error: err.message }); }
  }

  // ── status — live limit dashboard ─────────────────────────────────────────
  if (action === 'status') {
    const now = Date.now(); const cutoff = now - 60000;
    return res.status(200).json({
      ok: true,
      limits: {
        global_per_min:    { used: globalWindow.filter(t => t > cutoff).length, limit: LIMITS.GLOBAL_PER_MIN },
        ip_per_min:        { used: (ipWindows[ip]||[]).filter(t => t > cutoff).length, limit: LIMITS.PER_IP_PER_MIN },
        daily:             { used: dailyCount, limit: LIMITS.DAILY_MAX, remaining: LIMITS.DAILY_MAX - dailyCount },
        concurrent:        { active: inFlight, limit: LIMITS.MAX_CONCURRENT },
        queued:            { waiting: waitQueue.length, limit: LIMITS.MAX_QUEUED },
        probe_cooldown_ms: Math.max(0, LIMITS.PROBE_COOLDOWN - (now - probeLastRun)),
      },
    });
  }

  // All other actions: rate limit + daily counter
  try {
    checkRateLimits(ip);
    checkAndIncrementDaily();
  } catch (err) {
    return res.status(err.type === 'rate_limit' ? 429 : 400).json({ ok: false, error: err.message, type: err.type });
  }

  // ── health ────────────────────────────────────────────────────────────────
  if (action === 'health') {
    let entity, dataset;
    try { entity = sanitiseName(req.query.entity, 'entity'); dataset = sanitiseName(req.query.dataset, 'dataset'); }
    catch (err) { return res.status(400).json({ ok: false, error: err.message }); }
    await acquireSlot();
    try {
      const token  = await getToken(baseUrl, securityId, clientId, clientSecret);
      const result = await ddaFetch(`${baseUrl}/secure/ddads/health/1.0.0/${entity}/${dataset}`, token, 1);
      return res.status(result.status).json({ ok: result.ok, status: result.status, data: result.data });
    } catch (err) { return res.status(502).json({ ok: false, error: err.message }); }
    finally { releaseSlot(); }
  }

  // ── query ─────────────────────────────────────────────────────────────────
  if (action === 'query') {
    let entity, dataset, filter;
    try {
      entity  = sanitiseName(req.query.entity,  'entity');
      dataset = sanitiseName(req.query.dataset, 'dataset');
      filter  = sanitiseFilter(req.query.filter);
    } catch (err) { return res.status(400).json({ ok: false, error: err.message }); }

    const { column, page, limit, order_by, order_dir, offset } = req.query;
    const pageSize       = clampPageSize(req.query.pageSize);
    const requestedSize  = parseInt(req.query.pageSize, 10);
    const wasClamped     = !isNaN(requestedSize) && requestedSize > LIMITS.MAX_PAGE_SIZE;

    const params = new URLSearchParams();
    if (column)    params.set('column',    column.slice(0, 500));
    if (filter)    params.set('filter',    filter);
    if (page)      params.set('page',      String(Math.max(1, parseInt(page, 10) || 1)));
    params.set('pageSize', String(pageSize));
    if (limit)     params.set('limit',     String(Math.min(parseInt(limit, 10) || 50, LIMITS.MAX_PAGE_SIZE)));
    if (order_by)  { try { params.set('order_by', sanitiseName(order_by, 'order_by')); } catch(_) {} }
    if (order_dir) params.set('order_dir', order_dir === 'asc' ? 'asc' : 'desc');
    if (offset)    params.set('offset',    String(Math.max(0, parseInt(offset, 10) || 0)));

    const qs  = params.toString();
    const url = `${baseUrl}/secure/ddads/openapi/1.0.0/${entity}/${dataset}${qs ? '?' + qs : ''}`;

    await acquireSlot();
    try {
      const token  = await getToken(baseUrl, securityId, clientId, clientSecret);
      const result = await ddaFetch(url, token, 2);
      return res.status(result.status).json({
        ok: result.ok, status: result.status, data: result.data,
        page_size_used: pageSize,
        ...(wasClamped ? { warning: `pageSize clamped to ${LIMITS.MAX_PAGE_SIZE} (requested ${requestedSize})` } : {}),
      });
    } catch (err) { return res.status(502).json({ ok: false, error: err.message }); }
    finally { releaseSlot(); }
  }

  // ── probe ─────────────────────────────────────────────────────────────────
  if (action === 'probe') {
    const now = Date.now();
    if (now - probeLastRun < LIMITS.PROBE_COOLDOWN) {
      const wait = Math.ceil((LIMITS.PROBE_COOLDOWN - (now - probeLastRun)) / 1000);
      return res.status(429).json({
        ok: false, type: 'probe_cooldown',
        error: `Probe cooldown active — wait ${wait}s before running again.`,
        retry_after_seconds: wait,
      });
    }
    probeLastRun = now;

    const guesses = [
      { entity: 'dld', dataset: 'dld_transactions' },
      { entity: 'dld', dataset: 'dld_projects' },
      { entity: 'dld', dataset: 'dld_rental_index' },
      { entity: 'dld', dataset: 'dld_brokers' },
      { entity: 'dld', dataset: 'dld_developers' },
      { entity: 'dld', dataset: 'dld_units' },
      { entity: 'dld', dataset: 'dld_mortgages' },
      { entity: 'dld', dataset: 'transactions' },
      { entity: 'dld', dataset: 'projects' },
      { entity: 'dld', dataset: 'units' },
      { entity: 'dld', dataset: 'brokers' },
      { entity: 'dld', dataset: 'developers' },
      { entity: 'dld', dataset: 'rental_index' },
      { entity: 'ded', dataset: 'ded_licenses' },
      { entity: 'ded', dataset: 'business_licenses' },
    ];

    if (dailyCount + guesses.length > LIMITS.DAILY_MAX) {
      return res.status(429).json({
        ok: false, type: 'rate_limit',
        error: `Not enough daily quota for probe (need ${guesses.length}, have ${LIMITS.DAILY_MAX - dailyCount})`,
      });
    }

    try {
      const token   = await getToken(baseUrl, securityId, clientId, clientSecret);
      const results = [];

      for (const { entity, dataset } of guesses) {
        // Back off if global window is full
        if (!slidingWindowCheck(globalWindow, LIMITS.GLOBAL_PER_MIN)) {
          await new Promise(r => setTimeout(r, 5000));
        }
        dailyCount++;

        await acquireSlot();
        try {
          const ctrl = new AbortController();
          const tid  = setTimeout(() => ctrl.abort(), 8000);
          const resp = await fetch(`${baseUrl}/secure/ddads/health/1.0.0/${entity}/${dataset}`, {
            headers: { Authorization: `Bearer ${token}` }, signal: ctrl.signal,
          });
          clearTimeout(tid);
          results.push({ entity, dataset, status: resp.status, found: resp.ok });
        } catch (err) {
          results.push({ entity, dataset, status: err.name === 'AbortError' ? 'timeout' : 'error', found: false });
        } finally { releaseSlot(); }

        await new Promise(r => setTimeout(r, 1000)); // 1s between probe calls
      }

      return res.status(200).json({
        ok: true, results,
        requests_used:    guesses.length,
        daily_remaining:  LIMITS.DAILY_MAX - dailyCount,
      });
    } catch (err) { return res.status(502).json({ ok: false, error: err.message }); }
  }

  return res.status(400).json({
    ok: false, error: `Unknown action: "${action}"`,
    valid_actions: ['token', 'status', 'health', 'query', 'probe'],
  });
}

export const config = { api: { bodyParser: true } };
