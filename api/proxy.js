// /api/proxy.js
// Replaces dubai_re_proxy.py — runs as a Vercel serverless function
// Proxies external API calls to avoid CORS restrictions in the browser

const ALLOWED_HOSTS = [
  'api.telegram.org',
  'www.dubaipulse.gov.ae',
  'dubaipulse.gov.ae',
  'rapidapi.com',
  'stg-apis.data.dubai',
  'apis.data.dubai',
];

function isAllowed(host) {
  if (ALLOWED_HOSTS.includes(host)) return true;
  for (const d of ALLOWED_HOSTS) {
    if (host.endsWith('.' + d)) return true;
  }
  if (host.endsWith('.p.rapidapi.com')) return true;
  return false;
}

export default async function handler(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-RapidAPI-Key,X-RapidAPI-Host');
    return res.status(200).end();
  }

  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  if (!isAllowed(parsedUrl.hostname)) {
    return res.status(403).json({ error: `Blocked host: ${parsedUrl.hostname}` });
  }

  const headers = {
    'User-Agent': 'Mozilla/5.0',
    'Accept': 'application/json, text/plain, */*',
  };

  // Forward safe headers from the incoming request
  const forwardHeaders = ['content-type', 'authorization', 'x-rapidapi-key', 'x-rapidapi-host'];
  for (const h of forwardHeaders) {
    if (req.headers[h]) headers[h] = req.headers[h];
  }

  // Forward header_ query params (RapidAPI pattern)
  for (const [k, v] of Object.entries(req.query)) {
    if (k.startsWith('header_')) headers[k.slice(7)] = v;
  }

  try {
    const fetchOptions = {
      method: req.method,
      headers,
    };

    if (req.method === 'POST' && req.body) {
      fetchOptions.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    }

    const upstream = await fetch(url, fetchOptions);
    const contentType = upstream.headers.get('content-type') || 'application/json';
    const data = await upstream.arrayBuffer();

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', contentType);
    res.status(upstream.status).send(Buffer.from(data));
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
}

export const config = { api: { bodyParser: { sizeLimit: '10mb' } } };
