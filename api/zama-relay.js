export const config = { runtime: 'edge' };
export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*',
    }});
  }
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/zama-relay/, '') || '/';
  const target = `https://relayer.testnet.zama.org${path}${url.search}`;

  // Forward original headers (includes ZAMA-SDK-VERSION, ZAMA-SDK-NAME)
  const forwardHeaders = {};
  for (const [key, value] of req.headers.entries()) {
    if (!['host', 'connection'].includes(key.toLowerCase())) {
      forwardHeaders[key] = value;
    }
  }

  const response = await fetch(target, {
    method: req.method,
    headers: forwardHeaders,
    body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
  });
  // [H-4] Detect binary responses — text() corrupts octet-stream blobs from Zama relayer
  const contentType = response.headers.get('content-type') ?? 'application/json';
  const isBinary = contentType.includes('octet-stream') || contentType.includes('binary');
  const data = isBinary ? await response.arrayBuffer() : await response.text();
  return new Response(data, {
    status: response.status,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      'content-type': contentType,
    },
  });
}
