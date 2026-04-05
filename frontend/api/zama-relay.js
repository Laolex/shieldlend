export const config = { runtime: 'edge' };

export default async function handler(req) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': '*',
      },
    });
  }

  const url = new URL(req.url);
  const path = url.pathname.replace('/api/zama-relay', '');
  const search = url.search ?? '';
  const target = `https://relayer.testnet.zama.org${path}${search}`;

  const response = await fetch(target, {
    method: req.method,
    headers: { 'content-type': 'application/json' },
    body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
  });

  const contentType = response.headers.get('content-type') ?? 'application/octet-stream';
  const data = contentType.includes('application/octet-stream') || contentType.includes('binary')
    ? await response.arrayBuffer()
    : await response.text();

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
