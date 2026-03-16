export const config = { runtime: 'edge' };

export default async function handler(req) {
  const url = new URL(req.url);
  const path = url.pathname.replace('/api/zama-relay', '');
  const target = `https://relayer.testnet.zama.org${path}`;

  const response = await fetch(target, {
    method: req.method,
    headers: { 'content-type': 'application/json' },
    body: req.method !== 'GET' ? req.body : undefined,
  });

  const data = await response.text();

  return new Response(data, {
    status: response.status,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      'content-type': 'application/json',
    },
  });
}
