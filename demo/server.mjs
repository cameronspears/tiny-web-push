// The demo: `pnpm demo`, then open http://localhost:4174. Dev only, not part of the package.
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';

import { generateVapidKeys, sendWebPush } from '../dist/index.js';

const PORT = 4174;
const HOST = '127.0.0.1';

let keys = { publicKey: process.env.VAPID_PUBLIC_KEY, privateKey: process.env.VAPID_PRIVATE_KEY };
if (!keys.publicKey || !keys.privateKey) {
  keys = generateVapidKeys();
  console.log('No VAPID keys set, so the demo made a fresh pair for this run.');
}
const vapid = { ...keys, subject: 'mailto:demo@example.com' };

const files = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/sw.js': ['sw.js', 'text/javascript; charset=utf-8'],
};

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readBody(req, limit = 4096) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > limit) throw new Error('Body too large');
  }
  return body;
}

async function send(req, res) {
  let subscription;
  try {
    subscription = JSON.parse(await readBody(req));
  } catch {
    return json(res, 400, { error: 'Send the subscription as JSON.' });
  }

  // A wrapped fetch shows how big the encrypted body was. It's also how you'd add a proxy.
  let bytes = null;
  const started = Date.now();
  const outcome = await sendWebPush(
    subscription,
    JSON.stringify({
      title: 'Hello from tiny-web-push',
      body: 'Your server encrypted this. Only your browser could read it.',
    }),
    {
      vapid,
      ttl: 60,
      urgency: 'high',
      fetch: (url, init) => {
        bytes = init.body.byteLength;
        return fetch(url, init);
      },
    }
  );
  console.log(`${outcome.result} (${outcome.status ?? 'no response'}) from ${outcome.host ?? 'unknown host'}`);
  json(res, 200, { ...outcome, bytes, ms: Date.now() - started });
}

const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (req.method === 'GET' && path === '/api/key') return json(res, 200, { publicKey: vapid.publicKey });
    if (req.method === 'POST' && path === '/api/send') return await send(req, res);
    const file = req.method === 'GET' ? files[path] : undefined;
    if (!file) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': file[1], 'Cache-Control': 'no-store' });
    res.end(await readFile(new URL(file[0], import.meta.url)));
  } catch (error) {
    console.error(error);
    if (!res.headersSent) json(res, 500, { error: 'The demo server hit an error. See the terminal.' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`tiny-web-push demo: http://localhost:${PORT}  (Ctrl+C to stop)`);
});
