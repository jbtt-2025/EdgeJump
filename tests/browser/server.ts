// Local acceptance harness: production Worker/DO code, SQLite D1 adapter,
// in-memory recording bucket, and a real encrypted SSH server. No Cloudflare resources.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';
import worker from '../../src/worker.ts';
import { createSshFixture } from '../ssh-fixture.ts';
import { createUser, resetUserPassword } from '../../src/users/user-service.ts';
import { setupMfa, confirmMfa } from '../../src/auth/auth-service.ts';
import { generateTotpCode } from '../../src/crypto/totp.ts';

const port = Number(process.env.EDGEJUMP_BROWSER_PORT || 4173);
const origin = `http://127.0.0.1:${port}`;
const dist = path.resolve('dist');
const fx = await createSshFixture();
for (const user of [fx.topo.admin, fx.topo.alice]) {
  await resetUserPassword(user.id, 'Browser-test-password-42!', fx.topo.admin.id, fx.ctx.env);
  await fx.ctx.db.prepare('UPDATE users SET mfa_enabled = 0 WHERE id = ?').bind(user.id).run();
}
const demoUser = await createUser({ username: 'd', password: '1', roles: ['Super Admin'] }, fx.topo.admin.id, { ...fx.ctx.env, DEPLOY_TYPE: 'demo' });
const demoMfa = await setupMfa(demoUser.id, fx.ctx.env);
await confirmMfa(demoUser.id, await generateTotpCode(demoMfa.secret), fx.ctx.env);
fx.ctx.env.ASSETS = { async fetch(request: Request) {
  const pathname = decodeURIComponent(new URL(request.url).pathname);
  const file = path.resolve(dist, `.${pathname === '/' ? '/index.html' : pathname}`);
  if (!file.startsWith(dist + path.sep)) return new Response('Not found', { status: 404 });
  try {
    const bytes = await readFile(file);
    const type = file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html';
    return new Response(bytes, { headers: { 'Content-Type': type } });
  } catch { return new Response('Not found', { status: 404 }); }
} } as Fetcher;

async function dispatch(req: http.IncomingMessage) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) if (value) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
  headers.set('CF-Connecting-IP', '198.51.100.9');
  const chunks: Uint8Array[] = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  // This cookie selects the demo environment only in the local browser harness.
  const demo = headers.get('Cookie')?.split(';').some((cookie) => cookie.trim() === 'edgejump_test_demo=1');
  const env = demo ? { ...fx.ctx.env, DEPLOY_TYPE: 'demo' } : fx.ctx.env;
  return worker.fetch(new Request(new URL(req.url!, origin), {
    method: req.method, headers, ...(body.length ? { body } : {}),
  }), env);
}
const server = http.createServer(async (req, res) => {
  if (req.url === '/__test/ssh-state') {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ sizes: fx.sizes, input: fx.input, connections: fx.connections }));
    return;
  }
  try {
    const response = await dispatch(req);
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => { responseHeaders[key] = value; });
    res.writeHead(response.status, responseHeaders);
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) { console.error(error); res.writeHead(500); res.end('Harness request failed'); }
});
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', async (req, socket, head) => {
  try {
    const response = await dispatch(req);
    const fallback = (response as Response & { webSocket?: WebSocket }).webSocket;
    if (response.status !== 101 || !fallback) {
      socket.end(`HTTP/1.1 ${response.status} Rejected\r\nConnection: close\r\n\r\n`);
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      let closed = false;
      ws.on('message', (data, binary) => fallback.send(binary ? new Uint8Array(data as Buffer) : data.toString()));
      fallback.addEventListener('message', (event) => { if (ws.readyState === WebSocket.OPEN) ws.send(event.data); });
      fallback.addEventListener('close', (event) => { if (!closed) { closed = true; ws.close(event.code || 1000, event.reason); } });
      ws.on('close', () => { if (!closed) { closed = true; fallback.close(); } });
      ws.on('error', () => { if (!closed) { closed = true; fallback.close(); } });
    });
  } catch (error) { console.error(error); socket.destroy(); }
});
server.listen(port, '127.0.0.1', () => console.log(`EdgeJump browser harness ready at ${origin}`));
async function stop() { for (const client of wss.clients) client.terminate(); await fx.close(); server.close(); process.exit(0); }
process.on('SIGTERM', () => void stop());
process.on('SIGINT', () => void stop());
