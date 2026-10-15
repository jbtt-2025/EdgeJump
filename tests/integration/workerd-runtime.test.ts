import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pbkdf2Sync } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { build } from 'esbuild';
import { parse } from 'smol-toml';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('workerd runs the internal 600k KDF and serves secure SPA assets without invoking the Worker', { timeout: 60_000 }, async () => {
  const config = parse(await readFile('wrangler.toml', 'utf8')) as any;
  const root = await mkdtemp(path.join(tmpdir(), 'edgejump-runtime-'));
  let mf: Miniflare | undefined;
  try {
    await Promise.all([
      writeFile(path.join(root, 'index.html'), '<!doctype html><title>Runtime fixture</title>'),
      writeFile(path.join(root, 'app.js'), 'export const fixture = true;'),
      writeFile(path.join(root, '_headers'), await readFile('frontend/public/_headers', 'utf8')),
    ]);
    const bundle = await build({
      stdin: { contents: `
        import application from './src/worker.ts';
        import { hashUserPassword, verifyUserPassword } from './src/auth/password-service.ts';
        export { SSHSessionDO, RateLimitDO, PasswordKdfDO } from './src/worker.ts';
        export default { async fetch(request, env) {
          let response;
          if (new URL(request.url).pathname === '/api/kdf-smoke') {
            const { password, legacyHash, salt } = await request.json();
            const record = await hashUserPassword('smoke-user', password, env);
            response = Response.json({ record,
              correct: await verifyUserPassword('smoke-user', password, record.hash, record.salt, record.iterations, env),
              wrong: await verifyUserPassword('smoke-user', 'wrong', record.hash, record.salt, record.iterations, env),
              legacy: await verifyUserPassword('smoke-user', password, legacyHash, salt, 600000, env),
            });
          } else response = await application.fetch(request, env);
          const headers = new Headers(response.headers); headers.set('x-smoke-worker', 'invoked');
          return new Response(response.body, {status: response.status, headers});
        } };
      `, resolveDir: process.cwd(), sourcefile: 'runtime-smoke.ts', loader: 'ts' },
      bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:sockets'],
    });
    mf = new Miniflare(convertV4MiniflareOptions({
      modules: true, compatibilityDate: config.compatibility_date, script: bundle.outputFiles[0].text,
      bindings: { AUTH_PEPPER: 'runtime-test-pepper' },
      durableObjects: { PASSWORD_KDF: { className: 'PasswordKdfDO', useSQLite: true } },
      assets: { directory: root, binding: 'ASSETS', run_worker_first: config.assets.run_worker_first,
        routerConfig: { has_user_worker: true },
        assetConfig: { not_found_handling: config.assets.not_found_handling } },
    }));
    for (const assetPath of ['/', '/app.js', '/terminal/example-session']) {
      const response = await mf.dispatchFetch(`http://localhost${assetPath}`);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('x-smoke-worker'), null, assetPath);
      assert.equal(response.headers.get('x-frame-options'), 'DENY');
      assert.match(response.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.match(response.headers.get('strict-transport-security')!, /max-age=31536000/);
      await response.text();
    }
    for (const apiPath of ['/api', '/api/not-a-real-endpoint']) {
      const response = await mf.dispatchFetch(`http://localhost${apiPath}`, { headers: { 'Sec-Fetch-Mode': 'navigate', Accept: 'text/html' } });
      assert.equal(response.headers.get('x-smoke-worker'), 'invoked');
      assert.match(response.headers.get('content-type')!, /application\/json/);
      assert.equal(response.status, 401);
      await response.text();
    }
    const password = 'Runtime-test-password!';
    const salt = '00112233445566778899aabbccddeeff';
    const legacyHash = Buffer.from(pbkdf2Sync(password + 'runtime-test-pepper', Buffer.from(salt, 'hex'), 600_000, 32, 'sha256')).toString('hex');
    const response = await mf.dispatchFetch('http://localhost/api/kdf-smoke', { method: 'POST', body: JSON.stringify({ password, legacyHash, salt }) });
    assert.equal(response.status, 200);
    const result = await response.json() as any;
    assert.equal(result.correct, true);
    assert.equal(result.wrong, false);
    assert.equal(result.legacy, true);
    assert.equal(result.record.iterations, 600_000);
    assert.equal(result.record.hash, Buffer.from(pbkdf2Sync(password + 'runtime-test-pepper', Buffer.from(result.record.salt, 'hex'), 600_000, 32, 'sha256')).toString('hex'));
  } finally {
    await mf?.dispose();
    assert.ok(path.resolve(root).startsWith(path.resolve(tmpdir()) + path.sep));
    await rm(root, { recursive: true, force: true });
  }
});
