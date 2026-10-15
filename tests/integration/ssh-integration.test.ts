import test from 'node:test';
import assert from 'node:assert/strict';
import { api } from '../compliance-helpers.ts';
import { createSshFixture, eventually } from '../ssh-fixture.ts';
import { createCredential } from '../../src/credentials/credential-service.ts';
import { updateAssetAccount } from '../../src/assets/asset-service.ts';

test('real SSH: encrypted handshake, PTY, input/output, monitor, resize, exit status and verified replay', async () => {
  const fx = await createSshFixture();
  try {
    const { ctx, topo } = fx;
    const created = await api(ctx, 'POST', '/api/sessions', { cookie: topo.alice.cookie, body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id } });
    assert.equal(created.status, 201);
    const id = created.json.sessionId;
    const upgrade = await api(ctx, 'GET', created.json.wsUrl, { cookie: topo.alice.cookie, headers: { Upgrade: 'websocket' } });
    assert.equal(upgrade.status, 101);
    const socket = upgrade.webSocket as WebSocket;
    const output: string[] = [];
    socket.addEventListener('message', (event) => output.push(typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data)));
    socket.send(JSON.stringify({ type: 'resize', cols: 117, rows: 35 }));
    await eventually(() => output.join('').includes('Welcome'), 'SSH shell output');
    assert.ok(fx.sizes.some((size) => size.cols === 117 && size.rows === 35));
    const monitor = await api(ctx, 'GET', `/api/admin/sessions/${id}/monitor`, { cookie: topo.auditor.cookie, headers: { Upgrade: 'websocket' } });
    assert.equal(monitor.status, 101);
    const watched: string[] = [];
    (monitor.webSocket as WebSocket).addEventListener('message', (event) => watched.push(typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data)));
    (monitor.webSocket as WebSocket).send('forbidden\r');
    socket.send(new TextEncoder().encode('echo hello\r') as any);
    await eventually(() => watched.join('').includes('executed: echo hello'), 'read-only monitor');
    assert.ok(!fx.input.join('').includes('forbidden'));
    socket.send(JSON.stringify({ type: 'resize', cols: 140, rows: 45 }));
    await eventually(() => fx.sizes.some((size) => size.cols === 140), 'window-change');
    socket.send(new TextEncoder().encode('exit\r') as any);
    await eventually(async () => (await ctx.db.prepare('SELECT ended_at FROM ssh_sessions WHERE id = ?').bind(id).first<any>())?.ended_at != null, 'session finalization');
    const detail = await api(ctx, 'GET', `/api/sessions/${id}`, { cookie: topo.alice.cookie });
    assert.equal(detail.json.exitCode, 7);
    assert.equal(detail.json.recordingStatus, 'completed');
    const recording = await api(ctx, 'GET', `/api/admin/sessions/${id}/recording`, { cookie: topo.auditor.cookie });
    assert.equal(recording.status, 200);
    const chunk = await api(ctx, 'GET', `/api/admin/sessions/${id}/recording/1`, { cookie: topo.auditor.cookie });
    assert.ok(chunk.json.some((event: any) => event.type === 'stdout' && event.data.includes('echo hello')));
    assert.deepEqual(fx.connections, ['8.8.8.8:22']);
    const descriptor = recording.json.manifest.chunks[0];
    const original = fx.objects.get(descriptor.path)!;
    const modified = original.slice(); modified[0] ^= 1;
    fx.objects.set(descriptor.path, modified);
    assert.equal((await api(ctx, 'GET', `/api/admin/sessions/${id}/recording/1`, { cookie: topo.auditor.cookie })).status, 400);
    fx.objects.set(descriptor.path, original);
    const manifestPath = `${recording.json.manifest.recordingPath}/manifest.json`;
    fx.objects.set(manifestPath, new TextEncoder().encode(JSON.stringify({ ...recording.json.manifest, finalHash: '0'.repeat(64) })));
    assert.equal((await api(ctx, 'GET', `/api/admin/sessions/${id}/recording`, { cookie: topo.auditor.cookie })).status, 400);
  } finally { await fx.close(); }
});

test('session closure releases TCP and browser even when D1 fails, and a retry finishes metadata and audit', async () => {
  const fx = await createSshFixture();
  const db = fx.ctx.env.DB;
  try {
    const { ctx, topo } = fx;
    const created = await api(ctx, 'POST', '/api/sessions', { cookie: topo.alice.cookie, body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id } });
    const connected = await api(ctx, 'GET', created.json.wsUrl, { cookie: topo.alice.cookie, headers: { Upgrade: 'websocket' } });
    let closed = false;
    (connected.webSocket as WebSocket).addEventListener('close', () => { closed = true; });
    await eventually(() => fx.channels.size === 1, 'shell');
    let rejected = false;
    ctx.env.DB = {
      prepare(sql: string) {
        if (!rejected && sql.includes('UPDATE ssh_sessions SET') && sql.includes('ended_at')) { rejected = true; throw new Error('Injected transient D1 failure'); }
        return db.prepare(sql);
      },
      batch: db.batch.bind(db),
    } as D1Database;
    const route = `/api/admin/sessions/${created.json.sessionId}/terminate`;
    assert.equal((await api(ctx, 'POST', route, { cookie: topo.admin.cookie })).status, 400);
    assert.ok(closed);
    await eventually(() => fx.channels.size === 0, 'TCP cleanup despite failed metadata');
    assert.equal((await api(ctx, 'POST', route, { cookie: topo.admin.cookie })).status, 200);
    const row = await db.prepare('SELECT status FROM ssh_sessions WHERE id = ?').bind(created.json.sessionId).first<any>();
    assert.equal(row.status, 'terminated');
    const audit = await db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE resource_id = ? AND action = 'SESSION_TERMINATED'").bind(created.json.sessionId).first<any>();
    assert.equal(audit.count, 1);
  } finally { fx.ctx.env.DB = db; await fx.close(); }
});

test('continuous stderr crosses the SSH receive window and remains complete in terminal, monitor and recording', async () => {
  const fx = await createSshFixture();
  try {
    const { ctx, topo } = fx;
    const created = await api(ctx, 'POST', '/api/sessions', { cookie: topo.alice.cookie, body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id } });
    const id = created.json.sessionId;
    const connected = await api(ctx, 'GET', created.json.wsUrl, { cookie: topo.alice.cookie, headers: { Upgrade: 'websocket' } });
    const output: string[] = [];
    (connected.webSocket as WebSocket).addEventListener('message', (event) => { if (typeof event.data !== 'string') output.push(new TextDecoder().decode(event.data)); });
    await eventually(() => output.join('').includes('Welcome'), 'shell');
    const monitor = await api(ctx, 'GET', `/api/admin/sessions/${id}/monitor`, { cookie: topo.auditor.cookie, headers: { Upgrade: 'websocket' } });
    const watched: string[] = [];
    (monitor.webSocket as WebSocket).addEventListener('message', (event) => { if (typeof event.data !== 'string') watched.push(new TextDecoder().decode(event.data)); });
    const channel = [...fx.channels][0];
    const initialOutput = output.join('');
    const payload = 'E'.repeat(3 * 1024 * 1024) + '\r\nEND-OF-LARGE-STDERR\r\n';
    channel.stderr.write(payload);
    await eventually(() => watched.join('').includes('END-OF-LARGE-STDERR'), 'stderr beyond initial SSH receive window', 10_000);
    assert.equal(output.join(''), initialOutput + payload);
    assert.equal(watched.join(''), payload);
    await api(ctx, 'POST', `/api/sessions/${id}/disconnect`, { cookie: topo.alice.cookie });
    const recording = await api(ctx, 'GET', `/api/admin/sessions/${id}/recording`, { cookie: topo.auditor.cookie });
    assert.equal(recording.status, 200);
    let replay = '';
    for (let index = 1; index <= recording.json.manifest.chunkCount; index++) {
      const chunk = await api(ctx, 'GET', `/api/admin/sessions/${id}/recording/${index}`, { cookie: topo.auditor.cookie });
      assert.equal(chunk.status, 200);
      replay += chunk.json.filter((event: any) => event.type === 'stdout').map((event: any) => event.data).join('');
    }
    assert.ok(replay.endsWith(payload));
  } finally { await fx.close(); }
});

for (const scenario of ['wrong password', 'invalid private key', 'connection timeout', 'malformed packet'] as const) {
  test(`real SSH rejects ${scenario}, closes the browser and audits failure`, async () => {
    const fx = await createSshFixture({ password: scenario === 'wrong password' ? 'wrong-password' : undefined,
      hang: scenario === 'connection timeout', malformed: scenario === 'malformed packet' });
    try {
      const { ctx, topo } = fx;
      ctx.env.CONNECT_TIMEOUT_MS = scenario === 'connection timeout' ? '300' : '2000';
      if (scenario === 'invalid private key') {
        const credential = await createCredential({ name: 'invalid key', type: 'private_key', secret: 'invalid-private-key' }, ctx.kek, ctx.db);
        await updateAssetAccount(topo.deploy.id, { credentialId: credential.id }, ctx.db);
      }
      const created = await api(ctx, 'POST', '/api/sessions', { cookie: topo.alice.cookie, body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id } });
      assert.equal(created.status, 201);
      const response = await api(ctx, 'GET', created.json.wsUrl, { cookie: topo.alice.cookie, headers: { Upgrade: 'websocket' } });
      let closed = false;
      (response.webSocket as WebSocket).addEventListener('close', () => { closed = true; });
      await eventually(async () => !!await ctx.db.prepare("SELECT id FROM audit_events WHERE resource_id = ? AND action = 'SESSION_FAILED'")
        .bind(created.json.sessionId).first(), 'failure audit');
      const row = await ctx.db.prepare('SELECT * FROM ssh_sessions WHERE id = ?').bind(created.json.sessionId).first<any>();
      assert.equal(row.status, 'failed');
      assert.ok(row.ended_at);
      assert.ok(closed);
      if (scenario === 'connection timeout') assert.equal(row.disconnect_reason, 'connection_timeout');
      else assert.notEqual(row.disconnect_reason, 'connection_timeout');
      const instance = ctx.sessions.instances.get(ctx.sessions.idFromName(created.json.sessionId).toString()) as any;
      assert.equal(instance.config.password, undefined);
      assert.equal(instance.config.privateKey, undefined);
    } finally { await fx.close(); }
  });
}

test('real SSH termination closes all sockets; recording storage is optional', async () => {
  const fx = await createSshFixture({ storage: false });
  try {
    const { ctx, topo } = fx;
    const created = await api(ctx, 'POST', '/api/sessions', { cookie: topo.alice.cookie, body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id } });
    const connected = await api(ctx, 'GET', created.json.wsUrl, { cookie: topo.alice.cookie, headers: { Upgrade: 'websocket' } });
    let closed = false;
    (connected.webSocket as WebSocket).addEventListener('close', () => { closed = true; });
    await eventually(() => fx.channels.size === 1, 'shell');
    const terminated = await api(ctx, 'POST', `/api/admin/sessions/${created.json.sessionId}/terminate`, { cookie: topo.admin.cookie, body: { reason: 'test termination' } });
    assert.equal(terminated.status, 200);
    assert.ok(closed);
    await eventually(() => fx.channels.size === 0, 'TCP shutdown');
    const row = await ctx.db.prepare('SELECT status, recording_status, terminated_by FROM ssh_sessions WHERE id = ?').bind(created.json.sessionId).first<any>();
    assert.deepEqual({ ...row }, { status: 'terminated', recording_status: 'none', terminated_by: topo.admin.id });
  } finally { await fx.close(); }
});
