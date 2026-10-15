import { createContext, seedDemoTopology } from './compliance-helpers.ts';
import { verifyAssetHostKey } from '../src/assets/host-key-verification.ts';
// Unit and Integration Tests for Session Recording, Hash Chaining, Command Heuristics, and Durable Objects

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  compressGzip,
  decompressGzip,
  computeChunkHash,
  computeRollingHash,
  SessionRecorder,
  hexToBytes,
  bytesToHex,
  type TerminalEvent,
} from '../src/durable/recording.ts';
import { CommandHeuristicsTracker } from '../src/durable/heuristics.ts';
import { RateLimitDO } from '../src/durable/RateLimitDO.ts';
import { SSHSessionDO } from '../src/durable/SSHSessionDO.ts';
import {
  getRecordingStorage,
  R2RecordingStorage,
  S3RecordingStorage,
} from '../src/storage/recording-storage.ts';

test('recording: WebStreams CompressionStream(gzip) compresses and decompressGzip restores exact content', async () => {
  const events: TerminalEvent[] = [
    { seq: 1, t: 0, type: 'connect', cols: 80, rows: 24 },
    { seq: 2, t: 150, type: 'stdout', data: 'Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-generic x86_64)\r\n' },
    { seq: 3, t: 300, type: 'stdout', data: 'deploy@prod-bastion:~$ ' },
    { seq: 4, t: 1200, type: 'resize', cols: 140, rows: 45 },
    { seq: 5, t: 2500, type: 'disconnect', reason: 'client_closed' },
  ];

  const jsonl = events.map((e) => JSON.stringify(e)).join('\n') + '\n';
  const rawBytes = new TextEncoder().encode(jsonl);

  // Compress with WebStreams CompressionStream('gzip')
  const compressed = await compressGzip(rawBytes);

  // Verify gzip magic bytes (0x1f, 0x8b)
  assert.equal(compressed[0], 0x1f);
  assert.equal(compressed[1], 0x8b);
  assert.ok(compressed.length > 0);

  // Decompress with WebStreams DecompressionStream('gzip')
  const decompressed = await decompressGzip(compressed);
  assert.deepEqual(decompressed, rawBytes);

  // Verify JSON parsing of restored events
  const restoredLines = new TextDecoder().decode(decompressed).trim().split('\n');
  assert.equal(restoredLines.length, events.length);
  const parsedEvents = restoredLines.map((l) => JSON.parse(l));
  assert.deepEqual(parsedEvents, events);
});

test('recording: SHA-256 rolling hash chain integrity and tamper detection', async () => {
  const chunk1 = new TextEncoder().encode('{"seq":1,"t":0,"type":"connect","cols":80,"rows":24}\n');
  const chunk2 = new TextEncoder().encode('{"seq":2,"t":100,"type":"stdout","data":"uptime: up 42 days"}\n');
  const chunk3 = new TextEncoder().encode('{"seq":3,"t":200,"type":"disconnect","reason":"closed"}\n');

  const gzip1 = await compressGzip(chunk1);
  const gzip2 = await compressGzip(chunk2);
  const gzip3 = await compressGzip(chunk3);

  const hash1 = await computeChunkHash(gzip1);
  const hash2 = await computeChunkHash(gzip2);
  const hash3 = await computeChunkHash(gzip3);

  assert.equal(hash1.length, 64);
  assert.equal(hash2.length, 64);
  assert.equal(hash3.length, 64);

  // Chunk 1: first rolling hash is hash1
  const rolling1 = await computeRollingHash(null, hash1);
  assert.equal(rolling1, hash1);

  // Chunk 2: rolling2 = SHA256(rolling1 || hash2)
  const rolling2 = await computeRollingHash(rolling1, hash2);
  assert.notEqual(rolling2, rolling1);

  // Verify manual computation of rolling2
  const combinedBytes1_2 = new Uint8Array([...hexToBytes(rolling1), ...hexToBytes(hash2)]);
  const expectedRolling2 = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', combinedBytes1_2)));
  assert.equal(rolling2, expectedRolling2);

  // Chunk 3: rolling3 = SHA256(rolling2 || hash3)
  const rolling3 = await computeRollingHash(rolling2, hash3);
  const combinedBytes2_3 = new Uint8Array([...hexToBytes(rolling2), ...hexToBytes(hash3)]);
  const expectedRolling3 = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', combinedBytes2_3)));
  assert.equal(rolling3, expectedRolling3);

  // Tamper detection: if chunk 2 was tampered with, rolling hash chain changes!
  const tamperedGzip2 = new Uint8Array(gzip2);
  tamperedGzip2[tamperedGzip2.length - 1] ^= 0xff; // flip bit
  const tamperedHash2 = await computeChunkHash(tamperedGzip2);
  assert.notEqual(tamperedHash2, hash2);

  const tamperedRolling2 = await computeRollingHash(rolling1, tamperedHash2);
  const tamperedRolling3 = await computeRollingHash(tamperedRolling2, hash3);

  assert.notEqual(tamperedRolling2, rolling2);
  assert.notEqual(tamperedRolling3, rolling3);
});

test('recording: SessionRecorder buffers events, uploads chunks and manifest to R2', async () => {
  const r2Storage = new Map<string, { data: Uint8Array; metadata: any }>();
  const mockR2Bucket = {
    async put(key: string, value: Uint8Array | string, options?: any) {
      const data = typeof value === 'string' ? new TextEncoder().encode(value) : value;
      r2Storage.set(key, { data, metadata: options?.customMetadata });
    },
  };

  const sessionId = 'test-session-recording-001';
  const recorder = new SessionRecorder(sessionId, mockR2Bucket as any, 1700000000000);

  recorder.recordEvent('connect', undefined, { cols: 80, rows: 24 });
  recorder.recordEvent('stdout', 'Last login: Wed Oct 7 10:00:00 2026\r\n');
  recorder.recordEvent('resize', undefined, { cols: 120, rows: 40 });

  // Manually flush first chunk
  const chunkRes = await recorder.flushChunk();
  assert.ok(chunkRes);
  assert.equal(chunkRes.chunkIndex, 1);
  assert.ok(r2Storage.has(chunkRes.path));

  // Verify uploaded chunk in R2 can be decompressed
  const storedChunk = r2Storage.get(chunkRes.path)!;
  const decompressedChunk = await decompressGzip(storedChunk.data);
  const chunkText = new TextDecoder().decode(decompressedChunk);
  assert.ok(chunkText.includes('Last login'));
  assert.ok(chunkText.includes('connect'));

  // Close session recorder
  const manifest = await recorder.close('user_exit');
  assert.equal(manifest.sessionId, sessionId);
  assert.equal(manifest.chunkCount, 2); // 1st chunk + 2nd chunk containing disconnect
  assert.ok(manifest.firstChunkHash);
  assert.ok(manifest.finalHash);

  // Verify manifest.json in R2
  const manifestPath = `${recorder.getRecordingPrefix()}/manifest.json`;
  assert.ok(r2Storage.has(manifestPath));
  const manifestJson = JSON.parse(new TextDecoder().decode(r2Storage.get(manifestPath)!.data));
  assert.equal(manifestJson.sessionId, sessionId);
  assert.equal(manifestJson.chunkCount, 2);
  assert.equal(manifestJson.finalHash, manifest.finalHash);
});

test('recording: SessionRecorder operates gracefully as a no-op when R2 is omitted (optional R2)', async () => {
  const sessionId = 'test-session-no-r2';
  // Initialize recorder without R2 bucket
  const recorder = new SessionRecorder(sessionId, undefined, 1700000000000);

  // Recording events should not throw or buffer
  recorder.recordEvent('connect', undefined, { cols: 80, rows: 24 });
  recorder.recordEvent('stdout', 'Linux prompt$ ');
  recorder.recordEvent('resize', undefined, { cols: 100, rows: 30 });

  // Flush chunk returns null when no R2
  const chunkRes = await recorder.flushChunk();
  assert.equal(chunkRes, null);
  assert.equal(recorder.getChunkCount(), 0);

  // Close returns manifest with zero chunks and empty path
  const manifest = await recorder.close('client_closed');
  assert.equal(manifest.sessionId, sessionId);
  assert.equal(manifest.chunkCount, 0);
  assert.equal(manifest.firstChunkHash, null);
  assert.equal(manifest.finalHash, null);
  assert.equal(manifest.recordingPath, '');
});

test('storage: getRecordingStorage selects R2, S3/B2, or null based on env bindings', () => {
  // 1. Neither configured -> null
  assert.equal(getRecordingStorage({} as any), null);

  // 2. R2 configured
  const mockR2 = { put: async () => {}, get: async () => null };
  const r2Storage = getRecordingStorage({ RECORDINGS: mockR2 as any } as any);
  assert.ok(r2Storage instanceof R2RecordingStorage);

  // 3. Backblaze B2 / Generic S3 configured
  const s3Storage = getRecordingStorage({
    S3_ENDPOINT: 'https://s3.us-west-004.backblazeb2.com',
    S3_BUCKET: 'b2-test-bucket',
    S3_ACCESS_KEY_ID: '004abc123',
    S3_SECRET_ACCESS_KEY: 'K004def456',
  } as any);
  assert.ok(s3Storage instanceof S3RecordingStorage);

  // 4. Missing one of S3 fields -> null
  const incompleteS3 = getRecordingStorage({
    S3_ENDPOINT: 'https://s3.us-west-004.backblazeb2.com',
    S3_BUCKET: 'b2-test-bucket',
    // missing access keys
  } as any);
  assert.equal(incompleteS3, null);
});

test('heuristics: command line reconstruction across Enter, Backspace, Ctrl+C, Ctrl+U', () => {
  const tracker = new CommandHeuristicsTracker('test-heuristics-001');

  // 1. Basic command
  let cmds = tracker.feedStdin('ls -la\r');
  assert.equal(cmds.length, 1);
  assert.equal(cmds[0].command, 'ls -la');
  assert.equal(cmds[0].redacted, 0);

  // 2. Command with Backspace (\x7f DEL)
  cmds = tracker.feedStdin('dockre\x7f\x7fer ps\r');
  assert.equal(cmds.length, 1);
  assert.equal(cmds[0].command, 'docker ps');
  assert.equal(cmds[0].redacted, 0);

  // 3. Command with Backspace (\x08 BS)
  cmds = tracker.feedStdin('whom\x08ami\r');
  assert.equal(cmds.length, 1);
  assert.equal(cmds[0].command, 'whoami');

  // 4. Ctrl+C (\x03) aborts current line
  cmds = tracker.feedStdin('rm -rf /\x03');
  assert.equal(cmds.length, 0);
  assert.equal(tracker.getCurrentLineBuffer(), '');

  // Next command starts fresh
  cmds = tracker.feedStdin('pwd\r');
  assert.equal(cmds.length, 1);
  assert.equal(cmds[0].command, 'pwd');

  // 5. Ctrl+U (\x15) clears current line
  cmds = tracker.feedStdin('bad command line\x15systemctl status nginx\r');
  assert.equal(cmds.length, 1);
  assert.equal(cmds[0].command, 'systemctl status nginx');

  // 6. Multiple commands in one stream
  cmds = tracker.feedStdin('date\runame -a\r');
  assert.equal(cmds.length, 2);
  assert.equal(cmds[0].command, 'date');
  assert.equal(cmds[1].command, 'uname -a');
});

test('heuristics: sensitive password prompt detection and [REDACTED] redaction', () => {
  const tracker = new CommandHeuristicsTracker('test-heuristics-redact');

  // Normal command
  tracker.feedStdout('deploy@server:~$ ');
  let cmds = tracker.feedStdin('sudo apt update\r');
  assert.equal(cmds[0].command, 'sudo apt update');
  assert.equal(cmds[0].redacted, 0);

  // Sudo password prompt
  tracker.feedStdout('[sudo] password for deploy: ');
  assert.equal(tracker.isPromptSensitive(), true);

  // User types secret password
  cmds = tracker.feedStdin('MySuperSecretPassword123!\r');
  assert.equal(cmds.length, 1);
  assert.equal(cmds[0].command, '[REDACTED]');
  assert.equal(cmds[0].redacted, 1);
  assert.equal(tracker.isPromptSensitive(), false);

  // Next normal command is NOT redacted
  tracker.feedStdout('\r\nHit:1 http://archive.ubuntu.com/ubuntu noble InRelease\r\ndeploy@server:~$ ');
  cmds = tracker.feedStdin('echo done\r');
  assert.equal(cmds.length, 1);
  assert.equal(cmds[0].command, 'echo done');
  assert.equal(cmds[0].redacted, 0);

  // Passphrase prompt
  tracker.feedStdout('Enter passphrase for key /home/deploy/.ssh/id_ed25519: ');
  assert.equal(tracker.isPromptSensitive(), true);
  cmds = tracker.feedStdin('KeyPassphrase999\r');
  assert.equal(cmds[0].command, '[REDACTED]');
  assert.equal(cmds[0].redacted, 1);

  // API Token prompt
  tracker.feedStdout('Please enter your GitHub personal access token: ');
  assert.equal(tracker.isPromptSensitive(), true);
  cmds = tracker.feedStdin('ghp_abcdef1234567890\r');
  assert.equal(cmds[0].command, '[REDACTED]');
  assert.equal(cmds[0].redacted, 1);
});

test('ratelimit: RateLimitDO enforces sliding window and lockout TTL', async () => {
  const rateLimit = new RateLimitDO();
  const testIp = '198.51.100.25';
  const testUser = 'admin_user';

  // 1. Initial check - allowed
  let checkRes = await rateLimit.checkLogin(testIp, testUser, { maxAttempts: 5, windowMs: 300_000 });
  assert.equal(checkRes.allowed, true);
  assert.equal(checkRes.remaining, 5);
  assert.equal(checkRes.lockoutTtl, 0);

  // 2. 4 failed attempts - still allowed, remaining decreases
  for (let i = 1; i <= 4; i++) {
    const failRes = await rateLimit.recordLoginFailure(testIp, testUser, { maxAttempts: 5, windowMs: 300_000 });
    assert.equal(failRes.allowed, true);
    assert.equal(failRes.remaining, 5 - i);
    assert.equal(failRes.lockoutTtl, 0);
  }

  // 3. 5th failed attempt - locked out!
  const fifthFail = await rateLimit.recordLoginFailure(testIp, testUser, { maxAttempts: 5, windowMs: 300_000 });
  assert.equal(fifthFail.allowed, false);
  assert.equal(fifthFail.remaining, 0);
  assert.ok(fifthFail.lockoutTtl > 0 && fifthFail.lockoutTtl <= 300);

  // 4. Subsequent check is blocked
  checkRes = await rateLimit.checkLogin(testIp, testUser, { maxAttempts: 5, windowMs: 300_000 });
  assert.equal(checkRes.allowed, false);
  assert.equal(checkRes.remaining, 0);
  assert.ok(checkRes.lockoutTtl > 0);

  // 5. Successful login resets counter
  await rateLimit.resetLogin(testIp, testUser);
  checkRes = await rateLimit.checkLogin(testIp, testUser, { maxAttempts: 5, windowMs: 300_000 });
  assert.equal(checkRes.allowed, true);
  assert.equal(checkRes.remaining, 5);
  assert.equal(checkRes.lockoutTtl, 0);

  // 6. Test HTTP fetch interface of RateLimitDO
  const httpCheckReq = new Request('http://localhost/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: testIp, username: testUser }),
  });
  const httpCheckRes = await rateLimit.fetch(httpCheckReq);
  assert.equal(httpCheckRes.status, 200);
  const checkJson = (await httpCheckRes.json()) as any;
  assert.equal(checkJson.allowed, true);
});

test('ssh-session: SSHSessionDO HTTP endpoints (init, ticket, status, terminate)', async () => {
  const session = new SSHSessionDO(undefined, { SESSION_TICKET_SECRET: 'unit-ticket-key' } as any);

  // 1. POST /init
  const initReq = new Request('http://localhost/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionId: 'sess-unit-test-101',
      userId: 'usr_admin',
      assetId: 'ast_web_01',
      accountId: 'acc_deploy',
      host: '203.0.113.10',
      port: 22,
      username: 'deploy',
      authMethod: 'password',
      password: 'InitialPassword123',
    }),
  });
  const initRes = await session.fetch(initReq);
  assert.equal(initRes.status, 200);
  const initJson = (await initRes.json()) as any;
  assert.equal(initJson.success, true);
  assert.equal(initJson.sessionId, 'sess-unit-test-101');
  assert.equal(session.getStatus(), 'connecting');

  // 2. POST /ticket
  const ticketReq = new Request('http://localhost/ticket', { method: 'POST', headers: { 'x-user-id': 'usr_admin' } });
  const ticketRes = await session.fetch(ticketReq);
  assert.equal(ticketRes.status, 200);
  const ticketJson = (await ticketRes.json()) as any;
  assert.ok(ticketJson.ticket);
  assert.ok(ticketJson.expiresAt > Date.now());

  // 3. GET /status
  const statusReq = new Request('http://localhost/status');
  const statusRes = await session.fetch(statusReq);
  assert.equal(statusRes.status, 200);
  const statusJson = (await statusRes.json()) as any;
  assert.equal(statusJson.sessionId, 'sess-unit-test-101');
  assert.equal(statusJson.status, 'connecting');

  // 4. POST /terminate
  const termReq = new Request('http://localhost/terminate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'admin_force_close', actorId: 'usr_superadmin' }),
  });
  const termRes = await session.fetch(termReq);
  assert.equal(termRes.status, 200);
  const termJson = (await termRes.json()) as any;
  assert.equal(termJson.success, true);
  assert.equal(termJson.status, 'terminated');
  assert.equal(session.getStatus(), 'terminated');
});

test('ssh-session: SSHSessionDO correctly persists recording_status = none when R2 is omitted', async () => {
  let sessionUpdateData: any = null;
  const mockDb = {
    prepare(query: string) {
      return {
        bind(...args: any[]) {
          if (query.includes('UPDATE ssh_sessions SET')) {
            sessionUpdateData = {
              status: args[0],
              endedAt: args[1],
              reason: args[2],
              clientClosed: args[3],
              terminatedBy: args[4],
              recordingStatus: args[5],
              recordingPath: args[6],
              recordingHash: args[7],
              sessionId: args[8],
            };
          }
          return {
            async run() {},
            async first() { return null; },
            async all() { return { results: [] }; },
          };
        },
      };
    },
  };

  const session = new SSHSessionDO({} as any, { DB: mockDb as any } as any);

  const initReq = new Request('http://localhost/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionId: 'sess-no-r2-test',
      userId: 'usr_normal',
      assetId: 'ast_web_02',
      accountId: 'acc_deploy',
      host: '203.0.113.11',
      port: 22,
      username: 'deploy',
      authMethod: 'password',
      password: 'SamplePassword',
    }),
  });
  await session.fetch(initReq);

  const termReq = new Request('http://localhost/terminate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'user_exit' }),
  });
  await session.fetch(termReq);

  assert.ok(sessionUpdateData);
  assert.equal(sessionUpdateData.status, 'terminated');
  assert.equal(sessionUpdateData.recordingStatus, 'none');
  assert.equal(sessionUpdateData.recordingPath, null);
  assert.equal(sessionUpdateData.recordingHash, null);
});

test('tofu: persists first trust, blocks changes and preserves the trusted key', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'test-private-key');
    const actor = { actorUserId: topo.alice.id, sourceIp: '8.8.4.4' };
    await verifyAssetHostKey(ctx.env, topo.prodWeb01.id, 'ssh-ed25519', 'SHA256:first', 'key1', actor);
    await verifyAssetHostKey(ctx.env, topo.prodWeb01.id, 'ssh-ed25519', 'SHA256:first', 'key1', actor);
    await assert.rejects(verifyAssetHostKey(ctx.env, topo.prodWeb01.id, 'ssh-ed25519', 'SHA256:changed', 'key2', actor));
    const row = await ctx.db.prepare('SELECT * FROM ssh_host_keys WHERE asset_id = ?').bind(topo.prodWeb01.id).first<any>();
    assert.equal(row.status, 'changed'); assert.equal(row.fingerprint, 'SHA256:first');
    assert.equal(row.candidate_fingerprint, 'SHA256:changed');
  } finally { await ctx.cleanup(); }
});

test('monitor: Read-only auditor watcher receives stdout and resize, and watcher input is ignored', async () => {
  const session = new SSHSessionDO();

  // Initialize session
  await session.fetch(
    new Request('http://localhost/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sessionId: 'sess-watcher-test',
        userId: 'usr_dev',
        assetId: 'ast_web',
        accountId: 'acc_deploy',
        host: '203.0.113.10',
        port: 22,
        username: 'deploy',
        authMethod: 'password',
      }),
    })
  );

  // Connect watcher via /monitor
  const monitorRes = await session.fetch(
    new Request('http://localhost/monitor', {
      headers: { Upgrade: 'websocket' },
    })
  );
  assert.equal(monitorRes.status, 101);
  assert.equal(session.getWatchersCount(), 1);

  // Verify watcher input is discarded and does not throw or corrupt state
  const watcherWs = (monitorRes as any).webSocket;
  assert.doesNotThrow(() => {
    watcherWs.send('malicious_watcher_input_attempt');
  });

  // Test broadcast to watchers
  let receivedBroadcast = '';
  watcherWs.addEventListener('message', (event: any) => {
    receivedBroadcast = typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data);
  });

  (session as any).broadcastToWatchers('broadcast test output\r\n');
  assert.equal(receivedBroadcast, 'broadcast test output\r\n');

  await session.terminate();
});

