// SSRF Protection and Security Tests for EdgeJump

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isPrivateAddress,
  assertPublicTarget,
  createTicket,
  verifyTicket,
  toSocketHostname,
} from '../src/backend/security.ts';

test('isPrivateAddress detects RFC 1918 private IPv4 ranges', () => {
  // 10.0.0.0/8
  assert.equal(isPrivateAddress('10.0.0.1'), true);
  assert.equal(isPrivateAddress('10.254.1.5'), true);
  assert.equal(isPrivateAddress('10.255.255.255'), true);

  // 172.16.0.0/12
  assert.equal(isPrivateAddress('172.16.0.1'), true);
  assert.equal(isPrivateAddress('172.24.12.34'), true);
  assert.equal(isPrivateAddress('172.31.255.255'), true);
  // Boundary checks: 172.15.x.x and 172.32.x.x are public
  assert.equal(isPrivateAddress('172.15.255.255'), false);
  assert.equal(isPrivateAddress('172.32.0.1'), false);

  // 192.168.0.0/16
  assert.equal(isPrivateAddress('192.168.0.1'), true);
  assert.equal(isPrivateAddress('192.168.1.100'), true);
  assert.equal(isPrivateAddress('192.168.255.254'), true);
});

test('isPrivateAddress detects loopback, link-local, and special IPv4 ranges', () => {
  // 127.0.0.0/8 Loopback
  assert.equal(isPrivateAddress('127.0.0.1'), true);
  assert.equal(isPrivateAddress('127.1.2.3'), true);

  // 169.254.0.0/16 Link-Local / Cloud Metadata
  assert.equal(isPrivateAddress('169.254.169.254'), true);
  assert.equal(isPrivateAddress('169.254.1.1'), true);

  // 0.0.0.0/8 Current network
  assert.equal(isPrivateAddress('0.0.0.0'), true);

  // 100.64.0.0/10 Shared Address Space (CGNAT)
  assert.equal(isPrivateAddress('100.64.0.1'), true);
  assert.equal(isPrivateAddress('100.127.255.255'), true);

  // Multicast and reserved (>= 224)
  assert.equal(isPrivateAddress('224.0.0.1'), true);
  assert.equal(isPrivateAddress('240.0.0.1'), true);
  assert.equal(isPrivateAddress('255.255.255.255'), true);
});

test('isPrivateAddress detects IPv6 private, loopback, and local ranges', () => {
  // Loopback and unspecified
  assert.equal(isPrivateAddress('::1'), true);
  assert.equal(isPrivateAddress('[::1]'), true);
  assert.equal(isPrivateAddress('::'), true);

  // Unique Local (fc00::/7)
  assert.equal(isPrivateAddress('fc00::1'), true);
  assert.equal(isPrivateAddress('fd12:3456:789a::1'), true);

  // Link-Local (fe80::/10)
  assert.equal(isPrivateAddress('fe80::1'), true);
  assert.equal(isPrivateAddress('fea0::1'), true);

  // IPv4-mapped IPv6
  assert.equal(isPrivateAddress('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateAddress('::ffff:10.0.0.1'), true);
  assert.equal(isPrivateAddress('::ffff:192.168.1.1'), true);
  assert.equal(isPrivateAddress('::ffff:8.8.8.8'), false);
});

test('isPrivateAddress detects metadata, localhost, and internal hostnames', () => {
  assert.equal(isPrivateAddress('localhost'), true);
  assert.equal(isPrivateAddress('app.localhost'), true);
  assert.equal(isPrivateAddress('metadata.google.internal'), true);
  assert.equal(isPrivateAddress('service.internal'), true);
  assert.equal(isPrivateAddress('host.local'), true);
  assert.equal(isPrivateAddress('instance-data'), true);
});

test('isPrivateAddress allows public IP addresses', () => {
  assert.equal(isPrivateAddress('8.8.8.8'), false);
  assert.equal(isPrivateAddress('1.1.1.1'), false);
  assert.equal(isPrivateAddress('140.82.121.3'), false); // GitHub
  assert.equal(isPrivateAddress('2606:4700:4700::1111'), false); // Cloudflare DNS IPv6
});

test('assertPublicTarget rejects private targets and invalid ports', async () => {
  const privateTargets = [
    '10.0.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '127.0.0.1',
    '169.254.169.254',
    '::1',
    'metadata.google.internal',
  ];

  for (const target of privateTargets) {
    await assert.rejects(
      async () => {
        await assertPublicTarget(target, 22);
      },
      /Private and reserved SSH targets are disabled/,
      `Expected ${target} to be rejected`
    );
  }

  // Invalid ports
  await assert.rejects(async () => {
    await assertPublicTarget('8.8.8.8', 0);
  }, /Invalid port/);

  await assert.rejects(async () => {
    await assertPublicTarget('8.8.8.8', 70000);
  }, /Invalid port/);

  await assert.rejects(async () => {
    await assertPublicTarget('8.8.8.8', -1);
  }, /Invalid port/);

  // Empty host
  await assert.rejects(async () => {
    await assertPublicTarget('', 22);
  }, /Host must not be empty/);
});

test('assertPublicTarget accepts public IP addresses and bracketed IPv6', async () => {
  const resultV4 = await assertPublicTarget('8.8.8.8', 22);
  assert.deepEqual(resultV4, ['8.8.8.8']);

  const resultV6 = await assertPublicTarget('2606:4700:4700::1111', 22);
  assert.deepEqual(resultV6, ['2606:4700:4700::1111']);

  const resultBracketed = await assertPublicTarget('[2606:4700:4700::1111]', 22);
  assert.deepEqual(resultBracketed, ['2606:4700:4700::1111']);
});

test('assertPublicTarget with domain name resolving to public IP succeeds', async () => {
  const mockResolver = async (host: string, type: 'A' | 'AAAA') => {
    if (type === 'A') return ['93.184.216.34'];
    return [];
  };

  const result = await assertPublicTarget('example.com', 22, mockResolver);
  assert.deepEqual(result, ['93.184.216.34']);
});

test('assertPublicTarget with domain name resolving to private IP is blocked (DNS Rebinding)', async () => {
  const maliciousResolver = async (host: string, type: 'A' | 'AAAA') => {
    if (type === 'A') return ['169.254.169.254'];
    return [];
  };

  await assert.rejects(
    async () => {
      await assertPublicTarget('evil-rebind.com', 22, maliciousResolver);
    },
    /Target DNS resolves to a private or reserved address/
  );
});

test('toSocketHostname formats IPv6 literals properly for sockets', () => {
  assert.equal(toSocketHostname('8.8.8.8'), '8.8.8.8');
  assert.equal(toSocketHostname('example.com'), 'example.com');
  assert.equal(toSocketHostname('2606:4700:4700::1111'), '[2606:4700:4700::1111]');
  assert.equal(toSocketHostname('[2606:4700:4700::1111]'), '[2606:4700:4700::1111]');
});

test('createTicket and verifyTicket cycle correctly validates tickets', async () => {
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);

  const { ticket, expiresAt } = await createTicket(secret, '198.51.100.1', {
    sessionId: 'sess-12345',
    userId: 'user-001',
    assetId: 'asset-789',
    accountId: 'acc-456',
  });

  assert.ok(ticket.includes('.'));
  assert.ok(expiresAt > Date.now());

  // Verifies with same secret
  const valid = await verifyTicket(secret, ticket, '198.51.100.1');
  assert.equal(valid, true);

  // Fails with wrong secret
  const wrongSecret = new Uint8Array(32);
  wrongSecret.fill(1);
  const invalidSecret = await verifyTicket(wrongSecret, ticket, '198.51.100.1');
  assert.equal(invalidSecret, false);

  // Fails with tampered ticket
  const tampered = ticket.slice(0, -3) + 'abc';
  const invalidTampered = await verifyTicket(secret, tampered, '198.51.100.1');
  assert.equal(invalidTampered, false);
});
