// Comprehensive unit tests for SSH 2.0 protocol engine in EdgeJump

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SSH_VERSION,
  isSSH2Identification,
  SSHTransport,
} from '../../src/ssh/transport.ts';
import {
  SSHPacketParser,
  SSHPacketBuilder,
  nextSequenceNumber,
} from '../../src/ssh/packet.ts';
import {
  KEXInitBuilder,
  parseKEXInit,
  negotiate,
  parseServerSigAlgs,
  filterExtInfo,
} from '../../src/ssh/kex.ts';
import { Curve25519KeyExchange } from '../../src/ssh/kex-curve25519.ts';
import { ECDHKeyExchange } from '../../src/ssh/kex-ecdh.ts';
import {
  SSHAESGCMCipher,
  SSHAESCTRCipher,
  SSHHMAC,
} from '../../src/ssh/crypto.ts';
import { KeyDerivation } from '../../src/ssh/keys.ts';
import {
  classifyHostKey,
  computeHostKeyFingerprint,
  verifyHostKeySignature,
} from '../../src/ssh/host-key.ts';
import {
  buildPasswordAuthRequest,
  buildKeyboardInteractiveAuthRequest,
  parseKeyboardInteractiveChallenge,
  passwordResponsesForChallenge,
  buildKeyboardInteractiveResponse,
  isSupportedPasswordPrompt,
} from '../../src/ssh/auth-password.ts';
import { SSHChannel } from '../../src/ssh/channel.ts';
import {
  concat,
  encodeString,
  readUint32,
  writeUint32,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
} from '../../src/ssh/utils.ts';
import {
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_USERAUTH_INFO_REQUEST,
  getCipherSpec,
  getMacSpec,
} from '../../src/ssh/types.ts';

test('transport: SSH version banner and identification parsing', () => {
  assert.equal(SSH_VERSION, 'SSH-2.0-EdgeJump_1.0');
  assert.equal(isSSH2Identification('SSH-2.0-OpenSSH_9.0'), true);
  assert.equal(isSSH2Identification('SSH-1.99-Cisco'), true);
  assert.equal(isSSH2Identification('HTTP/1.1 200 OK'), false);

  const transport = new SSHTransport();
  assert.equal(transport.getLocalVersion(), 'SSH-2.0-EdgeJump_1.0');
  const bannerBytes = transport.getLocalIdentification();
  assert.equal(new TextDecoder().decode(bannerBytes), 'SSH-2.0-EdgeJump_1.0\r\n');

  const incoming = new TextEncoder().encode('Banner: welcome to test\r\nSSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n');
  const parsed = SSHTransport.parseIdentification(incoming);
  assert.ok(parsed);
  assert.equal(parsed.version, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu');
  assert.ok(parsed.consumed > 0);
});

test('packet: unencrypted packet building and parsing', async () => {
  const payload = new Uint8Array([5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104]);
  const packet = await SSHPacketBuilder.build(payload, 8, null, 0);

  const parser = new SSHPacketParser();
  parser.feed(packet);

  const parsed = await parser.nextPacket(8, (data) => data, false, 0);
  assert.ok(parsed);
  assert.deepEqual(parsed.payload, payload);
  assert.equal(parser.getSeqNum(), 1);
});

test('packet: AES-GCM encrypted packet building and parsing', async () => {
  const key = new Uint8Array(32);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(key);
  crypto.getRandomValues(iv);

  const encryptCipher = new SSHAESGCMCipher(key, iv);
  await encryptCipher.init();
  const decryptCipher = new SSHAESGCMCipher(key, iv);
  await decryptCipher.init();

  const payload = new Uint8Array([10, 20, 30, 40, 50, 60]);
  const packet = await SSHPacketBuilder.build(
    payload,
    16,
    (data, seq, aad) => encryptCipher.encrypt(data, seq, aad),
    0,
    true
  );

  const parser = new SSHPacketParser();
  parser.feed(packet);

  const parsed = await parser.nextPacket(
    16,
    (data, seq, aad) => decryptCipher.decrypt(data, seq, aad),
    true,
    0
  );
  assert.ok(parsed);
  assert.deepEqual(parsed.payload, payload);
});

test('kex: KEXINIT building, parsing, and algorithm negotiation', () => {
  const clientKexInit = KEXInitBuilder.build();
  assert.ok(clientKexInit.length > 20);

  const parsed = parseKEXInit(clientKexInit);
  assert.ok(parsed.kexAlgorithms.includes('curve25519-sha256'));
  assert.ok(parsed.hostKeyAlgorithms.includes('ssh-ed25519'));
  assert.ok(parsed.encryptionC2S.includes('aes256-gcm@openssh.com'));

  const negotiatedKex = negotiate(parsed.kexAlgorithms, ['curve25519-sha256', 'diffie-hellman-group14-sha256']);
  assert.equal(negotiatedKex, 'curve25519-sha256');

  const filtered = filterExtInfo(['ext-info-c', 'curve25519-sha256']);
  assert.deepEqual(filtered, ['curve25519-sha256']);
});

test('kex: Curve25519 key exchange', async () => {
  const clientKeyPair = await Curve25519KeyExchange.generateKeyPair();
  const clientPub = await Curve25519KeyExchange.exportRawPublicKey(clientKeyPair);
  assert.equal(clientPub.length, 32);

  const serverKeyPair = await Curve25519KeyExchange.generateKeyPair();
  const serverPub = await Curve25519KeyExchange.exportRawPublicKey(serverKeyPair);

  const clientShared = await Curve25519KeyExchange.computeSharedSecret(clientKeyPair.privateKey, serverPub);
  const serverShared = await Curve25519KeyExchange.computeSharedSecret(serverKeyPair.privateKey, clientPub);

  assert.deepEqual(clientShared, serverShared);
});

test('kex: ECDH P-256 key exchange', async () => {
  const clientKeyPair = await ECDHKeyExchange.generateKeyPair();
  const clientPub = await ECDHKeyExchange.exportRawPublicKey(clientKeyPair);
  assert.equal(clientPub.length, 65); // uncompressed point 0x04 || X || Y

  const serverKeyPair = await ECDHKeyExchange.generateKeyPair();
  const serverPub = await ECDHKeyExchange.exportRawPublicKey(serverKeyPair);

  const clientShared = await ECDHKeyExchange.computeSharedSecret(clientKeyPair.privateKey, serverPub);
  const serverShared = await ECDHKeyExchange.computeSharedSecret(serverKeyPair.privateKey, clientPub);

  assert.deepEqual(clientShared, serverShared);
});

test('crypto and keys: Session key derivation and HMAC verification', async () => {
  const sharedK = new Uint8Array(32).fill(0x42);
  const hashH = new Uint8Array(32).fill(0x33);
  const sessionID = hashH;

  const keys = await KeyDerivation.deriveKeys(sharedK, hashH, sessionID);
  assert.equal(keys.encKeyClientToServer.length, 32);
  assert.equal(keys.encKeyServerToClient.length, 32);
  assert.equal(keys.ivClientToServer.length, 12);
  assert.equal(keys.ivServerToClient.length, 12);
  assert.equal(keys.integrityKeyC2S.length, 32);

  const hmac = new SSHHMAC('hmac-sha2-256', keys.integrityKeyC2S);
  await hmac.init();
  const packet = new Uint8Array([1, 2, 3, 4, 5]);
  const sig = await hmac.sign(packet, 0);
  assert.equal(sig.length, 32);
  const valid = await hmac.verify(packet, 0, sig);
  assert.equal(valid, true);
  const invalid = await hmac.verify(packet, 1, sig);
  assert.equal(invalid, false);
});

test('host-key: TOFU classification and fingerprint calculation', async () => {
  const mockHostKey = new Uint8Array([
    0, 0, 0, 11, ...new TextEncoder().encode('ssh-ed25519'),
    0, 0, 0, 32, ...new Uint8Array(32).fill(7),
  ]);

  const fp = await computeHostKeyFingerprint(mockHostKey);
  assert.ok(fp.startsWith('SHA256:'));

  assert.equal(classifyHostKey(undefined, fp), 'first-seen');
  assert.equal(classifyHostKey(null, fp), 'first-seen');
  assert.equal(classifyHostKey(fp, fp), 'trusted');
  assert.equal(classifyHostKey('SHA256:differentFingerprint12345678901234567890', fp), 'changed');
});

test('host-key: Ed25519 signature verification', async () => {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

  const hostKeyBlob = concat(
    encodeString('ssh-ed25519'),
    encodeString(rawPub)
  );

  const hash = new Uint8Array(32).fill(0x55);
  const rawSig = new Uint8Array(await crypto.subtle.sign('Ed25519', keyPair.privateKey, hash));

  const signatureBlob = concat(
    encodeString('ssh-ed25519'),
    encodeString(rawSig)
  );

  const verified = await verifyHostKeySignature(hostKeyBlob, signatureBlob, hash, 'ssh-ed25519');
  assert.equal(verified, true);
});

test('auth-password: password and keyboard-interactive challenge handling', () => {
  const req = buildPasswordAuthRequest('testuser', 'secret123');
  assert.equal(req[0], 50); // SSH_MSG_USERAUTH_REQUEST

  const challengePayload = concat(
    new Uint8Array([SSH_MSG_USERAUTH_INFO_REQUEST]),
    encodeString(''),
    encodeString(''),
    encodeString(''),
    new Uint8Array([0, 0, 0, 1]), // 1 prompt
    encodeString('Password: '),
    new Uint8Array([0]) // echo = false
  );

  const parsed = parseKeyboardInteractiveChallenge(challengePayload);
  assert.equal(parsed.prompts.length, 1);
  assert.equal(parsed.prompts[0].text, 'Password: ');
  assert.equal(parsed.prompts[0].echo, false);

  const responses = passwordResponsesForChallenge(parsed, 'secret123', { username: 'testuser', host: 'example.com' });
  assert.deepEqual(responses, ['secret123']);

  const responsePacket = buildKeyboardInteractiveResponse(responses);
  assert.equal(responsePacket[0], 61); // SSH_MSG_USERAUTH_INFO_RESPONSE
});

test('channel: Shell channel open, PTY request, and window resize', () => {
  const channel = new SSHChannel();
  assert.equal(channel.isOpen(), false);

  const openPacket = channel.buildOpenSession(0);
  assert.equal(openPacket[0], 90); // SSH_MSG_CHANNEL_OPEN

  // Simulate server confirmation
  const confirmPayload = new Uint8Array(17);
  confirmPayload[0] = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
  writeUint32(confirmPayload, 1, 0); // local channel ID
  writeUint32(confirmPayload, 5, 42); // remote channel ID
  writeUint32(confirmPayload, 9, 2 * 1024 * 1024); // remote window
  writeUint32(confirmPayload, 13, 32 * 1024); // max packet size

  channel.handleOpenConfirmation(confirmPayload);
  assert.equal(channel.isOpen(), true);
  assert.equal(channel.getRemoteChannelID(), 42);

  const ptyReq = channel.buildPTYRequest(120, 40, 'xterm-256color');
  assert.equal(ptyReq[0], 98); // SSH_MSG_CHANNEL_REQUEST

  const shellReq = channel.buildShellRequest();
  assert.equal(shellReq[0], 98);

  const winChange = channel.buildWindowChange(160, 50);
  assert.equal(winChange[0], 98);

  const closePacket = channel.buildClose();
  assert.equal(closePacket[0], 97); // SSH_MSG_CHANNEL_CLOSE
  assert.equal(channel.hasSentClose(), true);
});

test('utils: base64 and base64url conversions', () => {
  const data = new TextEncoder().encode('EdgeJump Bastion 2026!');
  const b64 = toBase64(data);
  assert.deepEqual(fromBase64(b64), data);

  const b64url = toBase64Url(data);
  assert.ok(!b64url.includes('+') && !b64url.includes('/') && !b64url.includes('='));
  assert.deepEqual(fromBase64Url(b64url), data);
});
