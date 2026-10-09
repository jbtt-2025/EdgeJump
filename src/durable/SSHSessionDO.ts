// SSHSessionDO — State-holding Durable Object for individual SSH Sessions in EdgeJump

import type { Env, HostKeyStatus, SessionStatus } from '../types.ts';
import {
  SSH_VERSION,
  SSHTransport,
} from '../ssh/transport.ts';
import {
  SSHPacketParser,
  SSHPacketBuilder,
  nextSequenceNumber,
} from '../ssh/packet.ts';
import {
  KEXInitBuilder,
  parseKEXInit,
  negotiate,
  filterExtInfo,
  parseServerSigAlgs,
} from '../ssh/kex.ts';
import { Curve25519KeyExchange } from '../ssh/kex-curve25519.ts';
import { ECDHKeyExchange } from '../ssh/kex-ecdh.ts';
import {
  SSHAESGCMCipher,
  SSHAESCTRCipher,
  SSHHMAC,
} from '../ssh/crypto.ts';
import { KeyDerivation } from '../ssh/keys.ts';
import {
  computeHostKeyFingerprint,
  getHostKeyAlgorithm,
  verifyHostKeySignature,
} from '../ssh/host-key.ts';
import { SSHAuth } from '../ssh/auth.ts';
import { SSHChannel } from '../ssh/channel.ts';
import {
  concat,
  encodeString,
  toBase64,
  toBufferSource,
} from '../ssh/utils.ts';
import {
  SSH_MSG_KEXINIT,
  SSH_MSG_NEWKEYS,
  SSH_MSG_SERVICE_REQUEST,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_EXT_INFO,
  SSH_MSG_USERAUTH_SUCCESS,
  SSH_MSG_USERAUTH_INFO_REQUEST,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EXTENDED_DATA,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_DISCONNECT,
  SSH_MSG_DEBUG,
  SSH_MSG_IGNORE,
  SSH_MSG_GLOBAL_REQUEST,
  getCipherSpec,
  getMacSpec,
  normalizeTerminalSize,
  type SSHPacket,
} from '../ssh/types.ts';
import { SessionRecorder } from './recording.ts';
import { CommandHeuristicsTracker } from './heuristics.ts';
import { getRecordingStorage } from '../storage/recording-storage.ts';

export interface TCPSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): void | Promise<void>;
  closed?: Promise<void>;
}

export type SocketConnector = (address: { hostname: string; port: number }) => Promise<TCPSocket> | TCPSocket;

let globalSocketConnector: SocketConnector | null = null;

export function setCustomSocketConnector(connector: SocketConnector | null): void {
  globalSocketConnector = connector;
}

export interface SSHSessionInitConfig {
  sessionId?: string;
  userId: string;
  usernameSnapshot?: string;
  assetId: string;
  assetNameSnapshot?: string;
  accountId: string;
  accountNameSnapshot?: string;
  host: string;
  port: number;
  username: string; // SSH username on target
  authMethod: 'password' | 'publickey';
  password?: string;
  privateKey?: string;
  sourceIp?: string;
  userAgent?: string;
  cols?: number;
  rows?: number;
  term?: string;
}

// Simple fallback WebSocketPair for Node test environments
class FallbackWebSocketPair {
  0: any;
  1: any;
  constructor() {
    const listeners0: Record<string, Function[]> = {};
    const listeners1: Record<string, Function[]> = {};

    const createWs = (listeners: Record<string, Function[]>, peerListeners: Record<string, Function[]>) => ({
      accept() {},
      send(data: any) {
        for (const fn of peerListeners['message'] || []) {
          fn({ data });
        }
      },
      close(code = 1000, reason = '') {
        for (const fn of listeners['close'] || []) fn({ code, reason });
        for (const fn of peerListeners['close'] || []) fn({ code, reason });
      },
      addEventListener(event: string, fn: Function) {
        listeners[event] = listeners[event] || [];
        listeners[event].push(fn);
      },
      removeEventListener(event: string, fn: Function) {
        listeners[event] = (listeners[event] || []).filter((f) => f !== fn);
      },
    });

    this[0] = createWs(listeners0, listeners1);
    this[1] = createWs(listeners1, listeners0);
  }
}

export class SSHSessionDO {
  private readonly state?: DurableObjectState;
  private readonly env?: Env;

  private sessionId: string = '';
  private config: SSHSessionInitConfig | null = null;
  private status: SessionStatus = 'creating';
  private startedAt: number = 0;
  private isTerminated: boolean = false;
  private clientClosed: boolean = false;
  private disconnectReason: string | null = null;
  private terminatedBy: string | null = null;

  // Single-use tickets
  private readonly validTickets: Map<string, number> = new Map();

  // WebSockets
  private userWebSocket: WebSocket | null = null;
  private readonly watchers: Set<WebSocket> = new Set();

  // Subsystems
  private recorder: SessionRecorder | null = null;
  private heuristics: CommandHeuristicsTracker | null = null;

  // Timers
  private readonly idleTimeoutMs: number = 30 * 60 * 1000;      // 30 min default
  private readonly maxDurationMs: number = 8 * 60 * 60 * 1000;  // 8 hours default
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private maxDurationTimer: ReturnType<typeof setTimeout> | null = null;

  // Network / SSH Protocol State
  private socket: TCPSocket | null = null;
  private socketReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private socketWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private transport: SSHTransport = new SSHTransport();
  private parser: SSHPacketParser = new SSHPacketParser();
  private channel: SSHChannel | null = null;

  private clientSeqNum: number = 0;
  private blockSize: number = 8;
  private isAead: boolean = false;
  private macLength: number = 0;
  private encryptCipher: SSHAESGCMCipher | SSHAESCTRCipher | null = null;
  private decryptCipher: SSHAESGCMCipher | SSHAESCTRCipher | null = null;
  private hmacC2S: SSHHMAC | null = null;
  private hmacS2C: SSHHMAC | null = null;
  private serverSigAlgs: string[] | undefined;

  constructor(state?: DurableObjectState, env?: Env) {
    this.state = state;
    this.env = env;
  }

  getSessionId(): string {
    return this.sessionId;
  }

  getStatus(): SessionStatus {
    return this.status;
  }

  getWatchersCount(): number {
    return this.watchers.size;
  }

  getRecorder(): SessionRecorder | null {
    return this.recorder;
  }

  getHeuristics(): CommandHeuristicsTracker | null {
    return this.heuristics;
  }

  // --- HTTP Request Router ---
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === 'POST' && path === '/init') {
        const body = (await request.json()) as SSHSessionInitConfig;
        return await this.handleInit(body);
      }

      if (request.method === 'POST' && path === '/ticket') {
        return this.handleCreateTicket();
      }

      if (request.method === 'GET' && path === '/connect') {
        return await this.handleConnectUpgrade(request, url);
      }

      if (request.method === 'GET' && path === '/monitor') {
        return await this.handleMonitorUpgrade(request);
      }

      if (request.method === 'POST' && path === '/terminate') {
        const body = (await request.json().catch(() => ({}))) as { reason?: string; actorId?: string };
        await this.terminate(body.reason || 'terminated_by_admin', body.actorId);
        return Response.json({ success: true, status: this.status });
      }

      if (request.method === 'GET' && path === '/status') {
        return Response.json({
          sessionId: this.sessionId,
          status: this.status,
          watchersCount: this.watchers.size,
          startedAt: this.startedAt,
          disconnectReason: this.disconnectReason,
        });
      }

      return Response.json({ error: 'Endpoint not found' }, { status: 404 });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return Response.json({ error: message }, { status: 500 });
    }
  }

  // --- Admin Endpoints ---

  private async handleInit(config: SSHSessionInitConfig): Promise<Response> {
    this.config = config;
    this.sessionId = config.sessionId || (this.state?.id ? this.state.id.toString() : crypto.randomUUID());
    this.status = 'connecting';

    const storage = getRecordingStorage(this.env);
    this.recorder = new SessionRecorder(this.sessionId, storage);
    this.heuristics = new CommandHeuristicsTracker(this.sessionId, this.env?.DB);

    // Initial record in D1 ssh_sessions
    await this.persistSessionCreated();

    return Response.json({ success: true, sessionId: this.sessionId });
  }

  private handleCreateTicket(): Response {
    const ticket = crypto.randomUUID();
    const expiresAt = Date.now() + 60_000; // 60-second single-use ticket
    this.validTickets.set(ticket, expiresAt);
    return Response.json({ ticket, expiresAt });
  }

  private async handleConnectUpgrade(request: Request, url: URL): Promise<Response> {
    const ticket = url.searchParams.get('ticket');
    if (!ticket || !this.validTickets.has(ticket)) {
      return new Response('Invalid or expired ticket', { status: 403 });
    }
    const expiry = this.validTickets.get(ticket)!;
    this.validTickets.delete(ticket); // Single use
    if (Date.now() > expiry) {
      return new Response('Ticket expired', { status: 403 });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    const PairClass = typeof WebSocketPair !== 'undefined' ? WebSocketPair : FallbackWebSocketPair;
    const pair = new PairClass();
    const [clientWs, serverWs] = Object.values(pair) as [WebSocket, WebSocket];

    serverWs.accept();
    this.setupUserWebSocket(serverWs);

    // If SSH connection has not yet begun, initiate it in the background
    if (!this.socket && this.config) {
      this.startSSHConnection().catch(async (err) => {
        console.error(`[SSHSessionDO] SSH connection failed:`, err);
        const errMsg = `\r\n\x1b[31m[EdgeJump] Connection error: ${err instanceof Error ? err.message : String(err)}\x1b[0m\r\n`;
        this.userWebSocket?.send(errMsg);
        await this.handleSessionClose('failed', err instanceof Error ? err.message : String(err));
      });
    }

    return this.createWebSocketUpgradeResponse(clientWs);
  }

  private async handleMonitorUpgrade(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    const PairClass = typeof WebSocketPair !== 'undefined' ? WebSocketPair : FallbackWebSocketPair;
    const pair = new PairClass();
    const [clientWs, serverWs] = Object.values(pair) as [WebSocket, WebSocket];

    serverWs.accept();
    this.setupWatcherWebSocket(serverWs);

    return this.createWebSocketUpgradeResponse(clientWs);
  }

  private createWebSocketUpgradeResponse(clientWs: WebSocket): Response {
    try {
      return new Response(null, { status: 101, webSocket: clientWs } as ResponseInit);
    } catch {
      // In Node.js testing environments where Response restricts status to 200-599
      const resp = new Response(null, { status: 200 });
      Object.defineProperty(resp, 'status', { value: 101 });
      (resp as any).webSocket = clientWs;
      return resp;
    }
  }

  private setupUserWebSocket(ws: WebSocket): void {
    this.userWebSocket = ws;

    ws.addEventListener('message', async (event: any) => {
      this.resetIdleTimer();

      try {
        if (typeof event.data === 'string') {
          // Check for JSON control messages (e.g. resize)
          if (event.data.trim().startsWith('{')) {
            try {
              const msg = JSON.parse(event.data);
              if (msg.type === 'resize' && typeof msg.cols === 'number' && typeof msg.rows === 'number') {
                const norm = normalizeTerminalSize(msg.cols, msg.rows);
                if (norm && this.channel && this.channel.isOpen()) {
                  await this.sendPacket(this.channel.buildWindowChange(norm.cols, norm.rows));
                  this.recorder?.recordEvent('resize', undefined, { cols: norm.cols, rows: norm.rows });
                  this.broadcastToWatchers(JSON.stringify({ type: 'resize', cols: norm.cols, rows: norm.rows }));
                }
                return;
              }
              if (msg.type === 'stdin' && typeof msg.data === 'string') {
                await this.forwardTerminalInput(new TextEncoder().encode(msg.data));
                return;
              }
            } catch {
              // Not a control JSON, treat as raw text
            }
          }
          await this.forwardTerminalInput(new TextEncoder().encode(event.data));
        } else if (event.data instanceof ArrayBuffer || event.data instanceof Uint8Array) {
          const bytes = event.data instanceof Uint8Array ? event.data : new Uint8Array(event.data);
          await this.forwardTerminalInput(bytes);
        }
      } catch (err) {
        console.error('[SSHSessionDO] Error handling terminal stdin:', err);
      }
    });

    ws.addEventListener('close', async () => {
      this.clientClosed = true;
      this.userWebSocket = null;
      await this.handleSessionClose('closed', 'client_closed');
    });

    ws.addEventListener('error', async () => {
      this.clientClosed = true;
      this.userWebSocket = null;
      await this.handleSessionClose('closed', 'websocket_error');
    });
  }

  private setupWatcherWebSocket(ws: WebSocket): void {
    this.watchers.add(ws);

    // Watcher input is strictly ignored per AGENTS.md and requirements
    ws.addEventListener('message', () => {
      /* Read-only watcher input is discarded */
    });

    ws.addEventListener('close', () => {
      this.watchers.delete(ws);
    });

    ws.addEventListener('error', () => {
      this.watchers.delete(ws);
    });
  }

  private broadcastToWatchers(data: string | Uint8Array): void {
    for (const watcher of this.watchers) {
      try {
        watcher.send(data);
      } catch {
        this.watchers.delete(watcher);
      }
    }
  }

  // --- Terminal Stdin & Forwarding ---

  private async forwardTerminalInput(data: Uint8Array): Promise<void> {
    if (!this.channel || !this.channel.isOpen()) return;

    // Command heuristics tracker: reconstructs lines, detects sensitive prompts, redacts passwords
    this.heuristics?.feedStdin(data);

    // Write data to SSH shell channel in chunks respecting remote window & packet size
    let offset = 0;
    while (offset < data.length) {
      const chunk = this.channel.takeChannelDataChunk(data, offset);
      if (!chunk) {
        // Window exhausted, small yield or break
        break;
      }
      const payload = new Uint8Array(chunk.payloadLength);
      this.channel.writeChannelDataPayload(payload, 0, data, offset, chunk.bytesConsumed);
      offset += chunk.bytesConsumed;
      await this.sendPacket(payload);
    }
  }

  // --- Session Timers ---

  private resetIdleTimer(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (this.isTerminated) return;

    this.idleTimer = setTimeout(() => {
      this.handleSessionClose('timeout', 'idle_timeout').catch((err) =>
        console.error('[SSHSessionDO] Idle timeout cleanup failed:', err)
      );
    }, this.idleTimeoutMs);
  }

  private startTimers(): void {
    this.resetIdleTimer();

    if (this.maxDurationTimer) clearTimeout(this.maxDurationTimer);
    this.maxDurationTimer = setTimeout(() => {
      this.handleSessionClose('timeout', 'max_duration_timeout').catch((err) =>
        console.error('[SSHSessionDO] Max duration timeout cleanup failed:', err)
      );
    }, this.maxDurationMs);
  }

  private clearTimers(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    if (this.maxDurationTimer) {
      clearTimeout(this.maxDurationTimer);
      this.maxDurationTimer = null;
    }
  }

  // --- TCP Socket Connection ---

  private async connectSocket(host: string, port: number): Promise<TCPSocket> {
    if (globalSocketConnector) {
      return await globalSocketConnector({ hostname: host, port });
    }

    try {
      const cf = await import('cloudflare:sockets');
      return cf.connect({ hostname: host, port }) as unknown as TCPSocket;
    } catch {
      throw new Error(
        `TCP socket connection to ${host}:${port} unavailable. 'cloudflare:sockets' is only supported in Cloudflare Workers or with custom socket connector.`
      );
    }
  }

  // --- Packet Send / Receive Helpers ---

  private async readPacket(): Promise<SSHPacket> {
    if (!this.socketReader) throw new Error('TCP reader not initialized');

    while (true) {
      const packet = await this.parser.nextPacket(
        this.blockSize,
        this.decryptFn.bind(this),
        this.isAead,
        this.macLength,
        this.verifyMacFn ? this.verifyMacFn.bind(this) : undefined
      );
      if (packet) return packet;

      const { done, value } = await this.socketReader.read();
      if (done) throw new Error('SSH socket closed unexpectedly by server');
      if (value && value.length > 0) {
        this.parser.feed(value);
      }
    }
  }

  private async sendPacket(payload: Uint8Array): Promise<void> {
    if (!this.socketWriter) throw new Error('TCP writer not initialized');

    const packet = await SSHPacketBuilder.build(
      payload,
      this.blockSize,
      this.encryptFn ? this.encryptFn.bind(this) : null,
      this.clientSeqNum,
      this.isAead,
      this.macFn ? this.macFn.bind(this) : undefined
    );
    this.clientSeqNum = nextSequenceNumber(this.clientSeqNum);
    await this.socketWriter.write(packet);
  }

  private async encryptFn(data: Uint8Array, seq: number, aad?: Uint8Array): Promise<Uint8Array> {
    if (!this.encryptCipher) return data;
    return this.encryptCipher.encrypt(data, seq, aad);
  }

  private async decryptFn(data: Uint8Array, seq: number, aad?: Uint8Array, commit?: boolean): Promise<Uint8Array | null> {
    if (!this.decryptCipher) return data;
    return this.decryptCipher.decrypt(data, seq, aad, commit);
  }

  private async macFn(packet: Uint8Array, seq: number): Promise<Uint8Array> {
    if (!this.hmacC2S) throw new Error('HMAC C2S not initialized');
    return this.hmacC2S.sign(packet, seq);
  }

  private async verifyMacFn(packet: Uint8Array, mac: Uint8Array, seq: number): Promise<boolean> {
    if (!this.hmacS2C) throw new Error('HMAC S2C not initialized');
    return this.hmacS2C.verify(packet, seq, mac);
  }

  // --- SSH Handshake & Lifecycle ---

  private async startSSHConnection(): Promise<void> {
    if (!this.config) throw new Error('SSHSessionDO has not been initialized');

    const { host, port } = this.config;
    this.socket = await this.connectSocket(host, port);
    this.socketReader = this.socket.readable.getReader();
    this.socketWriter = this.socket.writable.getWriter();

    // 1. Identification Banner Exchange
    const localBanner = this.transport.getLocalIdentification();
    await this.socketWriter.write(localBanner);

    let idBuffer: Uint8Array = new Uint8Array(0);
    while (true) {
      const { done, value } = await this.socketReader.read();
      if (done) throw new Error('SSH server closed socket during identification exchange');
      if (value) {
        idBuffer = concat(idBuffer, value) as Uint8Array<ArrayBuffer>;
      }
      const parsedId = SSHTransport.parseIdentification(idBuffer);
      if (parsedId) {
        this.transport.setRemoteVersion(parsedId.version);
        if (parsedId.consumed < idBuffer.length) {
          this.parser.feed(idBuffer.subarray(parsedId.consumed));
        }
        break;
      }
    }

    // 2. KEXINIT Exchange
    const clientKexInit = KEXInitBuilder.build();
    await this.sendPacket(clientKexInit);

    const serverKexPacket = await this.readPacket();
    if (serverKexPacket.payload[0] !== SSH_MSG_KEXINIT) {
      throw new Error(`Expected KEXINIT (20), received ${serverKexPacket.payload[0]}`);
    }
    const serverKex = parseKEXInit(serverKexPacket.payload);
    const parsedClientKex = parseKEXInit(clientKexInit);

    const negotiatedKex = negotiate(filterExtInfo(parsedClientKex.kexAlgorithms), serverKex.kexAlgorithms, 'kex');
    const negotiatedHostKey = negotiate(parsedClientKex.hostKeyAlgorithms, serverKex.hostKeyAlgorithms, 'host key');
    const negotiatedCipherC2S = negotiate(parsedClientKex.encryptionC2S, serverKex.encryptionC2S, 'cipher c2s');
    const negotiatedCipherS2C = negotiate(parsedClientKex.encryptionS2C, serverKex.encryptionS2C, 'cipher s2c');
    const negotiatedMacC2S = negotiate(parsedClientKex.macC2S, serverKex.macC2S, 'mac c2s');
    const negotiatedMacS2C = negotiate(parsedClientKex.macS2C, serverKex.macS2C, 'mac s2c');

    // 3. Key Exchange (Curve25519 or ECDH P-256)
    let sharedK: Uint8Array;
    let exchangeHash: Uint8Array;
    let hostKey: Uint8Array;
    let signature: Uint8Array;

    if (negotiatedKex === 'curve25519-sha256') {
      const keyPair = await Curve25519KeyExchange.generateKeyPair();
      const clientRawPub = await Curve25519KeyExchange.exportRawPublicKey(keyPair);
      await this.sendPacket(Curve25519KeyExchange.buildInit(clientRawPub));

      const replyPacket = await this.readPacket();
      const parsedReply = Curve25519KeyExchange.parseReply(replyPacket.payload);
      hostKey = parsedReply.hostKey;
      signature = parsedReply.signature;

      sharedK = await Curve25519KeyExchange.computeSharedSecret(keyPair.privateKey, parsedReply.serverRawPublicKey);
      exchangeHash = await Curve25519KeyExchange.computeExchangeHash(
        SSH_VERSION,
        this.transport.getRemoteVersion(),
        clientKexInit,
        serverKexPacket.payload,
        hostKey,
        clientRawPub,
        parsedReply.serverRawPublicKey,
        sharedK
      );
    } else {
      const keyPair = await ECDHKeyExchange.generateKeyPair();
      const clientRawPub = await ECDHKeyExchange.exportRawPublicKey(keyPair);
      await this.sendPacket(ECDHKeyExchange.buildInit(clientRawPub));

      const replyPacket = await this.readPacket();
      const parsedReply = ECDHKeyExchange.parseReply(replyPacket.payload);
      hostKey = parsedReply.hostKey;
      signature = parsedReply.signature;

      sharedK = await ECDHKeyExchange.computeSharedSecret(keyPair.privateKey, parsedReply.serverRawPublicKey);
      exchangeHash = await ECDHKeyExchange.computeExchangeHash(
        SSH_VERSION,
        this.transport.getRemoteVersion(),
        clientKexInit,
        serverKexPacket.payload,
        hostKey,
        clientRawPub,
        parsedReply.serverRawPublicKey,
        sharedK
      );
    }

    // 4. Host Key Verification & TOFU (Trust On First Use)
    const validSig = await verifyHostKeySignature(hostKey, signature, exchangeHash, negotiatedHostKey);
    if (!validSig) {
      throw new Error('SSH host key signature verification failed');
    }

    const hostKeyFingerprint = await computeHostKeyFingerprint(hostKey);
    const hostKeyAlgo = getHostKeyAlgorithm(hostKey);
    await this.processHostKeyTOFU(hostKeyAlgo, hostKeyFingerprint, hostKey);

    // 5. NEWKEYS
    await this.sendPacket(new Uint8Array([SSH_MSG_NEWKEYS]));
    const serverNewKeys = await this.readPacket();
    if (serverNewKeys.payload[0] !== SSH_MSG_NEWKEYS) {
      throw new Error(`Expected NEWKEYS (21), received ${serverNewKeys.payload[0]}`);
    }

    // 6. Session Key Derivation and Cipher Setup
    const sessionID = exchangeHash;
    const cipherSpecC2S = getCipherSpec(negotiatedCipherC2S);
    const cipherSpecS2C = getCipherSpec(negotiatedCipherS2C);
    const macSpecC2S = getMacSpec(negotiatedMacC2S);
    const macSpecS2C = getMacSpec(negotiatedMacS2C);

    const keys = await KeyDerivation.deriveKeys(
      sharedK,
      exchangeHash,
      sessionID,
      cipherSpecC2S.ivLength,
      cipherSpecS2C.ivLength,
      macSpecC2S.keyLength,
      macSpecS2C.keyLength,
      cipherSpecC2S.keyLength,
      cipherSpecS2C.keyLength
    );

    if (cipherSpecC2S.aead) {
      const encGcm = new SSHAESGCMCipher(keys.encKeyClientToServer, keys.ivClientToServer);
      await encGcm.init();
      this.encryptCipher = encGcm;

      const decGcm = new SSHAESGCMCipher(keys.encKeyServerToClient, keys.ivServerToClient);
      await decGcm.init();
      this.decryptCipher = decGcm;

      this.blockSize = 16;
      this.isAead = true;
      this.macLength = 0;
    } else {
      const encCtr = new SSHAESCTRCipher(keys.encKeyClientToServer, keys.ivClientToServer);
      await encCtr.init();
      this.encryptCipher = encCtr;

      const decCtr = new SSHAESCTRCipher(keys.encKeyServerToClient, keys.ivServerToClient);
      await decCtr.init();
      this.decryptCipher = decCtr;

      const hmacC = new SSHHMAC(negotiatedMacC2S, keys.integrityKeyC2S);
      await hmacC.init();
      this.hmacC2S = hmacC;

      const hmacS = new SSHHMAC(negotiatedMacS2C, keys.integrityKeyS2C);
      await hmacS.init();
      this.hmacS2C = hmacS;

      this.blockSize = 16;
      this.isAead = false;
      this.macLength = hmacS.length;
    }

    // 7. Service Request (ssh-userauth)
    const serviceReq = concat(new Uint8Array([SSH_MSG_SERVICE_REQUEST]), encodeString('ssh-userauth'));
    await this.sendPacket(serviceReq);

    let serviceAccept = await this.readPacket();
    while (serviceAccept.payload[0] === SSH_MSG_EXT_INFO) {
      this.serverSigAlgs = parseServerSigAlgs(serviceAccept.payload);
      serviceAccept = await this.readPacket();
    }
    if (serviceAccept.payload[0] !== SSH_MSG_SERVICE_ACCEPT) {
      throw new Error(`Expected SERVICE_ACCEPT (6), received ${serviceAccept.payload[0]}`);
    }

    // 8. User Authentication & Credential Cleanup
    const authMethod = this.config.authMethod;
    if (authMethod === 'password') {
      const password = this.config.password || '';
      const authReq = SSHAuth.buildPasswordAuthRequest(this.config.username, password);
      await this.sendPacket(authReq);

      let authRes = await this.readPacket();
      while (authRes.payload[0] === SSH_MSG_USERAUTH_INFO_REQUEST) {
        const challenge = SSHAuth.parseKeyboardInteractiveChallenge(authRes.payload);
        const responses = SSHAuth.passwordResponsesForChallenge(challenge, password, {
          username: this.config.username,
          host: this.config.host,
        });
        const respPacket = SSHAuth.buildKeyboardInteractiveResponse(responses);
        await this.sendPacket(respPacket);
        authRes = await this.readPacket();
      }

      if (authRes.payload[0] !== SSH_MSG_USERAUTH_SUCCESS) {
        throw new Error(`Password authentication failed for SSH account ${this.config.username}`);
      }
    } else if (authMethod === 'publickey') {
      const privateKey = this.config.privateKey || '';
      const authReq = await SSHAuth.buildPublicKeyAuthRequest(
        this.config.username,
        privateKey,
        sessionID,
        this.serverSigAlgs
      );
      await this.sendPacket(authReq);

      const authRes = await this.readPacket();
      if (authRes.payload[0] !== SSH_MSG_USERAUTH_SUCCESS) {
        throw new Error(`Public key authentication failed for SSH account ${this.config.username}`);
      }
    } else {
      throw new Error(`Unsupported auth method: ${authMethod}`);
    }

    // CRITICAL: Credential cleanup immediately after userauth completes
    this.config.password = undefined;
    this.config.privateKey = undefined;

    // 9. Channel Open & PTY & Shell
    this.channel = new SSHChannel();
    const openPacket = this.channel.buildOpenSession(0);
    await this.sendPacket(openPacket);

    let chanReply = await this.readPacket();
    while (
      chanReply.payload[0] === SSH_MSG_GLOBAL_REQUEST ||
      chanReply.payload[0] === SSH_MSG_DEBUG ||
      chanReply.payload[0] === SSH_MSG_IGNORE
    ) {
      chanReply = await this.readPacket();
    }
    if (chanReply.payload[0] !== SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
      throw new Error(`Channel open failed with message ${chanReply.payload[0]}`);
    }
    this.channel.handleOpenConfirmation(chanReply.payload);

    const cols = this.config.cols || 80;
    const rows = this.config.rows || 24;
    const term = this.config.term || 'xterm-256color';

    // PTY Request
    await this.sendPacket(this.channel.buildPTYRequest(cols, rows, term));
    let ptyReply = await this.readPacket();
    if (ptyReply.payload[0] !== SSH_MSG_CHANNEL_SUCCESS) {
      console.warn('[SSHSessionDO] PTY request non-success response:', ptyReply.payload[0]);
    }

    // Shell Request
    await this.sendPacket(this.channel.buildShellRequest());
    let shellReply = await this.readPacket();
    if (shellReply.payload[0] !== SSH_MSG_CHANNEL_SUCCESS) {
      console.warn('[SSHSessionDO] Shell request non-success response:', shellReply.payload[0]);
    }

    // 10. Session Activated!
    this.status = 'active';
    this.startedAt = Date.now();

    this.recorder?.recordEvent('connect', undefined, { cols, rows });
    await this.updateSessionStatusInD1('active');
    await this.recordAuditEvent('SESSION_CONNECTED', 'ssh_session', this.sessionId, 'success');

    this.startTimers();

    // Start background receive loop from SSH server
    this.runChannelLoop().catch(async (err) => {
      console.error('[SSHSessionDO] Channel loop terminated with error:', err);
      await this.handleSessionClose('failed', err instanceof Error ? err.message : String(err));
    });
  }

  // --- SSH Receive Loop ---

  private async runChannelLoop(): Promise<void> {
    if (!this.channel) return;

    while (this.status === 'active' && !this.isTerminated) {
      const packet = await this.readPacket();
      const msgType = packet.payload[0];

      if (msgType === SSH_MSG_CHANNEL_DATA) {
        const rawStdout = this.channel.handleChannelData(packet.payload);
        this.resetIdleTimer();

        // Forward stdout to user terminal and read-only watchers
        this.userWebSocket?.send(rawStdout);
        for (const watcher of this.watchers) {
          try {
            watcher.send(rawStdout);
          } catch {
            this.watchers.delete(watcher);
          }
        }

        const text = new TextDecoder('utf-8', { fatal: false }).decode(rawStdout);
        this.recorder?.recordEvent('stdout', text);
        this.heuristics?.feedStdout(text);

        // Check if local window buffer adjustment needed
        const adjust = this.channel.takeLocalWindowAdjustment(1024 * 1024);
        if (adjust && this.channel.isOpen()) {
          await this.sendPacket(this.channel.buildWindowAdjust(adjust));
        }
      } else if (msgType === SSH_MSG_CHANNEL_EXTENDED_DATA) {
        const rawStderr = this.channel.handleExtendedData(packet.payload);
        this.resetIdleTimer();

        this.userWebSocket?.send(rawStderr);
        for (const watcher of this.watchers) {
          try {
            watcher.send(rawStderr);
          } catch {
            this.watchers.delete(watcher);
          }
        }

        const text = new TextDecoder('utf-8', { fatal: false }).decode(rawStderr);
        this.recorder?.recordEvent('stdout', text);
        this.heuristics?.feedStdout(text);
      } else if (msgType === SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        this.channel.handleWindowAdjust(packet.payload);
      } else if (msgType === SSH_MSG_CHANNEL_EOF) {
        this.channel.handleEof(packet.payload);
      } else if (msgType === SSH_MSG_CHANNEL_CLOSE) {
        this.channel.handleClose(packet.payload);
        await this.handleSessionClose('closed', 'remote_closed');
        break;
      } else if (msgType === SSH_MSG_DISCONNECT) {
        await this.handleSessionClose('closed', 'server_disconnect');
        break;
      }
      // IGNORE, DEBUG, and global requests are safely skipped
    }
  }

  // --- Host Key TOFU Handling ---

  private async processHostKeyTOFU(algorithm: string, fingerprint: string, hostKeyBlob: Uint8Array): Promise<void> {
    if (!this.env?.DB || !this.config) return;

    const assetId = this.config.assetId;
    const b64PubKey = toBase64(hostKeyBlob);

    const existing = await this.env.DB.prepare(
      `SELECT id, fingerprint, status FROM ssh_host_keys WHERE asset_id = ? AND algorithm = ?`
    )
      .bind(assetId, algorithm)
      .first<{ id: string; fingerprint: string; status: HostKeyStatus }>();

    if (!existing || existing.status === 'unverified') {
      // First connect TOFU: auto-record as verified
      const recordId = existing?.id || crypto.randomUUID();
      const now = Date.now();

      await this.env.DB.prepare(
        `INSERT INTO ssh_host_keys (id, asset_id, algorithm, fingerprint, public_key, verified_at, verified_by, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'system-tofu', 'verified', ?)
         ON CONFLICT(asset_id, algorithm) DO UPDATE SET
           fingerprint = excluded.fingerprint,
           public_key = excluded.public_key,
           verified_at = excluded.verified_at,
           verified_by = 'system-tofu',
           status = 'verified'`
      )
        .bind(recordId, assetId, algorithm, fingerprint, b64PubKey, now, now)
        .run();

      await this.env.DB.prepare(`UPDATE assets SET last_seen_host_key = ? WHERE id = ?`)
        .bind(fingerprint, assetId)
        .run();

      await this.recordAuditEvent('HOST_KEY_TRUSTED', 'ssh_host_key', recordId, 'success', {
        algorithm,
        fingerprint,
        assetId,
      });

      return;
    }

    if (existing.status === 'verified') {
      if (existing.fingerprint === fingerprint) {
        // Verified match
        return;
      }

      // Host key changed! Potential MITM
      await this.env.DB.prepare(`UPDATE ssh_host_keys SET status = 'changed' WHERE id = ?`)
        .bind(existing.id)
        .run();

      await this.recordAuditEvent('HOST_KEY_CHANGED', 'ssh_host_key', existing.id, 'failure', {
        expectedFingerprint: existing.fingerprint,
        actualFingerprint: fingerprint,
        algorithm,
        assetId,
        alert: 'Host key mismatch detected! Connection blocked.',
      });

      this.status = 'failed';
      this.disconnectReason = 'host_key_changed';
      await this.updateSessionStatusInD1('failed', 'host_key_changed');

      throw new Error(
        `Security Alert: Host key verification failed! Fingerprint changed. Expected: ${existing.fingerprint}, got: ${fingerprint}`
      );
    }

    if (existing.status === 'changed') {
      throw new Error(`Host key verification blocked: asset ${assetId} has pending changed host key status.`);
    }
  }

  // --- Session Termination & Cleanup ---

  async terminate(reason: string = 'terminated_by_admin', actorId?: string): Promise<void> {
    this.terminatedBy = actorId || null;
    await this.handleSessionClose('terminated', reason);
  }

  private async handleSessionClose(status: SessionStatus, reason: string): Promise<void> {
    if (this.isTerminated) return;
    this.isTerminated = true;
    this.status = status;
    this.disconnectReason = reason;

    this.clearTimers();

    // 1. Close channel
    if (this.channel && this.channel.isOpen() && !this.channel.hasSentClose()) {
      try {
        await this.sendPacket(this.channel.buildClose());
      } catch {
        // Socket may already be dead
      }
    }

    // 2. Close TCP socket
    try {
      this.socket?.close();
    } catch {
      // Ignored
    }

    // 3. Flush Recording and save manifest to R2 / S3 / B2 (if storage configured)
    let recordingHash: string | null = null;
    let recordingPath: string | null = null;
    const storage = getRecordingStorage(this.env);
    if (this.recorder && storage) {
      try {
        const manifest = await this.recorder.close(reason);
        recordingHash = manifest.finalHash;
        recordingPath = manifest.recordingPath || null;
      } catch (err) {
        console.error('[SSHSessionDO] Failed to close recording:', err);
      }
    }

    // 4. Close WebSockets
    if (this.userWebSocket) {
      try {
        this.userWebSocket.close(1000, reason);
      } catch {}
      this.userWebSocket = null;
    }
    for (const watcher of this.watchers) {
      try {
        watcher.close(1000, reason);
      } catch {}
    }
    this.watchers.clear();

    // 5. Update D1 ssh_sessions
    await this.finalizeSessionInD1(status, reason, recordingPath, recordingHash);

    // 6. Audit Event
    const action = status === 'terminated' ? 'SESSION_TERMINATED' : 'SESSION_CLOSED';
    await this.recordAuditEvent(action, 'ssh_session', this.sessionId, 'success', {
      reason,
      status,
      terminatedBy: this.terminatedBy,
      recordingHash,
    });
  }

  // --- D1 Persistence Helpers ---

  private async persistSessionCreated(): Promise<void> {
    if (!this.env?.DB || !this.config) return;

    const now = Date.now();
    await this.env.DB.prepare(
      `INSERT INTO ssh_sessions (
         id, user_id, username_snapshot, asset_id, asset_name_snapshot,
         account_id, account_name_snapshot, source_ip, user_agent,
         started_at, status, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'connecting', ?)`
    )
      .bind(
        this.sessionId,
        this.config.userId,
        this.config.usernameSnapshot || this.config.userId,
        this.config.assetId,
        this.config.assetNameSnapshot || this.config.host,
        this.config.accountId,
        this.config.accountNameSnapshot || this.config.username,
        this.config.sourceIp || '127.0.0.1',
        this.config.userAgent || 'EdgeJump Terminal',
        now,
        now
      )
      .run();
  }

  private async updateSessionStatusInD1(status: SessionStatus, reason?: string): Promise<void> {
    if (!this.env?.DB) return;

    await this.env.DB.prepare(
      `UPDATE ssh_sessions SET status = ?, disconnect_reason = ? WHERE id = ?`
    )
      .bind(status, reason || null, this.sessionId)
      .run();
  }

  private async finalizeSessionInD1(
    status: SessionStatus,
    reason: string,
    recordingPath: string | null,
    recordingHash: string | null
  ): Promise<void> {
    if (!this.env?.DB) return;

    const endedAt = Date.now();
    const storage = getRecordingStorage(this.env);
    const recordingStatus = (storage && recordingPath) ? 'completed' : 'none';
    await this.env.DB.prepare(
      `UPDATE ssh_sessions SET
         status = ?,
         ended_at = ?,
         disconnect_reason = ?,
         client_closed = ?,
         terminated_by = ?,
         recording_status = ?,
         recording_path = ?,
         recording_hash = ?
       WHERE id = ?`
    )
      .bind(
        status,
        endedAt,
        reason,
        this.clientClosed ? 1 : 0,
        this.terminatedBy,
        recordingStatus,
        recordingPath,
        recordingHash,
        this.sessionId
      )
      .run();
  }

  private async recordAuditEvent(
    action: string,
    resourceType: string,
    resourceId: string,
    result: 'success' | 'failure' | 'denied',
    metadata?: Record<string, unknown>
  ): Promise<void> {
    if (!this.env?.DB) return;

    const id = crypto.randomUUID();
    const now = Date.now();
    const actorId = this.terminatedBy || this.config?.userId || null;
    const actorUsername = this.config?.usernameSnapshot || 'system';

    await this.env.DB.prepare(
      `INSERT INTO audit_events (
         id, timestamp, actor_user_id, actor_username_snapshot,
         action, resource_type, resource_id, resource_name_snapshot,
         source_ip, user_agent, result, metadata_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        now,
        actorId,
        actorUsername,
        action,
        resourceType,
        resourceId,
        this.config?.assetNameSnapshot || resourceId,
        this.config?.sourceIp || '127.0.0.1',
        this.config?.userAgent || 'EdgeJump',
        result,
        metadata ? JSON.stringify(metadata) : null
      )
      .run();
  }
}
