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
  readUint32,
  writeUint32,
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
  SSH_MSG_REQUEST_FAILURE,
  SSH_MSG_REQUEST_SUCCESS,
  SSH_MSG_CHANNEL_REQUEST,
  getCipherSpec,
  getMacSpec,
  normalizeTerminalSize,
  type SSHPacket,
} from '../ssh/types.ts';
import { SessionRecorder } from './recording.ts';
import { CommandHeuristicsTracker } from './heuristics.ts';
import { getRecordingStorage } from '../storage/recording-storage.ts';
import { assertPublicTarget, toSocketHostname, createTicket, verifyTicket } from '../backend/security.ts';
import { verifyAssetHostKey } from '../assets/host-key-verification.ts';
import { checkUserAssetAccountAccess } from '../authorization/authorization-service.ts';
import { getSessionCredential } from '../credentials/credential-service.ts';
import { getAllSettings } from '../settings/settings-service.ts';
import { recordAuditEvent as writeAuditEvent } from '../audit/audit-service.ts';
import { logError } from '../logging.ts';

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
  authMethod?: 'password' | 'publickey';
  password?: string;
  privateKey?: string;
  sourceIp?: string;
  userAgent?: string;
  cols?: number;
  rows?: number;
  term?: string;
  ticket?: string;
  expiresAt?: number;
  createdAt?: number;
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
  private terminationActor: { username?: string; sourceIp?: string; userAgent?: string | null } = {};
  private createdAt = Date.now();
  private lastActivityAt = Date.now();
  private disconnectOnBrowserClose = true;
  private connectionStarted = false;
  private restoring: Promise<void> | null = null;
  private closing: Promise<void> | null = null;
  private closeAudited = false;
  private endedAt: number | null = null;
  private exitCode: number | null = null;
  private exitSignal: string | null = null;
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private keepaliveOutstanding = 0;
  private readonly outputDecoder = new TextDecoder();
  private transferTails: Record<string, string> = {};

  // Single-use tickets
  private readonly validTickets: Map<string, number> = new Map();
  private readonly consumedTickets = new Set<string>();
  private sendQueue: Promise<void> = Promise.resolve();
  private pendingInput = new Uint8Array(0);
  private inputQueue: Promise<void> = Promise.resolve();
  private sendBlockSize = 8;
  private sendAead = false;

  // WebSockets
  private userWebSocket: WebSocket | null = null;
  private readonly watchers: Set<WebSocket> = new Set();

  // Subsystems
  private recorder: SessionRecorder | null = null;
  private heuristics: CommandHeuristicsTracker | null = null;

  // Timers
  private idleTimeoutMs: number = 30 * 60 * 1000;
  private maxDurationMs: number = 8 * 60 * 60 * 1000;
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
      if (!this.config && this.state?.storage) {
        this.restoring ??= this.restoreSession();
        try { await this.restoring; } finally { this.restoring = null; }
      }
      if (request.method === 'POST' && path === '/init') {
        const body = (await request.json()) as SSHSessionInitConfig;
        return await this.handleInit(body);
      }

      if (request.method === 'POST' && path === '/ticket') {
        return await this.handleCreateTicket(request);
      }

      if (request.method === 'GET' && path === '/connect') {
        return await this.handleConnectUpgrade(request, url);
      }

      if (request.method === 'GET' && path === '/monitor') {
        return await this.handleMonitorUpgrade(request);
      }

      if (request.method === 'POST' && path === '/terminate') {
        const body = await request.json<any>();
        this.terminationActor = { username: body.actorUsername, sourceIp: body.sourceIp, userAgent: body.userAgent };
        this.clientClosed = body.clientClosed === true;
        if (this.clientClosed) await this.handleSessionClose('closed', 'client_disconnected');
        else await this.terminate(body.reason || 'terminated_by_admin', body.actorId);
        return Response.json({ success: true, status: this.status });
      }

      if (request.method === 'GET' && path === '/status') {
        return Response.json({
          sessionId: this.sessionId,
          status: this.status,
          watchersCount: this.watchers.size,
          startedAt: this.startedAt,
          createdAt: this.createdAt,
          lastActivityAt: this.lastActivityAt,
          pty: { cols: this.config?.cols ?? 80, rows: this.config?.rows ?? 24, term: this.config?.term ?? 'xterm-256color' },
          disconnectReason: this.disconnectReason,
        });
      }

      return Response.json({ error: 'Endpoint not found' }, { status: 404 });
    } catch (err: unknown) {
      logError('session_request_failed', err);
      return Response.json({ error: 'Session operation failed' }, { status: 500 });
    }
  }

  // --- Admin Endpoints ---

  private async restoreSession(): Promise<void> {
    const saved = await this.state?.storage.get<SSHSessionInitConfig>('config');
    if (!saved || this.config) return;
    const row = await this.env?.DB.prepare('SELECT status FROM ssh_sessions WHERE id = ?')
      .bind(saved.sessionId).first<{ status: SessionStatus }>();
    if (!row) throw new Error('Session metadata is unavailable');
    this.config = saved;
    this.sessionId = saved.sessionId!;
    this.createdAt = saved.createdAt ?? Date.now();
    this.status = row.status;
    if (!['creating', 'connecting', 'active'].includes(row.status)) {
      this.isTerminated = true;
      this.closeAudited = true;
      return;
    }
    // TCP and SSH cipher state cannot survive an isolate restart. Never reconnect
    // an old session or overwrite its existing recording chunks.
    if (row.status === 'active' || await this.state?.storage.get('connectionStarted')) {
      await this.handleSessionClose('failed', 'runtime_restarted');
      return;
    }
    await this.loadSessionSettings();
    this.recorder = new SessionRecorder(this.sessionId, getRecordingStorage(this.env), this.createdAt);
    this.heuristics = new CommandHeuristicsTracker(this.sessionId, this.env?.DB);
    this.startTimers();
  }

  private async handleInit(config: SSHSessionInitConfig): Promise<Response> {
    if (this.config) return Response.json({ error: 'Session already initialized' }, { status: 409 });
    if (!config.sessionId || !config.userId || !config.assetId || !config.accountId || !config.host) {
      return Response.json({ error: 'Invalid session initialization' }, { status: 400 });
    }
    this.config = config;
    this.sessionId = config.sessionId || (this.state?.id ? this.state.id.toString() : crypto.randomUUID());
    this.status = 'connecting';
    this.createdAt = config.createdAt ?? Date.now();
    this.lastActivityAt = this.createdAt;
    await this.loadSessionSettings();

    const storage = getRecordingStorage(this.env);
    this.recorder = new SessionRecorder(this.sessionId, storage);
    this.heuristics = new CommandHeuristicsTracker(this.sessionId, this.env?.DB);

    // The Worker owns creation; the DO updates the same metadata record.
    await this.persistSessionCreated();
    const { password, privateKey, ticket, expiresAt, ...metadata } = config;
    await this.state?.storage?.put('config', metadata);
    if (ticket && expiresAt) await this.registerTicket(ticket, expiresAt);
    this.config.ticket = undefined;
    this.startTimers();

    return Response.json({ success: true, sessionId: this.sessionId });
  }

  private async loadSessionSettings(): Promise<void> {
    if (!this.env?.DB) return;
    const settings = await getAllSettings(this.env.DB);
    this.idleTimeoutMs = Number(settings.session_idle_timeout) * 1000;
    this.maxDurationMs = Number(settings.session_max_duration) * 1000;
    this.disconnectOnBrowserClose = settings.disconnect_on_browser_close !== 'false';
  }

  private async registerTicket(ticket: string, expiresAt: number): Promise<void> {
    this.validTickets.set(ticket, expiresAt);
    await this.state?.storage?.put(`ticket:${ticket}`, expiresAt);
  }

  private async handleCreateTicket(request: Request): Promise<Response> {
    if (!this.config || this.isTerminated || request.headers.get('x-user-id') !== this.config.userId || !this.env?.SESSION_TICKET_SECRET) {
      return new Response('Permission denied', { status: 403 });
    }
    const { ticket, expiresAt } = await createTicket(new TextEncoder().encode(this.env.SESSION_TICKET_SECRET), '', {
      sessionId: this.sessionId, userId: this.config.userId, assetId: this.config.assetId, accountId: this.config.accountId,
    });
    await this.registerTicket(ticket, expiresAt);
    return Response.json({ ticket, expiresAt });
  }

  private async handleConnectUpgrade(request: Request, url: URL): Promise<Response> {
    const ticket = request.headers.get('x-session-ticket') ?? url.searchParams.get('ticket');
    if (!this.config || this.isTerminated || this.userWebSocket || request.headers.get('x-user-id') !== this.config.userId ||
      !ticket || !this.env?.SESSION_TICKET_SECRET ||
      !await verifyTicket(new TextEncoder().encode(this.env.SESSION_TICKET_SECRET), ticket)) {
      return new Response('Invalid or expired ticket', { status: 403 });
    }
    const expiry = this.validTickets.get(ticket) ?? await this.state?.storage?.get<number>(`ticket:${ticket}`);
    if (!expiry || Date.now() >= expiry || this.consumedTickets.has(ticket)) {
      return new Response('Ticket expired', { status: 403 });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }
    // Consume before creating the socket and before any further await.
    this.consumedTickets.add(ticket);
    this.validTickets.delete(ticket);
    await this.state?.storage?.delete(`ticket:${ticket}`);

    const PairClass = typeof WebSocketPair !== 'undefined' ? WebSocketPair : FallbackWebSocketPair;
    const pair = new PairClass();
    const [clientWs, serverWs] = Object.values(pair) as [WebSocket, WebSocket];

    serverWs.accept();
    this.setupUserWebSocket(serverWs);
    if (this.status === 'active') serverWs.send(JSON.stringify({ type: 'status', status: 'active' }));

    // If SSH connection has not yet begun, initiate it in the background
    if (!this.connectionStarted && this.config) {
      this.connectionStarted = true;
      const connecting = this.startSSHConnection().catch(async (err) => {
        if (this.isTerminated) return;
        logError('ssh_connection_failed', err);
        const errMsg = '\r\n[EdgeJump] SSH connection failed. Contact your administrator.\r\n';
        try { this.userWebSocket?.send(errMsg); } catch {}
        await this.handleSessionClose('failed', 'ssh_connection_failed');
      }).catch((error) => logError('session_finalization_failed', error));
      this.state?.waitUntil?.(connecting);
    }

    return this.createWebSocketUpgradeResponse(clientWs);
  }

  private async handleMonitorUpgrade(request: Request): Promise<Response> {
    if (!this.config || this.isTerminated) return new Response('Session is offline', { status: 409 });
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
                if (norm && this.config) {
                  this.config!.cols = norm.cols;
                  this.config!.rows = norm.rows;
                  if (this.channel?.isOpen()) await this.sendPacket(this.channel.buildWindowChange(norm.cols, norm.rows));
                  await this.recorder?.recordEvent('resize', undefined, { cols: norm.cols, rows: norm.rows });
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
        logError('[SSHSessionDO] Error handling terminal stdin:', err);
      }
    });

    ws.addEventListener('close', async () => {
      this.clientClosed = true;
      this.userWebSocket = null;
      if (this.disconnectOnBrowserClose) await this.handleSessionClose('closed', 'client_closed')
        .catch((error) => logError('client_close_finalization_failed', error));
    });

    ws.addEventListener('error', async () => {
      this.clientClosed = true;
      this.userWebSocket = null;
      if (this.disconnectOnBrowserClose) await this.handleSessionClose('closed', 'websocket_error')
        .catch((error) => logError('websocket_error_finalization_failed', error));
    });
  }

  private setupWatcherWebSocket(ws: WebSocket): void {
    this.watchers.add(ws);
    ws.send(JSON.stringify({ type: 'resize', cols: this.config?.cols ?? 80, rows: this.config?.rows ?? 24 }));

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
    if (await this.rejectFileTransfer(data, 'upload')) return;

    // Command heuristics tracker: reconstructs lines, detects sensitive prompts, redacts passwords
    this.heuristics?.feedStdin(data);

    this.pendingInput = concat(this.pendingInput, data) as Uint8Array<ArrayBuffer>;
    if (this.pendingInput.length > 1024 * 1024) throw new Error('Terminal input buffer exceeded');
    await this.flushTerminalInput();
  }

  private async flushTerminalInput(): Promise<void> {
    const task = this.inputQueue.then(async () => {
    if (!this.channel?.isOpen()) return;
    const data = this.pendingInput;
    this.pendingInput = new Uint8Array(0);
    let offset = 0;
    while (offset < data.length) {
      const chunk = this.channel.takeChannelDataChunk(data, offset);
      if (!chunk) {
        break;
      }
      const payload = new Uint8Array(chunk.payloadLength);
      this.channel.writeChannelDataPayload(payload, 0, data, offset, chunk.bytesConsumed);
      offset += chunk.bytesConsumed;
      await this.sendPacket(payload);
    }
    this.pendingInput = concat(data.subarray(offset), this.pendingInput) as Uint8Array<ArrayBuffer>;
    });
    this.inputQueue = task.catch(() => {});
    await task;
  }

  private async rejectFileTransfer(data: Uint8Array, direction: string): Promise<boolean> {
    const text = (this.transferTails[direction] ?? '') + new TextDecoder('latin1').decode(data);
    this.transferTails[direction] = text.slice(-8);
    if (!/\x18[ABC]/.test(text)) return false;
    await this.recordAuditEvent('FILE_TRANSFER_DENIED', 'session', this.sessionId, 'denied', {
      assetId: this.config?.assetId, accountId: this.config?.accountId, direction,
      path: null, size: data.length, reason: 'file_transfer_disabled',
    });
    await this.handleSessionClose('closed', 'file_transfer_disabled');
    return true;
  }

  // --- Session Timers ---

  private resetIdleTimer(): void {
    this.lastActivityAt = Date.now();
    // Traffic only updates a timestamp. Re-arm once when the existing deadline fires.
    if (this.idleTimer || this.isTerminated) return;
    this.scheduleIdleCheck(this.idleTimeoutMs);
  }

  private scheduleIdleCheck(delayMs: number): void {
    this.idleTimer = setTimeout(() => {
      this.idleTimer = null;
      if (this.isTerminated) return;
      const remaining = this.lastActivityAt + this.idleTimeoutMs - Date.now();
      if (remaining > 0) this.scheduleIdleCheck(remaining);
      else this.handleSessionClose('timeout', 'idle_timeout').catch((err) =>
        logError('[SSHSessionDO] Idle timeout cleanup failed:', err)
      );
    }, Math.max(1, delayMs));
    (this.idleTimer as any).unref?.();
  }

  private startTimers(): void {
    this.resetIdleTimer();

    if (this.maxDurationTimer) clearTimeout(this.maxDurationTimer);
    this.maxDurationTimer = setTimeout(() => {
      this.handleSessionClose('timeout', 'max_duration_timeout').catch((err) =>
        logError('[SSHSessionDO] Max duration timeout cleanup failed:', err)
      );
    }, Math.max(1, this.maxDurationMs - (Date.now() - this.createdAt)));
    (this.maxDurationTimer as any).unref?.();
  }

  private clearTimers(): void {
    if (this.handshakeTimer) clearTimeout(this.handshakeTimer);
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
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
    const task = this.sendQueue.then(() => this.writePacket(payload));
    this.sendQueue = task.catch(() => {});
    return task;
  }

  private async writePacket(payload: Uint8Array): Promise<void> {
    if (!this.socketWriter) throw new Error('TCP writer not initialized');

    const packet = await SSHPacketBuilder.build(
      payload,
      this.sendBlockSize,
      this.encryptCipher ? this.encryptFn.bind(this) : null,
      this.clientSeqNum,
      this.sendAead,
      this.hmacC2S ? this.macFn.bind(this) : undefined
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
    await this.state?.storage?.put('connectionStarted', true);
    const timeout = Number(this.env?.CONNECT_TIMEOUT_MS || 30_000);
    this.handshakeTimer = setTimeout(() => {
      void this.handleSessionClose('failed', 'connection_timeout').catch((err) => logError('connection_timeout_cleanup', err));
    }, timeout);
    (this.handshakeTimer as any).unref?.();
    try {
      await this.establishSSHConnection();
    } finally {
      if (this.handshakeTimer) clearTimeout(this.handshakeTimer);
      if (this.config) { this.config.password = undefined; this.config.privateKey = undefined; }
    }
  }

  private async establishSSHConnection(): Promise<void> {
    if (!this.config) throw new Error('SSHSessionDO has not been initialized');

    const { host, port } = this.config;
    const [address] = await assertPublicTarget(host, port);
    if (this.isTerminated) return;
    this.socket = await this.connectSocket(toSocketHostname(address), port);
    if (this.isTerminated) { await this.socket.close(); return; }
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

    } else {
      const encCtr = new SSHAESCTRCipher(keys.encKeyClientToServer, keys.ivClientToServer);
      await encCtr.init();
      this.encryptCipher = encCtr;

      const hmacC = new SSHHMAC(negotiatedMacC2S, keys.integrityKeyC2S);
      await hmacC.init();
      this.hmacC2S = hmacC;

    }
    if (cipherSpecS2C.aead) {
      const decGcm = new SSHAESGCMCipher(keys.encKeyServerToClient, keys.ivServerToClient);
      await decGcm.init();
      this.decryptCipher = decGcm;
    } else {
      const decCtr = new SSHAESCTRCipher(keys.encKeyServerToClient, keys.ivServerToClient);
      await decCtr.init();
      this.decryptCipher = decCtr;
      const hmacS = new SSHHMAC(negotiatedMacS2C, keys.integrityKeyS2C);
      await hmacS.init();
      this.hmacS2C = hmacS;

      this.macLength = hmacS.length;
    }
    this.sendBlockSize = cipherSpecC2S.blockSize;
    this.sendAead = cipherSpecC2S.aead;
    this.blockSize = cipherSpecS2C.blockSize;
    this.isAead = cipherSpecS2C.aead;

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
    if (this.isTerminated) return;
    if (this.env?.DB) {
      const access = await checkUserAssetAccountAccess(this.config.userId, this.config.assetId, this.config.accountId, 'connect', this.env.DB);
      if (!access.authorized) throw new Error('Access denied before SSH authentication');
      const account = await this.env.DB.prepare('SELECT credential_id FROM asset_accounts WHERE id = ?').bind(this.config.accountId)
        .first<{ credential_id: string }>();
      if (!account) throw new Error('Account not found');
      const credential = await getSessionCredential(account.credential_id, this.env);
      this.config.authMethod = credential.type === 'password' ? 'password' : 'publickey';
      if (credential.type === 'password') this.config.password = credential.plaintext;
      else this.config.privateKey = credential.plaintext;
      credential.plaintext = '';
    }
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
    if (this.isTerminated) return;
    this.status = 'active';
    this.startedAt = Date.now();

    await this.recorder?.recordEvent('connect', undefined, { cols, rows });
    await this.updateSessionStatusInD1('active');
    await this.recordAuditEvent('SESSION_CONNECTED', 'ssh_session', this.sessionId, 'success');
    this.userWebSocket?.send(JSON.stringify({ type: 'status', status: 'active' }));

    this.startTimers();
    this.keepaliveTimer = setInterval(() => {
      if (this.keepaliveOutstanding >= 3) {
        void this.handleSessionClose('timeout', 'keepalive_timeout').catch((error) => logError('keepalive_finalization_failed', error));
        return;
      }
      this.keepaliveOutstanding++;
      void this.sendPacket(concat(new Uint8Array([SSH_MSG_GLOBAL_REQUEST]), encodeString('keepalive@openssh.com'), new Uint8Array([1])))
        .catch((err) => logError('keepalive_failed', err));
    }, 25_000);
    (this.keepaliveTimer as any).unref?.();

    // Start background receive loop from SSH server
    const channelLoop = this.runChannelLoop().catch(async (err) => {
      if (this.isTerminated) return;
      logError('[SSHSessionDO] Channel loop terminated with error:', err);
      await this.handleSessionClose('failed', 'ssh_channel_failed');
    }).catch((error) => logError('session_finalization_failed', error));
    this.state?.waitUntil?.(channelLoop);
  }

  // --- SSH Receive Loop ---

  private async runChannelLoop(): Promise<void> {
    if (!this.channel) return;

    while (this.status === 'active' && !this.isTerminated) {
      const packet = await this.readPacket();
      const msgType = packet.payload[0];

      if (msgType === SSH_MSG_CHANNEL_DATA) {
        const rawStdout = this.channel.handleChannelData(packet.payload);
        if (await this.rejectFileTransfer(rawStdout, 'download')) break;
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

        const text = this.outputDecoder.decode(rawStdout, { stream: true });
        await this.recorder?.recordEvent('stdout', text);
        this.heuristics?.feedStdout(text);

        // Check if local window buffer adjustment needed
        const adjust = this.channel.takeLocalWindowAdjustment(1024 * 1024);
        if (adjust && this.channel.isOpen()) {
          await this.sendPacket(this.channel.buildWindowAdjust(adjust));
        }
      } else if (msgType === SSH_MSG_CHANNEL_EXTENDED_DATA) {
        const rawStderr = this.channel.handleExtendedData(packet.payload);
        if (await this.rejectFileTransfer(rawStderr, 'download')) break;
        this.resetIdleTimer();

        this.userWebSocket?.send(rawStderr);
        for (const watcher of this.watchers) {
          try {
            watcher.send(rawStderr);
          } catch {
            this.watchers.delete(watcher);
          }
        }

        const text = this.outputDecoder.decode(rawStderr, { stream: true });
        await this.recorder?.recordEvent('stdout', text);
        this.heuristics?.feedStdout(text);
        const adjust = this.channel.takeLocalWindowAdjustment(1024 * 1024);
        if (adjust && this.channel.isOpen()) await this.sendPacket(this.channel.buildWindowAdjust(adjust));
      } else if (msgType === SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        this.channel.handleWindowAdjust(packet.payload);
        await this.flushTerminalInput();
      } else if (msgType === SSH_MSG_CHANNEL_EOF) {
        this.channel.handleEof(packet.payload);
      } else if (msgType === SSH_MSG_CHANNEL_CLOSE) {
        this.channel.handleClose(packet.payload);
        await this.handleSessionClose('closed', 'remote_closed');
        break;
      } else if (msgType === SSH_MSG_DISCONNECT) {
        await this.handleSessionClose('closed', 'server_disconnect');
        break;
      } else if (msgType === SSH_MSG_REQUEST_SUCCESS || msgType === SSH_MSG_REQUEST_FAILURE) {
        this.keepaliveOutstanding = 0;
      } else if (msgType === SSH_MSG_GLOBAL_REQUEST) {
        const length = readUint32(packet.payload, 1);
        if (packet.payload[5 + length]) await this.sendPacket(new Uint8Array([SSH_MSG_REQUEST_FAILURE]));
      } else if (msgType === SSH_MSG_CHANNEL_REQUEST) {
        const payload = packet.payload;
        const length = readUint32(payload, 5);
        if (payload.length < 10 + length) throw new Error('Malformed channel request');
        const name = new TextDecoder().decode(payload.subarray(9, 9 + length));
        const offset = 10 + length;
        if (name === 'exit-status') this.exitCode = readUint32(payload, offset);
        if (name === 'exit-signal') {
          const signalLength = readUint32(payload, offset);
          if (payload.length < offset + 4 + signalLength) throw new Error('Malformed exit signal');
          this.exitSignal = new TextDecoder().decode(payload.subarray(offset + 4, offset + 4 + signalLength));
        }
        if (payload[9 + length]) {
          const reply = new Uint8Array(5); reply[0] = 100; // CHANNEL_FAILURE for unsupported reply requests
          writeUint32(reply, 1, this.channel.getRemoteChannelID());
          await this.sendPacket(reply);
        }
      }
      // IGNORE, DEBUG, and global requests are safely skipped
    }
  }

  // --- Host Key TOFU Handling ---

  private async processHostKeyTOFU(algorithm: string, fingerprint: string, hostKeyBlob: Uint8Array): Promise<void> {
    if (!this.env || !this.config) throw new Error('Session is not initialized');
    try { await verifyAssetHostKey(this.env, this.config.assetId, algorithm, fingerprint, toBase64(hostKeyBlob), {
      actorUserId: this.config.userId, actorUsername: this.config.usernameSnapshot,
      sourceIp: this.config.sourceIp || '', userAgent: this.config.userAgent,
    }); } catch (error) { await this.handleSessionClose('failed', 'host_key_changed'); throw error; }
  }

  // --- Session Termination & Cleanup ---

  async terminate(reason: string = 'terminated_by_admin', actorId?: string): Promise<void> {
    if (!this.isTerminated) this.terminatedBy = actorId || null;
    await this.handleSessionClose('terminated', reason);
  }

  private async handleSessionClose(status: SessionStatus, reason: string): Promise<void> {
    if (this.closeAudited) return;
    if (!this.isTerminated) {
      this.isTerminated = true;
      this.status = status;
      this.disconnectReason = reason;
      this.endedAt = Date.now();
    }
    if (!this.closing) this.closing = this.finishSessionClose().finally(() => { this.closing = null; });
    return this.closing;
  }

  private async finishSessionClose(): Promise<void> {
    const status = this.status;
    const reason = this.disconnectReason!;

    this.clearTimers();
    if (this.config) { this.config.password = undefined; this.config.privateKey = undefined; }
    this.validTickets.clear();

    // 1. Close channel
    if (this.channel && this.channel.isOpen() && !this.channel.hasSentClose()) {
      try {
        await this.sendPacket(this.channel.buildClose());
      } catch {
        // Socket may already be dead
      }
    }

    // Send a protocol disconnect before closing TCP.
    if (this.socketWriter) {
      try {
        const code = new Uint8Array(4); writeUint32(code, 0, 11);
        await this.sendPacket(concat(new Uint8Array([SSH_MSG_DISCONNECT]), code, encodeString('Session closed'), encodeString('')));
      } catch {}
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
        logError('[SSHSessionDO] Failed to close recording:', err);
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
    try { await this.heuristics?.flush(); }
    catch (error) { logError('command_audit_flush_failed', error); }
    await this.finalizeSessionInD1(status, reason, recordingPath, recordingHash);

    // 6. Audit Event
    const action = status === 'failed' ? 'SESSION_FAILED' : status === 'terminated' ? 'SESSION_TERMINATED' : 'SESSION_CLOSED';
    await this.recordAuditEvent(action, 'ssh_session', this.sessionId, status === 'failed' ? 'failure' : 'success', {
      reason,
      status,
      terminatedBy: this.terminatedBy,
      recordingHash,
    });
    this.closeAudited = true;
    try { await this.state?.storage?.deleteAll(); }
    catch (error) { logError('session_storage_cleanup_failed', error); }
  }

  // --- D1 Persistence Helpers ---

  private async persistSessionCreated(): Promise<void> {
    if (!this.env?.DB || !this.config) return;

    const row = await this.env.DB.prepare('SELECT user_id, asset_id, account_id FROM ssh_sessions WHERE id = ?')
      .bind(this.sessionId).first<{ user_id: string; asset_id: string; account_id: string }>();
    if (!row || row.user_id !== this.config.userId || row.asset_id !== this.config.assetId || row.account_id !== this.config.accountId) {
      throw new Error('Session metadata does not match initialization');
    }
    await this.updateSessionStatusInD1('connecting');
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

    const endedAt = this.endedAt ?? Date.now();
    const storage = getRecordingStorage(this.env);
    const recordingStatus = storage ? (recordingPath ? 'completed' : 'failed') : 'none';
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
         , exit_code = ?, exit_signal = ?
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
        this.exitCode,
        this.exitSignal,
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

    await writeAuditEvent({
      actorUserId: this.terminatedBy || this.config?.userId,
      actorUsername: this.terminatedBy ? this.terminationActor.username : this.config?.usernameSnapshot,
      action, resourceType, resourceId, resourceName: this.config?.assetNameSnapshot,
      sourceIp: (this.terminatedBy ? this.terminationActor.sourceIp : this.config?.sourceIp) || '',
      userAgent: (this.terminatedBy ? this.terminationActor.userAgent : this.config?.userAgent),
      result, metadata,
    }, this.env.DB);
  }
}
