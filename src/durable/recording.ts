// Terminal Session Recording Engine with WebStreams Gzip Compression and SHA-256 Hash Chaining for EdgeJump

import { concat, toBufferSource } from '../ssh/utils.ts';

export type TerminalEventType = 'connect' | 'stdout' | 'resize' | 'disconnect';

export interface TerminalEvent {
  seq: number;
  t: number; // milliseconds since session start
  type: TerminalEventType;
  data?: unknown;
  cols?: number;
  rows?: number;
  reason?: string;
}

export interface RecordingManifest {
  sessionId: string;
  chunkCount: number;
  firstChunkHash: string | null;
  finalHash: string | null;
  startedAt: number;
  endedAt: number;
  recordingPath: string;
}

export interface ChunkFlushResult {
  chunkIndex: number;
  uncompressedBytes: number;
  compressedBytes: number;
  chunkHash: string;
  rollingHash: string;
  path: string;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string length');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Compresses raw data with WebStreams CompressionStream('gzip').
 */
export async function compressGzip(data: Uint8Array): Promise<Uint8Array> {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(data);
      controller.close();
    },
  });

  const compressedStream = stream.pipeThrough(new CompressionStream('gzip') as any) as ReadableStream<Uint8Array>;
  const reader = compressedStream.getReader();
  const chunks: Uint8Array[] = [];

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }

  return concat(...chunks);
}

/**
 * Decompresses gzip data with WebStreams DecompressionStream('gzip').
 */
export async function decompressGzip(data: Uint8Array): Promise<Uint8Array> {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(data);
      controller.close();
    },
  });

  const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip') as any) as ReadableStream<Uint8Array>;
  const reader = decompressedStream.getReader();
  const chunks: Uint8Array[] = [];

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }

  return concat(...chunks);
}

/**
 * Computes SHA-256 hash of a chunk and returns lowercase hex string.
 */
export async function computeChunkHash(chunkBytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', toBufferSource(chunkBytes));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Maintains rolling hash chain:
 * For chunk 1: hash_1 = chunk_hash_1
 * For chunk k: hash_k = SHA-256(hash_{k-1} || chunk_hash_k)
 */
export async function computeRollingHash(
  prevHashHex: string | null,
  currentChunkHashHex: string
): Promise<string> {
  if (!prevHashHex) {
    return currentChunkHashHex;
  }

  const prevBytes = hexToBytes(prevHashHex);
  const currBytes = hexToBytes(currentChunkHashHex);
  const combined = concat(prevBytes, currBytes);
  const digest = await crypto.subtle.digest('SHA-256', toBufferSource(combined));
  return bytesToHex(new Uint8Array(digest));
}

import { type RecordingStorage, R2RecordingStorage } from '../storage/recording-storage.ts';

function toRecordingStorage(target?: RecordingStorage | R2Bucket | null): RecordingStorage | null {
  if (!target) return null;
  if ('get' in target && 'put' in target && typeof (target as any).get === 'function') {
    return target as RecordingStorage;
  }
  return new R2RecordingStorage(target as R2Bucket);
}

export class SessionRecorder {
  private readonly sessionId: string;
  private readonly startedAt: number;
  private readonly storage?: RecordingStorage | null;
  private readonly recordingPrefix: string;

  private eventsBuffer: TerminalEvent[] = [];
  private bufferedBytes: number = 0;
  private seqNum: number = 0;
  private chunkCount: number = 0;
  private firstChunkHash: string | null = null;
  private rollingHash: string | null = null;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private isClosed: boolean = false;

  readonly maxChunkBytes: number = 512 * 1024; // 512 KiB threshold
  readonly flushIntervalMs: number = 15_000;   // 15 seconds threshold

  constructor(sessionId: string, storage?: RecordingStorage | R2Bucket | null, startedAt: number = Date.now()) {
    this.sessionId = sessionId;
    this.storage = toRecordingStorage(storage);
    this.startedAt = startedAt;

    const date = new Date(startedAt);
    const yyyy = date.getUTCFullYear();
    const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(date.getUTCDate()).padStart(2, '0');
    this.recordingPrefix = `recordings/${yyyy}/${mm}/${dd}/${sessionId}`;

    if (this.storage) {
      this.startPeriodicFlush();
    }
  }

  getRecordingPrefix(): string {
    return this.recordingPrefix;
  }

  getChunkCount(): number {
    return this.chunkCount;
  }

  getFirstChunkHash(): string | null {
    return this.firstChunkHash;
  }

  getRollingHash(): string | null {
    return this.rollingHash;
  }

  private startPeriodicFlush(): void {
    this.flushTimer = setInterval(() => {
      if (this.eventsBuffer.length > 0 && !this.isClosed) {
        this.flushChunk().catch((err) => {
          console.error(`[Recorder] Periodic flush error for session ${this.sessionId}:`, err);
        });
      }
    }, this.flushIntervalMs);
    if (this.flushTimer && typeof (this.flushTimer as any).unref === 'function') {
      (this.flushTimer as any).unref();
    }
  }

  private stopPeriodicFlush(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  recordEvent(type: TerminalEventType, data?: unknown, extra?: Partial<TerminalEvent>): void {
    if (this.isClosed || !this.storage) return;

    this.seqNum++;
    const t = Math.max(0, Date.now() - this.startedAt);

    const event: TerminalEvent = {
      seq: this.seqNum,
      t,
      type,
      ...extra,
    };
    if (data !== undefined) {
      event.data = data;
    }

    const serialized = JSON.stringify(event) + '\n';
    const eventBytes = new TextEncoder().encode(serialized).length;

    this.eventsBuffer.push(event);
    this.bufferedBytes += eventBytes;

    if (this.bufferedBytes >= this.maxChunkBytes) {
      this.flushChunk().catch((err) => {
        console.error(`[Recorder] Max size flush error for session ${this.sessionId}:`, err);
      });
    }
  }

  async flushChunk(): Promise<ChunkFlushResult | null> {
    if (this.eventsBuffer.length === 0 || !this.storage) {
      return null;
    }

    const eventsToFlush = this.eventsBuffer;
    this.eventsBuffer = [];
    const uncompressedBytes = this.bufferedBytes;
    this.bufferedBytes = 0;

    const jsonlText = eventsToFlush.map((e) => JSON.stringify(e)).join('\n') + '\n';
    const rawBytes = new TextEncoder().encode(jsonlText);

    // Compress chunk via WebStreams CompressionStream('gzip')
    const compressedGzip = await compressGzip(rawBytes);

    // Compute chunk SHA-256
    const chunkHash = await computeChunkHash(compressedGzip);

    if (this.firstChunkHash === null) {
      this.firstChunkHash = chunkHash;
    }

    // Maintain rolling hash chain: hash_k = SHA256(hash_{k-1} || chunk_hash)
    this.rollingHash = await computeRollingHash(this.rollingHash, chunkHash);

    this.chunkCount++;
    const paddedSeq = String(this.chunkCount).padStart(6, '0');
    const chunkPath = `${this.recordingPrefix}/chunk-${paddedSeq}.jsonl.gz`;

    if (this.storage) {
      await this.storage.put(chunkPath, compressedGzip, {
        contentType: 'application/gzip',
        customMetadata: {
          sessionId: this.sessionId,
          chunkIndex: String(this.chunkCount),
          chunkHash,
          rollingHash: this.rollingHash,
        },
      });
    }

    return {
      chunkIndex: this.chunkCount,
      uncompressedBytes,
      compressedBytes: compressedGzip.length,
      chunkHash,
      rollingHash: this.rollingHash,
      path: chunkPath,
    };
  }

  async close(disconnectReason?: string): Promise<RecordingManifest> {
    if (this.isClosed) {
      return {
        sessionId: this.sessionId,
        chunkCount: this.chunkCount,
        firstChunkHash: this.firstChunkHash,
        finalHash: this.rollingHash,
        startedAt: this.startedAt,
        endedAt: Date.now(),
        recordingPath: this.storage ? this.recordingPrefix : '',
      };
    }

    if (!this.storage) {
      this.isClosed = true;
      this.stopPeriodicFlush();
      return {
        sessionId: this.sessionId,
        chunkCount: 0,
        firstChunkHash: null,
        finalHash: null,
        startedAt: this.startedAt,
        endedAt: Date.now(),
        recordingPath: '',
      };
    }

    // Record disconnect event before marking closed
    this.recordEvent('disconnect', undefined, { reason: disconnectReason || 'closed' });

    this.isClosed = true;
    this.stopPeriodicFlush();

    // Flush remaining buffer
    await this.flushChunk();

    const endedAt = Date.now();
    const manifest: RecordingManifest = {
      sessionId: this.sessionId,
      chunkCount: this.chunkCount,
      firstChunkHash: this.firstChunkHash,
      finalHash: this.rollingHash,
      startedAt: this.startedAt,
      endedAt,
      recordingPath: this.recordingPrefix,
    };

    if (this.storage) {
      const manifestPath = `${this.recordingPrefix}/manifest.json`;
      const manifestJson = JSON.stringify(manifest, null, 2);
      await this.storage.put(manifestPath, manifestJson, {
        contentType: 'application/json',
        customMetadata: {
          sessionId: this.sessionId,
          finalHash: this.rollingHash || '',
        },
      });
    }

    return manifest;
  }
}
