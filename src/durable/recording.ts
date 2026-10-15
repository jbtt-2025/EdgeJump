import { logError } from '../logging.ts';
// Terminal Session Recording Engine with WebStreams Gzip Compression and SHA-256 Hash Chaining for EdgeJump

import { concat, toBufferSource } from '../ssh/utils.ts';

import type { TerminalEventType, TerminalEvent, RecordingManifest } from '../shared/types.ts';
export type { TerminalEventType, TerminalEvent, RecordingManifest } from '../shared/types.ts';

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

  private eventsBuffer: Uint8Array[] = [];
  private readonly encoder = new TextEncoder();
  private bufferedBytes: number = 0;
  private seqNum: number = 0;
  private chunkCount: number = 0;
  private firstChunkHash: string | null = null;
  private rollingHash: string | null = null;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private isClosed: boolean = false;
  private flushQueue: Promise<unknown> = Promise.resolve();
  private chunks: { index: number; path: string; hash: string; rollingHash: string }[] = [];
  private closePromise: Promise<RecordingManifest> | null = null;

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
          logError(`[Recorder] Periodic flush error for session ${this.sessionId}:`, err);
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

  async recordEvent(type: TerminalEventType, data?: unknown, extra?: Partial<TerminalEvent>): Promise<void> {
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

    const serialized = this.encoder.encode(JSON.stringify(event) + '\n');
    this.eventsBuffer.push(serialized);
    this.bufferedBytes += serialized.length;

    if (this.bufferedBytes >= this.maxChunkBytes) {
      await this.flushChunk();
    }
  }

  flushChunk(): Promise<ChunkFlushResult | null> {
    const events = this.eventsBuffer;
    const size = this.bufferedBytes;
    this.eventsBuffer = [];
    this.bufferedBytes = 0;
    const task = this.flushQueue.then(() => this.flushNextChunk(events, size));
    this.flushQueue = task;
    return task;
  }

  private async flushNextChunk(eventsToFlush: Uint8Array[], uncompressedBytes: number): Promise<ChunkFlushResult | null> {
    if (!eventsToFlush.length || !this.storage) return null;
    const rawBytes = concat(...eventsToFlush);

    // Compress chunk via WebStreams CompressionStream('gzip')
    const compressedGzip = await compressGzip(rawBytes);

    // Compute chunk SHA-256
    const chunkHash = await computeChunkHash(compressedGzip);

    // Maintain rolling hash chain: hash_k = SHA256(hash_{k-1} || chunk_hash)
    const rollingHash = await computeRollingHash(this.rollingHash, chunkHash);

    const nextIndex = this.chunkCount + 1;
    const paddedSeq = String(nextIndex).padStart(6, '0');
    const chunkPath = `${this.recordingPrefix}/chunk-${paddedSeq}.jsonl.gz`;

    if (this.storage) {
      await this.storage.put(chunkPath, compressedGzip, {
        contentType: 'application/gzip',
        customMetadata: {
          sessionId: this.sessionId,
          chunkIndex: String(nextIndex),
          chunkHash,
          rollingHash,
        },
      });
    }

    this.chunkCount = nextIndex;
    this.rollingHash = rollingHash;
    this.firstChunkHash ??= chunkHash;
    this.chunks.push({ index: nextIndex, path: chunkPath, hash: chunkHash, rollingHash });
    return {
      chunkIndex: this.chunkCount,
      uncompressedBytes,
      compressedBytes: compressedGzip.length,
      chunkHash,
      rollingHash,
      path: chunkPath,
    };
  }

  close(disconnectReason?: string): Promise<RecordingManifest> {
    if (!this.closePromise) this.closePromise = this.finish(disconnectReason);
    return this.closePromise;
  }

  private async finish(disconnectReason?: string): Promise<RecordingManifest> {
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
    try {
      await this.recordEvent('disconnect', undefined, { reason: disconnectReason || 'closed' });
    } finally {
      this.isClosed = true;
      this.stopPeriodicFlush();
    }

    // All size/time-triggered writes finish before the final chunk and manifest.
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
      firstChunk: this.chunks[0]?.path ?? null,
      lastChunk: this.chunks.at(-1)?.path ?? null,
      chunks: this.chunks,
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
