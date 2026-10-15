import { AwsClient } from 'aws4fetch';
import type { Env } from '../types.ts';

export interface StoragePutOptions {
  contentType?: string;
  customMetadata?: Record<string, string>;
}

export interface StorageObject {
  json<T = any>(): Promise<T>;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface RecordingStorage {
  put(key: string, value: Uint8Array | string, options?: StoragePutOptions): Promise<void>;
  get(key: string): Promise<StorageObject | null>;
  delete(key: string): Promise<void>;
}

/**
 * Cloudflare Native R2 Storage Provider
 */
export class R2RecordingStorage implements RecordingStorage {
  private readonly bucket: R2Bucket;

  constructor(bucket: R2Bucket) {
    this.bucket = bucket;
  }

  async put(key: string, value: Uint8Array | string, options?: StoragePutOptions): Promise<void> {
    await this.bucket.put(key, value, {
      httpMetadata: options?.contentType ? { contentType: options.contentType } : undefined,
      customMetadata: options?.customMetadata,
    });
  }

  async get(key: string): Promise<StorageObject | null> {
    const obj = await this.bucket.get(key);
    if (!obj) return null;
    return {
      json: () => obj.json(),
      text: () => obj.text(),
      arrayBuffer: () => obj.arrayBuffer(),
    };
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key);
  }
}

export interface S3StorageConfig {
  endpoint: string;          // e.g. https://s3.us-west-004.backblazeb2.com
  bucket: string;            // bucket name
  region?: string;           // e.g. us-west-004 or auto
  accessKeyId: string;       // B2 keyID or AWS access key
  secretAccessKey: string;   // B2 applicationKey or AWS secret key
  retries?: number;
}

/**
 * Generic S3-compatible Storage Provider (Backblaze B2, AWS S3, MinIO, Wasabi, etc.)
 */
export class S3RecordingStorage implements RecordingStorage {
  private readonly client: AwsClient;
  private readonly endpoint: string;
  private readonly bucket: string;

  constructor(config: S3StorageConfig) {
    this.endpoint = config.endpoint.replace(/\/+$/, '');
    this.bucket = config.bucket.trim();
    this.client = new AwsClient({
      accessKeyId: config.accessKeyId.trim(),
      secretAccessKey: config.secretAccessKey.trim(),
      service: 's3',
      region: config.region?.trim() || 'auto',
      retries: config.retries,
    });
  }

  private getUrl(key: string): string {
    const cleanKey = key.replace(/^\/+/, '');
    return `${this.endpoint}/${this.bucket}/${cleanKey}`;
  }

  async put(key: string, value: Uint8Array | string, options?: StoragePutOptions): Promise<void> {
    const url = this.getUrl(key);
    const headers: Record<string, string> = {
      'Content-Type': options?.contentType || 'application/octet-stream',
    };
    if (options?.customMetadata) {
      for (const [k, v] of Object.entries(options.customMetadata)) {
        headers[`x-amz-meta-${k}`] = v;
      }
    }

    const body = typeof value === 'string' ? value : value;
    const response = await this.client.fetch(url, {
      method: 'PUT',
      redirect: 'error',
      headers,
      body: body as any,
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      throw new Error(`S3 PUT "${key}" failed (HTTP ${response.status}): ${errText}`);
    }
  }

  async get(key: string): Promise<StorageObject | null> {
    const url = this.getUrl(key);
    const response = await this.client.fetch(url, { method: 'GET', redirect: 'error' });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      throw new Error(`S3 GET "${key}" failed (HTTP ${response.status}): ${errText}`);
    }

    return {
      json: () => response.json(),
      text: () => response.text(),
      arrayBuffer: () => response.arrayBuffer(),
    };
  }

  async delete(key: string): Promise<void> {
    const url = this.getUrl(key);
    const response = await this.client.fetch(url, { method: 'DELETE', redirect: 'error' });
    if (!response.ok && response.status !== 404) {
      const errText = await response.text().catch(() => '');
      throw new Error(`S3 DELETE "${key}" failed (HTTP ${response.status}): ${errText}`);
    }
  }
}

/**
 * Resolves configured storage provider from environment bindings:
 * 1. Cloudflare Native R2 binding (env.RECORDINGS)
 * 2. Generic S3-compatible storage (env.S3_ENDPOINT, env.S3_BUCKET, etc.)
 * 3. None (null) -> recordings disabled
 */
export function getRecordingStorage(env?: Env, options: { retries?: number } = {}): RecordingStorage | null {
  if (!env) return null;

  // 1. Cloudflare Native R2
  if (env.RECORDINGS) {
    return new R2RecordingStorage(env.RECORDINGS);
  }

  // 2. Generic S3-compatible Object Storage (Backblaze B2 / AWS S3 / MinIO / Wasabi)
  if (
    env.S3_ENDPOINT?.trim() &&
    env.S3_BUCKET?.trim() &&
    env.S3_ACCESS_KEY_ID?.trim() &&
    env.S3_SECRET_ACCESS_KEY?.trim()
  ) {
    return new S3RecordingStorage({
      endpoint: env.S3_ENDPOINT,
      bucket: env.S3_BUCKET,
      region: env.S3_REGION || 'auto',
      accessKeyId: env.S3_ACCESS_KEY_ID,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY,
      retries: options.retries,
    });
  }

  // 3. No object storage configured
  return null;
}
