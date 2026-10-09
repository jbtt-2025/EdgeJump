import { randomBytes } from 'node:crypto';

const apiUrl = 'https://api.cloudflare.com/client/v4';

interface ApiResult<T> {
  success: boolean;
  result: T;
  errors?: { code: number; message: string }[];
  result_info?: { total_pages?: number; page?: number; per_page?: number };
}

export class CloudflareApiError extends Error {
  readonly codes: number[];

  constructor(message: string, codes: number[] = []) {
    super(message);
    this.codes = codes;
  }
}

export class CloudflareApi {
  private readonly token: string;
  private readonly fetcher: typeof fetch;

  constructor(token: string, fetcher: typeof fetch = fetch) {
    this.token = token;
    this.fetcher = fetcher;
  }

  private async send<T>(path: string, method: string, body?: unknown): Promise<ApiResult<T>> {
    const response = await this.fetcher(`${apiUrl}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({})) as { errors?: { code: number; message: string }[] };
      const codes = error.errors?.map((entry) => entry.code) ?? [];
      const msg = error.errors?.map((entry) => entry.message).join('; ') || `HTTP ${response.status}`;
      throw new CloudflareApiError(
        `Cloudflare ${method} ${path.split('?')[0]} 失败（${msg}）。请检查 Token 权限与账户范围。`,
        codes
      );
    }

    const payload = (await response.json()) as ApiResult<T>;
    if (!payload.success) {
      throw new Error(`Cloudflare ${method} 请求未成功，请检查 Token 权限及资源配额。`);
    }
    return payload;
  }

  async request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
    return (await this.send<T>(path, method, body)).result;
  }

  async list<T>(path: string): Promise<T[]> {
    const items: T[] = [];
    const delimiter = path.includes('?') ? '&' : '?';
    for (let page = 1; ; page++) {
      const payload = await this.send<T[]>(`${path}${delimiter}per_page=50&page=${page}`, 'GET');
      items.push(...payload.result);
      if (
        payload.result_info?.total_pages !== undefined
          ? page >= payload.result_info.total_pages
          : payload.result.length < 50
      ) {
        return items;
      }
    }
  }
}

export async function resolveAccountId(api: CloudflareApi, configured?: string): Promise<string> {
  if (configured && configured.trim()) return configured.trim();
  const accounts = await api.list<{ id: string; name: string }>('/accounts');
  if (accounts.length === 0) {
    throw new Error('未找到可用的 Cloudflare 账户，请检查 Token 权限。');
  }
  if (accounts.length > 1) {
    throw new Error(
      `检测到多个 Cloudflare 账户（${accounts.map((a) => `${a.name}: ${a.id}`).join(', ')}）。请设置 CLOUDFLARE_ACCOUNT_ID 指定目标账户。`
    );
  }
  return accounts[0].id;
}

export interface D1DatabaseInfo {
  uuid: string;
  name: string;
}

export async function ensureDatabase(
  api: CloudflareApi,
  accountId: string,
  databaseName: string,
  databaseId?: string
): Promise<D1DatabaseInfo> {
  const base = `/accounts/${accountId}/d1/database`;

  if (databaseId && databaseId.trim()) {
    const db = await api.request<D1DatabaseInfo>(`${base}/${databaseId.trim()}`);
    return db;
  }

  // 查找已有数据库
  const databases = await api.list<D1DatabaseInfo>(base);
  const existing = databases.find((d) => d.name === databaseName);
  if (existing) {
    return existing;
  }

  // 不存在则自动创建
  console.log(`未找到 D1 数据库 ${databaseName}，正在通过 Cloudflare API 自动创建...`);
  const created = await api.request<D1DatabaseInfo>(base, 'POST', { name: databaseName });
  console.log(`✓ 已成功创建 D1 数据库: ${created.name} (${created.uuid})`);
  return created;
}

export interface KvNamespaceInfo {
  id: string;
  title: string;
}

export async function ensureKvNamespace(
  api: CloudflareApi,
  accountId: string,
  title: string,
  namespaceId?: string
): Promise<KvNamespaceInfo> {
  const base = `/accounts/${accountId}/storage/kv/namespaces`;

  if (namespaceId && namespaceId.trim()) {
    return { id: namespaceId.trim(), title };
  }

  // 查找已有 KV 命名空间
  const namespaces = await api.list<KvNamespaceInfo>(base);
  const existing = namespaces.find((ns) => ns.title === title);
  if (existing) {
    return existing;
  }

  // 不存在则自动创建
  console.log(`未找到 KV 命名空间 ${title}，正在通过 Cloudflare API 自动创建...`);
  const created = await api.request<KvNamespaceInfo>(base, 'POST', { title });
  console.log(`✓ 已成功创建 KV 命名空间: ${created.title} (${created.id})`);
  return created;
}

export async function readWorkerSecretNames(
  api: CloudflareApi,
  accountId: string,
  workerName: string
): Promise<Set<string>> {
  const base = `/accounts/${accountId}/workers/scripts`;
  try {
    const workers = await api.request<{ id: string }[]>(base);
    if (!workers.some((w) => w.id === workerName)) {
      return new Set();
    }
    const secrets = await api.request<{ name: string }[]>(`${base}/${workerName}/secrets`);
    return new Set(secrets.map((s) => s.name));
  } catch {
    return new Set();
  }
}

export async function resolveWorkersDevSubdomain(
  api: CloudflareApi,
  accountId: string,
  workerName: string
): Promise<string> {
  const path = `/accounts/${accountId}/workers/subdomain`;
  let subdomain: string | null = null;
  try {
    const res = await api.request<{ subdomain: string | null }>(path);
    subdomain = res.subdomain;
  } catch (error) {
    if (!(error instanceof CloudflareApiError) || !error.codes.includes(10007)) {
      // ignore
    }
  }

  if (!subdomain) {
    subdomain = `${workerName}-${accountId.slice(0, 8)}`;
    try {
      await api.request(path, 'PUT', { subdomain });
    } catch {
      // ignore fallback
    }
  }

  return subdomain || 'unknown';
}

export async function resolveWorkerHostname(
  api: CloudflareApi,
  accountId: string,
  workerName: string
): Promise<string> {
  const subdomain = await resolveWorkersDevSubdomain(api, accountId, workerName);
  return `${workerName}.${subdomain}.workers.dev`;
}
