import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parse, stringify } from 'smol-toml';
import {
  CloudflareApi,
  resolveAccountId,
  ensureDatabase,
  ensureKvNamespace,
  readWorkerSecretNames,
  resolveWorkerHostname,
} from './cloudflare-api.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const generatedConfig = '.wrangler.generated.toml';
const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));

function maskSecret(val: string): void {
  if (process.env.GITHUB_ACTIONS === 'true' && val) {
    console.log(`::add-mask::${val}`);
  }
}

async function runCommand(cmd: string, args: string[], cwd = root): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      stdio: 'inherit',
      shell: process.platform === 'win32',
      env: { ...process.env, CI: 'true' },
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`命令 "${cmd} ${args.join(' ')}" 失败（退出码 ${code}）。`));
    });
  });
}

async function runWrangler(args: string[], input?: string, configPath = generatedConfig): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, [wrangler, ...args, '--config', configPath], {
      cwd: root,
      env: { ...process.env, CI: 'true' },
      stdio: [input === undefined ? 'ignore' : 'pipe', 'inherit', 'inherit'],
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Wrangler ${args[0]} 执行失败（退出码 ${code}）。`));
    });
    if (input !== undefined) {
      child.stdin!.on('error', reject);
      child.stdin!.end(input);
    }
  });
}

async function main(): Promise<void> {
  const templatePath = new URL('../wrangler.toml', import.meta.url);
  const templateText = await readFile(templatePath, 'utf8');
  const template = parse(templateText) as any;

  const apiToken = process.env.CLOUDFLARE_API_TOKEN?.trim();
  if (!apiToken) {
    throw new Error('缺少环境变量 CLOUDFLARE_API_TOKEN。请配置具有 Workers、D1、KV 权限的 Cloudflare API 令牌。');
  }

  const workerName = process.env.WORKER_NAME?.trim() || String(template.name || 'edgejump');
  const customDomain = process.env.CUSTOM_DOMAIN?.trim();
  const d1Name = process.env.D1_DATABASE_NAME?.trim() || 'edgejump-db';
  const kvTitle = process.env.KV_NAMESPACE_NAME?.trim() || 'edgejump-kv';

  if (process.argv.includes('--validate-only')) {
    console.log('✓ 部署前置配置校验通过。');
    return;
  }

  const api = new CloudflareApi(apiToken);

  // 1. 解析账户 ID
  console.log('正在解析 Cloudflare 账户信息...');
  const accountId = await resolveAccountId(api, process.env.CLOUDFLARE_ACCOUNT_ID);
  process.env.CLOUDFLARE_ACCOUNT_ID = accountId;
  console.log(`✓ 使用 Cloudflare 账户 ID: ${accountId}`);

  // 2. 自动发现或创建 D1 数据库
  console.log(`正在检查 D1 关系型数据库 [${d1Name}]...`);
  const database = await ensureDatabase(api, accountId, d1Name, process.env.D1_DATABASE_ID);
  console.log(`✓ 关联 D1 数据库: ${database.name} (UUID: ${database.uuid})`);

  // 3. 自动发现或创建 KV 命名空间
  console.log(`正在检查 KV 命名空间 [${kvTitle}]...`);
  const kv = await ensureKvNamespace(api, accountId, kvTitle, process.env.KV_NAMESPACE_ID);
  console.log(`✓ 关联 KV 命名空间: ${kv.title} (ID: ${kv.id})`);

  // 4. 读取线上已有 Secret 并自动初始化安全凭证
  console.log('正在检查 Worker 安全密钥...');
  const existingSecrets = await readWorkerSecretNames(api, accountId, workerName);
  const secretsToPut: Record<string, string> = {};

  // KEK 主加密密钥 (用于信封加密凭证)
  if (!existingSecrets.has('CREDENTIAL_KEK_V1')) {
    const kek = process.env.CREDENTIAL_KEK_V1?.trim() || randomBytes(32).toString('hex');
    maskSecret(kek);
    secretsToPut.CREDENTIAL_KEK_V1 = kek;
    console.log('✓ 已自动生成主信封加密密钥 (CREDENTIAL_KEK_V1)');
  }

  // 用户密码哈希 Pepper
  if (!existingSecrets.has('AUTH_PEPPER')) {
    const pepper = process.env.AUTH_PEPPER?.trim() || randomBytes(32).toString('hex');
    maskSecret(pepper);
    secretsToPut.AUTH_PEPPER = pepper;
    console.log('✓ 已自动生成密码哈希加盐 Pepper (AUTH_PEPPER)');
  }

  // 超级管理员引导 Token
  let generatedBootstrapToken: string | null = null;
  if (process.env.BOOTSTRAP_TOKEN?.trim()) {
    const token = process.env.BOOTSTRAP_TOKEN.trim();
    maskSecret(token);
    secretsToPut.BOOTSTRAP_TOKEN = token;
    generatedBootstrapToken = token;
  } else if (!existingSecrets.has('BOOTSTRAP_TOKEN')) {
    const token = randomBytes(24).toString('base64url');
    maskSecret(token);
    secretsToPut.BOOTSTRAP_TOKEN = token;
    generatedBootstrapToken = token;
    console.log('✓ 已自动生成超级管理员引导令牌 (BOOTSTRAP_TOKEN)');
  }

  // 可选：外部 S3 / Backblaze B2 录像存储凭证
  const s3Keys = ['S3_ENDPOINT', 'S3_BUCKET', 'S3_REGION', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY'] as const;
  for (const key of s3Keys) {
    const val = process.env[key]?.trim();
    if (val) {
      maskSecret(val);
      secretsToPut[key] = val;
    }
  }
  if (process.env.S3_BUCKET?.trim() || existingSecrets.has('S3_BUCKET')) {
    console.log('✓ 已启用 S3/Backblaze B2 录像回放存储配置');
  }

  // 5. 编译 Web 前端
  console.log('正在构建前端静态页面单页应用 (npm run build:web)...');
  await runCommand('npm', ['run', 'build:web']);
  console.log('✓ 前端构建完成。');

  // 6. 生成临时部署配置文件 (避免硬编码生产 UUID 污染 Git)
  const generatedConfigObj = {
    ...template,
    name: workerName,
    account_id: accountId,
    workers_dev: !customDomain,
    ...(customDomain ? { routes: [{ pattern: customDomain, custom_domain: true }] } : {}),
    d1_databases: ((template.d1_databases as any[]) || []).map((b) =>
      b.binding === 'DB' ? { ...b, database_name: database.name, database_id: database.uuid } : b
    ),
    kv_namespaces: ((template.kv_namespaces as any[]) || []).map((b) =>
      b.binding === 'KV_CACHE' ? { ...b, id: kv.id } : b
    ),
  };

  const generatedConfigPath = new URL(`../${generatedConfig}`, import.meta.url);
  await writeFile(generatedConfigPath, stringify(generatedConfigObj), 'utf8');

  try {
    // 7. 应用 D1 远端数据库迁移
    console.log(`正在对远端数据库 ${database.name} 执行 D1 迁移...`);
    await runWrangler(['d1', 'migrations', 'apply', 'DB', '--remote']);
    console.log('✓ D1 数据库迁移成功。');

    // 8. 批量上传新生成的 Worker Secrets (通过标准输入传递，防落盘与防命令行泄露)
    if (Object.keys(secretsToPut).length > 0) {
      console.log(`正在写入 ${Object.keys(secretsToPut).length} 个安全密钥至 Worker Secrets...`);
      await runWrangler(['secret', 'bulk'], JSON.stringify(secretsToPut));
      console.log('✓ 密钥写入完成。');
    }

    // 9. 部署 Worker
    console.log(`正在将 ${workerName} 部署至 Cloudflare Workers...`);
    await runWrangler(['deploy']);
    console.log('✓ Worker 部署发布成功！');
  } finally {
    // 清理临时生成的配置文件
    await unlink(generatedConfigPath).catch(() => {});
  }

  // 10. 解析访问地址并输出部署摘要
  const hostname = customDomain || (await resolveWorkerHostname(api, accountId, workerName));
  const appUrl = `https://${hostname}`;

  console.log('\n============================================================');
  console.log(`🎉 EdgeJump 部署成功！访问地址: ${appUrl}`);
  if (generatedBootstrapToken) {
    console.log(`🔑 首次超级管理员初始化引导令牌 (BOOTSTRAP_TOKEN):`);
    console.log(`   ${generatedBootstrapToken}`);
    console.log(`👉 打开 ${appUrl} 进入向导输入上述 Token 完成账号创建！`);
  }
  console.log('============================================================\n');

  if (process.env.GITHUB_STEP_SUMMARY) {
    const summary = [
      '# 🚀 EdgeJump 自动部署成功',
      '',
      `* **访问地址**: [${appUrl}](${appUrl})`,
      `* **Worker 名称**: \`${workerName}\``,
      `* **D1 数据库**: \`${database.name}\` (\`${database.uuid}\`)`,
      `* **KV 缓存**: \`${kv.title}\` (\`${kv.id}\`)`,
      '',
      ...(generatedBootstrapToken
        ? [
            '### 🔑 首次超级管理员初始化 Token (BOOTSTRAP_TOKEN)',
            '```',
            generatedBootstrapToken,
            '```',
            `请立即访问 [${appUrl}](${appUrl})，系统将提示输入此 Token 完成超级管理员初始化。初始化后该 Token 将永久失效。`,
          ]
        : ['* **超级管理员状态**: 已初始化或沿用已有配置。']),
    ].join('\n');

    await writeFile(process.env.GITHUB_STEP_SUMMARY, summary, 'utf8');
  }
}

main().catch((err) => {
  console.error('\n❌ 部署失败:', err.message || err);
  process.exit(1);
});
