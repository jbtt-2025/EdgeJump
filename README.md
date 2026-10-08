# EdgeJump — Cloudflare 原生无中转 SSH 堡垒机

> 基于 Cloudflare Workers 架构构建的轻量级、无传统中转服务器的现代化企业级 SSH 堡垒机 / JumpServer。

前端单页应用与后端服务一体化运行于 Cloudflare 全球边缘网络，利用 Durable Objects 进行长连接会话与状态维护，依托 D1 关系型数据库、KV 以及可选的 R2 对象存储实现持久化与存储隔离，彻底摆脱传统堡垒机对固定中转虚机、独立网关、Redis 与 PostgreSQL 等重型组件的运维依赖。

---

## 核心功能特色

### 1. 现代化 Web 终端与文件传输
* **全功能 Web 终端**：基于 xterm.js 深度定制，支持 24 位真彩色（TrueColor）、Unicode 宽字符、自适应窗口缩放（Resize）、全屏模式与剪贴板快捷粘贴。
* **原生支持 lrzsz (ZMODEM) 文件传输**：
  * **上传文件**：在目标服务器输入 `rz` 或点击终端顶部快捷按钮，触发浏览器本地文件选择并自动上传。
  * **下载文件**：在目标服务器输入 `sz <文件名>`，浏览器自动接收并弹出文件下载。
  * **传输状态实时反馈**：终端顶部常驻文件传输进度条与百分比状态指示，支持大文件切片与批量文件传输。

### 2. JumpServer 风格资产与细粒度授权体系
* **两层权限完全隔离**：系统管理后台权限（RBAC）与资产访问授权完全解耦。
* **资产与层级资产组**：支持树状层级资产分组，子组自动继承父级资产规则。
* **五要素授权模型**：授权规则精确绑定 `主体(用户/用户组) × 客体(资产/资产组) × 账号 × 操作权限 × 生效/失效时间`。
* **`@ALL` 通配账号支持**：授权账号指定为 `@ALL` 时，自动继承并匹配资产下配置的所有 SSH 账号，后续新增账号即时生效。
* **动态可见性与安全隔离**：普通用户仅能查看与连接已获明确授权的资产列表，未授权资产在列表与接口中完全隐形；服务端在连接阶段二次严格校验授权时效与规则，拒绝未授权访问。

### 3. 严格的凭证安全托管（Write-Only / Replace-Only）
* **明文单向写入**：普通用户与系统管理员均无法查看或导出已托管的 SSH 密码或私钥明文；界面仅提供重置/替换凭证功能。
* **信封加密（Envelope Encryption）**：每个凭证独立生成 256 位 DEK（数据加密密钥），采用 AES-256-GCM 加密，DEK 再由 Master KEK 二次加密，结合凭证身份 AAD 校验防替换，支持多版本密钥平滑轮转（Key Rotation）。
* **内存即用即弃**：凭证密文仅在建立 SSH 连接时由独立的 Durable Object 会话实例解密，握手认证完成后立即从运行内存中擦除，禁止写入任何日志、数据库或临时缓存。
* **高强度账号安全**：系统用户密码采用 PBKDF2-HMAC-SHA256（600,000+ 轮迭代）+ 独立 Salt + 全局 Pepper 存储，内置 TOTP MFA 两步验证与一次性应急恢复码。

### 4. 主机指纹安全与防中间人攻击（Anti-MITM）
* **TOFU 首次自动信任**：首次连接未知目标服务器时，后台自动提取 SSH Host Key 算法与指纹并记录至 D1，实现开箱即连的平滑体验。
* **指纹变更严格阻断**：若已信任的目标服务器公钥指纹发生改变，系统立即阻断连接、标记告警并记录审计日志，防范中间人劫持；需资产管理员在后台手动重新校验重置。
* **TCP SSRF 深度防护**：默认拦截回环地址、本地多播、云平台元数据地址（如 `169.254.169.254`）及内网保留地址段。

### 5. 全链路会话审计与录像回放
* **实时旁路监控（Live Monitor）**：安全审计员与管理员可对进行中的在线会话进行单向只读监视，不干扰终端用户的正常输入。
* **在线会话强制阻断（Terminate）**：管理员可一键终止任意异常在线会话，DO 实时切断 SSH Channel 与底层 TCP 链路，并记录终止审计。
* **命令审计与脱敏**：实时重建终端输入行命令记录，自动识别密码输入并进行脱敏标注，数据直接写入 D1 数据库（无需 R2）。
* **系统操作全量审计**：记录用户登录、资产变更、凭证替换、授权分配与管理员介入等全维度审计事件，永久持久化于 D1（无需 R2）。
* **全量终端录像回放（可选功能）**：
  * **启用 R2 时**：会话事件流（stdout、resize、时间戳）流式分块压缩上传至 R2，内置回放器支持变速播放与拖拽，分块支持 SHA-256 哈希链防篡改。
  * **未配置 R2 时**：系统自动跳过录像写入，**不保存审计录像回放**，列表状态显示为“未录像”；堡垒机所有连接、授权、监控与审计日志等核心功能完全正常运行。

### 6. 边缘原生高可用与防爆破防护
* **Durable Object 会话隔离**：每个 SSH Session 分配专属 DO 实例，独立管理 TCP 链路、PTY 状态与心跳保活。
* **防暴力破解**：内置 RateLimitDO 状态机，对登录尝试、MFA 验证与密码重置施加速度限制与 IP 锁定。

---

## 部署前置条件

1. **Cloudflare 账号**：已开通 Workers Paid 计划（运行 Durable Objects 所需）。
2. **Node.js**：版本 `>= 22.12.0`。
3. **包管理工具**：npm（随 Node.js 自带）。
4. **Cloudflare API 凭证**：
   * `CLOUDFLARE_API_TOKEN`：具有 Workers、D1、KV 的编辑与读写权限（若启用录像功能，则需包含 R2 权限）。
   * `CLOUDFLARE_ACCOUNT_ID`：Cloudflare 账户 ID（可在仪表板右侧获取）。

---

## 部署方式一：手动部署

### 步骤 1：克隆代码与安装依赖

```bash
git clone <repository-url>
cd jump_server_worker
npm install
```

### 步骤 2：创建 Cloudflare 资源

在命令行通过 Wrangler 创建项目所需的必要资源（D1 数据库与 KV 命名空间）：

```bash
# 1. 创建 D1 关系型数据库 (必要)
npx wrangler d1 create edgejump-db

# 2. 创建配置缓存 KV 命名空间 (必要)
npx wrangler kv namespace create edgejump-kv

# 3. [可选] 如需开启会话录像与回放，创建 R2 存储桶；若不需要录像回放可跳过此步：
npx wrangler r2 bucket create edgejump-recordings
```

### 步骤 3：配置 `wrangler.toml`

根据上一步命令返回的资源 ID，检查并更新项目根目录下的 `wrangler.toml`：

```toml
name = "edgejump"
main = "src/worker.ts"
compatibility_date = "2026-07-01"
workers_dev = true

[build]
command = "npm run build:web"

[assets]
directory = "./dist"
binding = "ASSETS"
not_found_handling = "single-page-application"
run_worker_first = true

[vars]
CONNECT_TIMEOUT_MS = "10000"
ENVIRONMENT = "production"

[[durable_objects.bindings]]
name = "SSH_SESSIONS"
class_name = "SSHSessionDO"

[[durable_objects.bindings]]
name = "RATE_LIMIT"
class_name = "RateLimitDO"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["SSHSessionDO", "RateLimitDO"]

[[d1_databases]]
binding = "DB"
database_name = "edgejump-db"
database_id = "<填入你的 edgejump-db database_id>"
migrations_dir = "migrations"

[[kv_namespaces]]
binding = "KV_CACHE"
id = "<填入你的 edgejump-kv namespace id>"

# [可选] R2 存储桶（仅在需要会话录像回放功能时取消注释；不需要可保持注释）
# [[r2_buckets]]
# binding = "RECORDINGS"
# bucket_name = "edgejump-recordings"
```

### 步骤 4：配置安全环境变量（Worker Secrets）

通过 `wrangler secret put` 录入生产运行所需的三个关键密钥：

```bash
# 1. 生成 32 字节 Hex 格式的主加密密钥 (CREDENTIAL_KEK_V1) 并录入
# Linux/macOS 可使用: openssl rand -hex 32
# Windows PowerShell 可使用: -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
npx wrangler secret put CREDENTIAL_KEK_V1

# 2. 录入用户密码哈希全局 Pepper 随机字符串
npx wrangler secret put AUTH_PEPPER

# 3. 录入首次创建超级管理员的引导密钥 (BOOTSTRAP_TOKEN)
npx wrangler secret put BOOTSTRAP_TOKEN
```

### 步骤 5：应用 D1 数据库迁移

初始化数据表结构与内置角色权限：

```bash
npx wrangler d1 migrations apply edgejump-db --remote
```

### 步骤 6：构建前端并发布部署

```bash
# 编译构建前端静态资源
npm run build:web

# 部署至 Cloudflare Workers
npx wrangler deploy
```

部署成功后，控制台将输出服务访问地址，形如：`https://edgejump.<你的子域名>.workers.dev`。

### 步骤 7：初始化超级管理员账号

1. 浏览器打开部署分配的访问地址。
2. 系统检测到无任何用户，自动进入【首次初始化超级管理员】向导页面。
3. 输入在步骤 4 中设置的 `BOOTSTRAP_TOKEN`，并设置管理员用户名、密码和邮箱。
4. 提交后系统完成引导创建，同时 `BOOTSTRAP_TOKEN` 立即失效，即可正式登录使用。

---

## 部署方式二：GitHub Actions 自动化 CI/CD 部署

项目已内置完整的 GitHub Actions 工作流（[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)），每次向 `main` 或 `master` 分支推送代码，或手动触发时，将自动完成类型检查、单元测试、前端打包、数据库迁移与 Worker 部署。

### 步骤 1：准备 Cloudflare 基础资源与 Worker 密钥

在 Cloudflare 仪表盘或通过本地 Wrangler 完成以下资源创建与密钥设置：
1. 创建 D1 数据库：`edgejump-db`
2. 创建 KV 命名空间：`edgejump-kv`
3. （可选）若需要录像回放，创建 R2 存储桶 `edgejump-recordings` 并在 `wrangler.toml` 中取消注释 `[[r2_buckets]]`；若不需要录像回放可不创建。
4. 将对应的 `database_id` 和 KV `id` 提交到仓库的 `wrangler.toml` 中。
5. 通过 `npx wrangler secret put` 配置好 Worker 运行时的三个环境变量：
   * `CREDENTIAL_KEK_V1`
   * `AUTH_PEPPER`
   * `BOOTSTRAP_TOKEN`

### 步骤 2：配置 GitHub 仓库 Secrets

进入 GitHub 项目仓库页面，依次点击 **Settings** -> **Secrets and variables** -> **Actions** -> **New repository secret**，添加以下两个 Secret：

| Secret 名称 | 说明 | 示例 / 获取位置 |
| :--- | :--- | :--- |
| `CLOUDFLARE_API_TOKEN` | 具备 Workers、D1、KV（及可选 R2）权限的 API Token | Cloudflare 仪表板 -> 我的个人资料 -> API 令牌 |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare 账户 ID | Cloudflare 仪表板 Workers 页面右侧栏 |

### 步骤 3：触发自动化流水线

1. 将代码推送至 GitHub 仓库的 `main` 或 `master` 分支：
   ```bash
   git push origin main
   ```
2. 或者在 GitHub 仓库页面点击 **Actions** -> 选择 **Deploy EdgeJump** -> 点击 **Run workflow** 手动触发。
3. 流水线将自动执行以下作业：
   * **Node.js 运行环境准备**（Node.js 22）
   * **TypeScript 类型检查**（`npm run typecheck`）
   * **自动化测试套件执行**（`npm test`）
   * **生产环境前端编译打包**（`npm run build:web`）
   * **自动执行 D1 远端数据库迁移**（`d1 migrations apply edgejump-db --remote`）
   * **全自动发布部署至 Cloudflare Workers**（`wrangler deploy`）

### 步骤 4：首次访问与初始化

流水线执行完毕（全部步骤呈现绿色对勾）后，访问 Worker 域名，在引导页面输入 `BOOTSTRAP_TOKEN` 完成超级管理员初始化。

---

## 日常运维与常用命令

### 常用开发与测试命令

```bash
# 运行单元与集成测试（内置 80+ 测试项）
npm test

# 执行前端与 Worker 严格类型校验
npm run typecheck

# 仅编译前端单页应用至 dist 目录
npm run build:web

# 启动本地前端开发服务器（Vite）
npm run dev:web
```

### 运维诊断与调试

```bash
# 实时查看远程 Worker 运行日志与连接事件
npx wrangler tail

# 执行远程 D1 数据库直接查询
npx wrangler d1 execute edgejump-db --remote --command "SELECT id, username, status FROM users;"

# [可选] 查看远程录像存储桶对象列表（启用 R2 时可用）
npx wrangler r2 object list edgejump-recordings
```
