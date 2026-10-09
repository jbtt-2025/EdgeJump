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
* **全量终端录像回放（可选功能，支持 R2 / S3 / Backblaze B2）**：
  * **原生 R2 存储**：配置 Cloudflare R2 绑定后，会话事件流（stdout、resize、时间戳）自动流式分块压缩上传，内置回放器支持变速播放与拖拽，分块支持 SHA-256 哈希链防篡改。
  * **S3 / Backblaze B2 兼容存储（免绑卡免费推荐）**：无需开通 R2 也无需绑定信用卡，仅需配置 Backblaze B2 或任意 S3 兼容存储的环境变量，即可直接获得全量录像与回放能力！
  * **未配置存储时**：系统自动跳过录像写入，**不保存审计录像回放**，列表状态显示为“未录像”；堡垒机所有连接、授权、监控与审计日志等核心功能完全正常运行。

### 6. 边缘原生高可用与防爆破防护
* **Durable Object 会话隔离**：每个 SSH Session 分配专属 DO 实例，独立管理 TCP 链路、PTY 状态与心跳保活。
* **防暴力破解**：内置 RateLimitDO 状态机，对登录尝试、MFA 验证与密码重置施加速度限制与 IP 锁定。

---

## 部署前置条件

1. **Cloudflare 账号**：普通免费账号即可（**Workers Free 免费计划现已原生支持 Durable Objects**，包含每日 100,000 次请求及 13,000 GB-s 计算额度，**无需开通 Workers Paid 订阅，实现完全零元部署**）。
2. **Node.js**：版本 `>= 22.12.0`。
3. **Cloudflare API 令牌 (`CLOUDFLARE_API_TOKEN`)**：
   * 在 Cloudflare 仪表板 -> 我的个人资料 -> API 令牌 中创建；
   * 需包含以下权限：
     * **Account / Cloudflare D1 / Edit**
     * **Account / Workers KV Storage / Edit**
     * **Account / Workers Scripts / Edit**
     * **Account / Account Settings / Read**（可选；若不授予此权限，可通过下方的 `CLOUDFLARE_ACCOUNT_ID` 直接指定账户）
4. **Cloudflare 账户 ID (`CLOUDFLARE_ACCOUNT_ID`)**（推荐配置）：
   * 在 Cloudflare 仪表板右侧栏即可复制 `Account ID`；
   * 若你的 API Token 仅关联单一账户且具备账号读取权限，脚本可自动发现；若关联了多个组织/团队账户，请务必配置此项以明确指定目标账户。

---

## 录像回放存储方案选择（可选）

基础堡垒机运行仅需 Workers + DO + D1 + KV，**全程零成本且无需绑定任何支付方式**。

如果你需要使用“会话录像回放”功能，提供以下三种灵活选择：

| 方案 | 是否需绑卡 | 成本 | 配置方式 |
| :--- | :---: | :---: | :--- |
| **方案 A：不配置录像（默认）** | 否 | 100% 免费 | 无需任何额外设置。仅不保存录像，所有连接/授权/命令审计正常工作。 |
| **方案 B：Backblaze B2 (推荐)** | **否** | **永久免费 10 GB** | **无需信用卡**，注册 B2 创建一个 Bucket，填入下方 S3 环境变量即可。 |
| **方案 C：Cloudflare R2** | 是（需验卡） | 免费额度 10 GB | 在 Cloudflare 控制台开通 R2 并创建 `RECORDINGS` 存储桶绑定。 |

---

## 自动化极简部署设计

系统采用全自动化基础设施发现与部署模式，**无需你手动创建数据库或修改 `wrangler.toml`**：
* ❌ **不用手动复制**: D1 Database ID、KV ID、生成的随机主加密密钥与 Pepper。
* ❌ **不用修改代码库中的 `wrangler.toml`**: 避免将个人/生产环境的专有资源 ID 提交到 Git 仓库。
* ✅ **自动化流水线全包办**: 脚本自动通过 Cloudflare API **自动查找或创建 D1 数据库 (`edgejump-db`)**、**自动查找或创建 KV 缓存 (`edgejump-kv`)**、**自动生成并安全注入高强度密钥**、**自动应用 D1 数据库表结构迁移**、**自动构建前端并发布 Worker**。

---

## 部署方式一：GitHub Actions 自动化 CI/CD 部署（推荐）

这是最省心、最快捷的部署方式。

### 步骤 1：配置 GitHub 仓库 Secrets / Variables

Fork 或推送到你自己的 GitHub 仓库后，进入项目仓库页面：  
依次点击 **Settings** -> **Secrets and variables** -> **Actions**，添加以下配置：

#### 基础必要配置（Repository Secrets）
| Secret 名称 | 必须 | 说明 |
| :--- | :---: | :--- |
| `CLOUDFLARE_API_TOKEN` | **是** | 具备 Workers、D1、KV 权限的 Cloudflare API 令牌 |
| `CLOUDFLARE_ACCOUNT_ID` | 推荐 | Cloudflare 账户 ID（多账号或精简权限 Token 必填，单账号可自动解析） |
| `BOOTSTRAP_TOKEN` | 否 | 首次初始化超级管理员的 Token（若不填，脚本自动生成并在 Actions 摘要中展示） |

#### 可选：Backblaze B2 / 兼容 S3 录像存储（免信用卡录像方案）
若想开启录像回放但不想在 Cloudflare 绑卡，可在 Actions **Secrets** 中添加：
| Secret 名称 | 必须 | 说明 |
| :--- | :---: | :--- |
| `S3_ENDPOINT` | 否 | S3 端点（如 B2: `https://s3.us-west-004.backblazeb2.com`） |
| `S3_BUCKET` | 否 | 存储桶名称（如 `edgejump-recordings`） |
| `S3_ACCESS_KEY_ID` | 否 | S3 Access Key ID（B2 为 keyID） |
| `S3_SECRET_ACCESS_KEY` | 否 | S3 Secret Access Key（B2 为 applicationKey） |
| `S3_REGION` | 否 | 存储区域（默认 `auto` 或填如 `us-west-004`） |

### 步骤 2：触发部署工作流

1. 将代码推送到 `main` 分支，或在 GitHub 仓库中进入 **Actions** -> 选择 **Deploy EdgeJump** -> 点击 **Run workflow** 手动触发。
2. 自动化流水线将自动完成：
   * 环境检查与单元测试验证；
   * 自动在 Cloudflare 账户中检查/创建 `edgejump-db` 数据库；
   * 自动在 Cloudflare 账户中检查/创建 `edgejump-kv` 缓存空间；
   * 自动生成主信封加密密钥 (`CREDENTIAL_KEK_V1`) 与密码加盐 (`AUTH_PEPPER`)；
   * 自动执行 D1 远端数据库迁移；
   * 全自动编译前端并发布至 Cloudflare Workers。
3. 部署成功后，在 GitHub Actions 该次运行详情的 **Summary（摘要）** 页面底部，即可直接看到：
   * **系统访问地址**（例如 `https://edgejump.<你的子域>.workers.dev`）
   * **首次超级管理员初始化引导令牌 (BOOTSTRAP_TOKEN)**

### 步骤 3：首次初始化

打开生成的站点地址，在向导中输入上述 `BOOTSTRAP_TOKEN`，设置管理员账号、密码及邮箱即可开始使用！

---

## 部署方式二：本地命令行一键部署

如果你需要在本地终端直接将 EdgeJump 部署到 Cloudflare，同样无需手动配置资源 ID 或编辑 `wrangler.toml`：

### 步骤 1：克隆代码与安装依赖

```bash
git clone <repository-url>
cd jump_server_worker
npm install
```

### 步骤 2：执行一键部署

设置你的 Cloudflare API 令牌后，直接运行部署脚本：

```bash
# Linux / macOS
export CLOUDFLARE_API_TOKEN="你的_CLOUDFLARE_API_TOKEN"
# 可选：指定账户 ID (多账号环境推荐)
# export CLOUDFLARE_ACCOUNT_ID="你的_ACCOUNT_ID"
# 可选：配置 Backblaze B2 免绑卡录像存储
# export S3_ENDPOINT="https://s3.us-west-004.backblazeb2.com"
# export S3_BUCKET="edgejump-recordings"
# export S3_ACCESS_KEY_ID="004..."
# export S3_SECRET_ACCESS_KEY="K004..."
npm run deploy

# Windows PowerShell
$env:CLOUDFLARE_API_TOKEN = "你的_CLOUDFLARE_API_TOKEN"
# $env:CLOUDFLARE_ACCOUNT_ID = "你的_ACCOUNT_ID"
npm run deploy
```

部署脚本会自动连接 Cloudflare 执行：
1. 解析账户并自动定位或创建 D1 `edgejump-db`；
2. 自动定位或创建 KV `edgejump-kv`；
3. 自动生成加解密主密钥并通过管道（`wrangler secret bulk`）安全存入 Worker；
4. 编译前端单页应用并应用 D1 迁移；
5. 完成 Worker 发布，并在终端末尾打印访问域名与 `BOOTSTRAP_TOKEN`。

---

## 本地开发与日常运维

### 本地开发

```bash
# 启动前端热重载开发服务器
npm run dev:web

# 运行本地 Miniflare 仿真开发
npm run dev

# 运行全量单元与集成测试（80+ 项）
npm test

# 检查类型
npm run typecheck
```

### 运维诊断与常用命令

```bash
# 实时跟踪远程 Worker 运行日志与错误
npx wrangler tail

# 查询远程 D1 数据库中的会话记录
npx wrangler d1 execute edgejump-db --remote --command "SELECT id, username_snapshot, asset_name_snapshot, status FROM ssh_sessions;"
```
