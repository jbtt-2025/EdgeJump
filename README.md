# EdgeJump — Cloudflare 原生无中转 SSH 堡垒机

> 基于 Cloudflare Workers 架构构建的轻量级、无传统中转服务器的现代化企业级 SSH 堡垒机 / JumpServer。

前端单页应用与后端服务一体化运行于 Cloudflare 全球边缘网络，利用 Durable Objects 进行长连接会话与状态维护，依托 D1 关系型数据库、KV 以及可选的 R2 对象存储实现持久化与存储隔离，彻底摆脱传统堡垒机对固定中转虚机、独立网关、Redis 与 PostgreSQL 等重型组件的运维依赖。

> **部署须知**：Free 适合少量、短时 SSH 维护；长连接会持续消耗 DO 时长额度，生产推荐 Workers Paid。项目已针对 Free 优化密码派生、静态资源、录像清理和会话开销，具体限制与配置见[部署须知](#部署须知)。

---

## 核心功能特色

### 1. 浏览器 SSH 终端
* **全功能 Web 终端**：基于 xterm.js 深度定制，支持 24 位真彩色（TrueColor）、Unicode 宽字符、自适应窗口缩放（Resize）、全屏模式与剪贴板快捷粘贴。
* **连接恢复入口**：会话断开后可重新连接；默认关闭浏览器即结束 SSH 会话，重连会创建新的授权会话。
* **V1 协议范围**：只开放 SSH Shell。SFTP、ZMODEM 文件传输和端口转发留待后续加入独立授权与文件审计后开放。

### 2. JumpServer 风格资产与细粒度授权体系
* **两层权限完全隔离**：系统管理后台权限（RBAC）与资产访问授权完全解耦。
* **资产与层级资产组**：支持树状层级资产分组，子组自动继承父级资产规则。
* **五要素授权模型**：授权规则精确绑定 `主体(用户/用户组) × 客体(资产/资产组) × 账号 × 操作权限 × 生效/失效时间`。
* **`@ALL` 通配账号支持**：默认选择具体 SSH 账号；显式勾选并确认 `@ALL` 后，授权覆盖目标资产全部账号，包括 root 与以后新增的账号。
* **动态可见性与安全隔离**：普通用户仅能查看与连接已获明确授权的资产列表，未授权资产在列表与接口中完全隐形；服务端在连接阶段二次严格校验授权时效与规则，拒绝未授权访问。

### 3. 严格的凭证安全托管（Write-Only / Replace-Only）
* **明文单向写入**：普通用户与系统管理员均无法查看或导出已托管的 SSH 密码或私钥明文；界面仅提供重置/替换凭证功能。
* **信封加密（Envelope Encryption）**：每个凭证独立生成 256 位 DEK（数据加密密钥），采用 AES-256-GCM 加密，DEK 再由 Master KEK 二次加密，结合凭证身份 AAD 校验防替换，支持多版本密钥平滑轮转（Key Rotation）。
* **认证后释放引用**：凭证仅在独立 DO 校验 Host Key 和授权后解密，认证结束或失败时清理明文引用与可清零的中间缓冲区。JavaScript 字符串的实际内存回收由运行时管理。
* **密码与 MFA**：密码使用 PBKDF2-HMAC-SHA256 600,000 次迭代、独立 Salt 和全局 Pepper，由内部专用 DO 执行标准 JavaScript 实现，兼容既有哈希并避开原生迭代上限。正式模式下管理员首次登录必须注册 TOTP，普通用户按系统策略执行；Demo 模式使用用户名与密码直接登录。两步验证挑战短时、绑定来源 IP、只能消费一次，恢复码也只能使用一次。正式模式的账户安全页支持注册验证器；策略允许时可用密码与动态码关闭 MFA，同时作废恢复码。

### 4. 主机指纹安全与防中间人攻击（Anti-MITM）
* **TOFU 首次自动信任**：首次连接未知目标服务器时，后台自动提取 SSH Host Key 算法与指纹并记录至 D1，实现开箱即连的平滑体验。
* **指纹变更严格阻断**：已知资产换指纹或算法都会阻断；资产管理员核实并批准具体指纹后才能继续。重置为待确认会保留旧记录，不会重新开启任意 TOFU 信任。
* **TCP SSRF 防护**：资产保存与连接时检查公网地址；连接前检查全部 A/AAAA 解析结果并固定连接到已验证 IP，拒绝内网、保留地址与 DNS 重绑定。V1 目标 SSH 服务必须能从 Workers 公网 TCP 网络访问。

### 5. 全链路会话审计与录像回放
* **实时旁路监控（Live Monitor）**：安全审计员与管理员可对进行中的在线会话进行单向只读监视，不干扰终端用户的正常输入。
* **在线会话强制阻断（Terminate）**：管理员可一键终止任意异常在线会话，DO 实时切断 SSH Channel 与底层 TCP 链路，并记录终止审计。
* **命令审计与脱敏**：以 `source=heuristic` 重建终端输入行，对敏感提示与无法确定的编辑分别标记 `[REDACTED]`、`[UNCERTAIN]`。它是辅助记录；配置录像时以终端输出录像为审计依据，默认不记录 raw stdin。
* **系统操作全量审计**：记录用户登录、资产变更、凭证替换、授权分配与管理员介入等全维度审计事件，永久持久化于 D1（无需 R2）。
* **全量终端录像回放（可选功能，支持 R2 / S3 / Backblaze B2）**：
  * **原生 R2 存储**：配置 Cloudflare R2 绑定后，会话事件流（stdout、resize、时间戳）自动流式分块压缩上传，内置回放器支持变速播放与拖拽，分块支持 SHA-256 哈希链防篡改。
  * **S3 / Backblaze B2 兼容存储**：配置兼容存储的环境变量即可启用录像与回放；存储、请求和流量费用按供应商配额计算，Worker 内的压缩、签名和外部请求仍消耗平台资源。
  * **保留策略**：`recording_retention_days` 默认 `0`，关闭应用物理清理。生产建议通过 Bucket Lock / Retention 配置 180 或 365 天。显式设置正数后 Cron 才清理；删除失败会记审计并保留 D1 路径和状态，适配不可变存储。
  * **未配置存储时**：系统自动跳过录像写入，**不保存审计录像回放**，列表状态显示为“未录像”；堡垒机所有连接、授权、监控与审计日志等核心功能完全正常运行。

### 6. 演示站模式 (Demo Mode)
系统支持通过 `DEPLOY_TYPE=demo` 环境变量一键启用公开演示站模式：
* **核心资产与密码保护**：在演示模式下，**禁止修改管理员密码**，**禁止禁用管理员账号**，**禁止修改录像保留时间**，有效防止公共体验用户破坏环境。
* **功能体验**：共享管理员通过用户名与密码直接进入后台，无需绑定或输入 MFA；普通用户管理、主机资产纳管、SSH 账号授权、终端连接与实时监视均可体验。Demo 模式关闭 MFA 设置，已有 MFA 记录也不会阻挡演示登录。
* **账号填写**：Demo 模式取消初始化用户名、密码的最小长度限制；新建普通用户与重置密码也允许短密码。用户名与密码仍为必填，正式模式保留原有长度要求。

### 7. 边缘原生高可用与防爆破防护
* **Durable Object 会话隔离**：每个 SSH Session 分配专属 DO 实例，独立管理 TCP 链路、PTY 状态与心跳保活。
* **防暴力破解**：RateLimitDO 按来源 IP 与规范化用户名分别累计登录尝试，原子预留限速额度；MFA 验证也受限速保护，锁定进入审计。

---

## 部署前置条件

1. **Cloudflare 账号**：Workers Free 支持本项目使用的 SQLite Durable Objects；生产推荐 **Workers Paid，最低 $5 USD/月，超出所含额度另计费**。计划限制见下方须知。
2. **Node.js**：版本 `>= 22.12.0`。
3. **Cloudflare API 令牌 (`CLOUDFLARE_API_TOKEN`)**：
   * 在 Cloudflare 仪表板 -> 我的个人资料 -> API 令牌 中创建；
   * 需包含以下权限：
     * **Account / D1 / Edit**（部分界面显示为 `Cloudflare D1`）
     * **Account / Workers KV Storage / Edit**
     * **Account / Workers Scripts / Edit**
     * **Account / Account Settings / Read**（可选；若不授予此权限，可通过下方的 `CLOUDFLARE_ACCOUNT_ID` 直接指定账户）
   * **使用 `Edit Cloudflare Workers` 模板时，必须手动添加 `Account / D1 / Edit`**；模板中的 Workers Scripts、KV、R2 等权限不包含 D1。账户资源建议仅选择部署目标账户，并确保与 `CLOUDFLARE_ACCOUNT_ID` 一致。
   * 若部署在“正在检查 D1 关系型数据库”后报 `Authentication error` / HTTP 403，编辑 Token 补上 D1 权限并检查账户范围，再重新运行部署。若新建了 Token，需将新值更新到 GitHub Actions 的 `CLOUDFLARE_API_TOKEN` Secret 或本地 `.env`。
4. **Cloudflare 账户 ID (`CLOUDFLARE_ACCOUNT_ID`)**（推荐配置）：
   * 在 Cloudflare 仪表板右侧栏即可复制 `Account ID`；
   * 若你的 API Token 仅关联单一账户且具备账号读取权限，脚本可自动发现；若关联了多个组织/团队账户，请务必配置此项以明确指定目标账户。

---

## 部署须知

### 免费版可能出现的问题

Free 的主要限制是总用量和持续负载，适合个人或小团队低频维护。以下配额按 2026-10-15 查阅的官方文档整理，同一账户的其他应用也会占用额度。

1. **长连接耗尽 DO 日时长**：Free 每天含 13,000 GB-s。SSH 会话持续持有 WebSocket、TCP 与定时器，在线期间都消耗时长。按官方计费示例每对象 128 MB（0.128 GB）计算，理论上限约为 `13,000 ÷ 0.128 ÷ 3,600 = 28.2` 个累计会话小时/天。两个会话各在线一小时消耗两个会话小时；密码派生和限速 DO 还会占用同一额度。两路终端全天在线就会超过上限，相关操作可能失败，日额度在 UTC 零点重置。SSH TCP 状态需要常驻，仅改用 WebSocket Hibernation API 无法消除这项用量。
2. **CPU 超限导致请求失败或终端断线**：普通 Free Worker HTTP 请求只有 10 ms CPU；D1/KV 网络等待不计入 CPU，JSON、权限处理与加密计算仍计入。密码派生已移到独立 DO。**DO 要单独看**：[官方 DO 限制专页](https://developers.cloudflare.com/durable-objects/platform/limits/)列出默认每次调用 30 秒，不应直接套用普通 Worker 的 10 ms。入站 HTTP/WebSocket 消息重置预算，TCP 输出、出站 keepalive 和定时器不会重置。持续刷日志、多路监控和录像压缩仍可能耗尽 DO CPU 并断开会话。
3. **请求或数据库配额耗尽**：Free 的普通动态 Worker 请求、DO 请求各有每天 100,000 次额度。登录会调用限速及密码 DO；大量 API 访问、终端输入和监控也消耗相应资源。D1/KV 另有读写及容量配额，持续命令审计会增加 D1 写入。超量可能使登录、管理或审计操作失败。
4. **S3/B2 外部子请求上限**：Free 每次调用最多 50 次外部子请求。长录像逐块删除不能一次做完；当前清理已切为每次最多 40 次对象操作并保存进度，历史积压需要多个批次。对象存储自身的容量、请求、流量与保留锁定规则仍独立生效。

### Paid 能解决什么

生产推荐 Workers Paid，最低 **$5 USD/月**，超出所含额度按用量计费。它主要增加普通 Worker 的计算余量，并允许相应请求、DO 时长超出所含用量后继续计费运行。

| 资源 | Workers Free | Workers Paid |
| --- | --- | --- |
| 普通 Worker HTTP 请求 CPU | 每次 10 ms | 默认 30 秒，可配置至 5 分钟 |
| 普通 Worker 动态请求 | 每天 100,000 次 | 每月含 1,000 万次，超量计费 |
| Durable Objects 请求 | 每天 100,000 次 | 每月含 100 万次，超量计费 |
| Durable Objects 在线时长 | 每天 13,000 GB-s | 每月含 400,000 GB-s，超量计费 |
| 外部子请求（例如 S3/B2 `fetch`） | 每次调用最多 50 次 | 默认 10,000 次，可配置 |

Paid 所含 DO 时长约为 `400,000 ÷ 0.128 ÷ 3,600 = 868` 个累计会话小时/月；这是月度所含用量，并非免费日额度的简单倍增。Paid 的 SSH DO 仍需持续计时，DO 默认 CPU 预算也不会因此自动变成无限。它不能自动解除原生 PBKDF2 迭代上限、修复存储故障或让 V1 连接私网服务器。

### 已做的免费版优化与建议配置

- **密码派生移到内部 `PasswordKdfDO`**：使用 `@noble/hashes` 的标准 PBKDF2-HMAC-SHA256，保留 600,000 次、独立 Salt、`AUTH_PEPPER` 及既有哈希格式，初始化、登录、创建/重置密码和 MFA 密码校验都走此路径。普通 HTTP Worker 只负责调用；DO 不保存密码、不启动常驻计时器。它增加一次内部 DO 请求与短时计算用量。派生服务故障返回 503，按预占 ID 退回本次限速额度，保留原有失败记录。
- **静态资源直接由 Assets 服务**：只有 `/api` 和 `/api/*` 优先执行 Worker，HTML、JS、CSS 和 SPA 页面路由不消耗动态 Worker 请求额度。静态 `_headers` 保留 CSP、HSTS、防 iframe 等安全头。
- **清理分批续跑**：每 15 分钟处理一批，每次最多 40 次对象操作，D1 保存分块游标及并发租约。S3 清理关闭 SDK 隐式重试；达到预算、运行中断或删除失败后，下次继续。全部对象删除成功才标记过期；部分删除的录像不再提供回放。`recording_retention_days = 0` 仍为默认值，关闭应用物理清理；生产保留/锁定优先通过存储基础设施配置。
- **减少持续输出开销**：录像事件只序列化、编码一次，复用已编码数据生成分块；活动只更新时间戳，空闲计时器到期后检查剩余时间，避免每个输出包都销毁/新建计时器。stdout/stderr 均补充 SSH 接收窗口，避免大量 stderr 卡住；分块背压、完整性校验和空闲/最长会话限制继续执行。

Free 建议从 **1–2 路短时会话、Ed25519 密钥、少量监控连接**开始。不需要回放时不配置 R2/S3，可省去录像压缩、签名和对象写入；需要回放则保留录像，并用实际负载评估成本。保持 `disconnect_on_browser_close = true`，可将 `session_idle_timeout` 调为 600 秒、`session_max_duration` 调为 3600 秒，降低遗留连接消耗。系统默认仍为 30 分钟空闲、8 小时最长时长；持续输出算活动，不能靠空闲超时限制刷屏，需依靠最长时长或主动断开。

### 部署与运行验收

保留现有 KEK 与 `AUTH_PEPPER`，应用全部未执行的 D1 迁移，并发布包含 `PASSWORD_KDF` 绑定及 DO migration 的新 Worker。自动部署脚本会处理这些配置；手工发布不能遗漏绑定。无需重置或改写旧密码哈希。

本地测试覆盖模拟原生 100,000 次上限、与原生标准哈希的一致性、KDF 故障与限速退款、分批清理、真实 SSH 大量输出；workerd 冒烟测试覆盖内部 DO 的 600,000 次派生及静态资源路由/安全头。本地 workerd 与托管生产的限制可能不同，上游说明见 [workerd #1346](https://github.com/cloudflare/workerd/issues/1346#issuecomment-1874827249)。上线时应在目标账户验收初始化、登录、创建/重置密码，以及持续 SSH 输出、录像与清理的实际 CPU 和用量。

CPU 数据从 Workers Logs 的 invocation 记录或 Tail Workers/Logpush 查看；Dashboard 的 `Exceeded CPU Time Limits` / `exceededCpu` 用于定位超限，`wrangler tail` 用于观察运行异常。

参考：[Workers 限制](https://developers.cloudflare.com/workers/platform/limits/)、[Workers 定价](https://developers.cloudflare.com/workers/platform/pricing/)、[DO 定价](https://developers.cloudflare.com/durable-objects/platform/pricing/)、[静态资源路由](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/)。

---

## 录像回放存储方案选择（可选）

基础依赖为 Workers + DO + D1 + KV，用量受各产品配额约束。对象存储的免费额度仅覆盖相应存储用量，部署成本还应计入 Worker 与 DO。

如果你需要使用“会话录像回放”功能，提供以下三种灵活选择：

| 方案 | 是否需绑卡 | 成本 | 配置方式 |
| :--- | :---: | :---: | :--- |
| **方案 A：不配置录像（默认）** | 否 | 无录像存储费用 | 无需额外存储设置。仅不保存录像，连接/授权/命令审计仍可使用。 |
| **方案 B：Backblaze B2** | **否** | 含 10 GB 存储免费额度 | 注册 B2 创建 Bucket，填入下方 S3 环境变量；费用与开户条件以供应商规则为准。 |
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
| `BOOTSTRAP_TOKEN` | **首次部署必须** | 自行生成并保存在密码管理器，只放加密 Secret；脚本不会打印或写入作业摘要 |

`DEPLOY_TYPE` 使用 Repository Variable，可设 `production`（默认）或 `demo`。

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
   * 自动生成主信封加密密钥 (`CREDENTIAL_KEK_V1`)、密码 Pepper (`AUTH_PEPPER`) 与独立票据密钥 (`SESSION_TICKET_SECRET`)，已存在的密钥保持不变；
   * 自动执行 D1 远端数据库迁移；
   * 全自动编译前端并发布至 Cloudflare Workers。
3. 部署成功后，在 GitHub Actions 该次运行详情的 **Summary（摘要）** 页面底部，即可直接看到：
   * **系统访问地址**（例如 `https://edgejump.<你的子域>.workers.dev`）
   * **初始化说明**（令牌使用你预先保存的 Secret）

### 步骤 3：首次初始化

打开站点，输入你保存的 `BOOTSTRAP_TOKEN` 并设置管理员账号、密码。正式模式随后按页面提示注册 TOTP、保存一次性恢复码；Demo 模式直接进入后台。初始化完成后 Bootstrap 永久关闭。

正式模式初始化要求用户名至少 3 个字符、密码至少 8 个字符；Demo 模式只要求填写。初始化失败时页面会显示具体原因；服务端错误还会显示请求编号，可在 Workers Logs 中搜索对应编号，检查日志中的错误代码。若页面提示管理员已创建，请直接登录。

---

## 部署方式二：本地命令行一键部署

如果你需要在本地终端直接将 EdgeJump 部署到 Cloudflare，同样无需手动配置资源 ID 或编辑 `wrangler.toml`：

### 步骤 1：克隆代码与安装依赖

```bash
git clone <repository-url>
cd jump_server_worker
npm install
```

### 步骤 2：配置本地环境变量文件 (`.env`)

复制项目根目录下的 `.env.example` 模版为 `.env`：

```bash
# Linux / macOS
cp .env.example .env

# Windows PowerShell
copy .env.example .env
```

打开 `.env` 文件，填入你的 `CLOUDFLARE_API_TOKEN`（以及可选的 `CLOUDFLARE_ACCOUNT_ID`、`DEPLOY_TYPE` 或 S3 存储参数等）：

```env
CLOUDFLARE_API_TOKEN=你的_CLOUDFLARE_API_TOKEN
BOOTSTRAP_TOKEN=自行生成并安全保存的高强度随机令牌
# 可选：指定账户 ID (多账号环境推荐)
# CLOUDFLARE_ACCOUNT_ID=你的_ACCOUNT_ID
# 可选：部署模式 (默认为 production，如需公开体验站可设为 demo)
# DEPLOY_TYPE=demo
# 可选：配置 Backblaze B2 免绑卡录像存储
# S3_ENDPOINT=https://s3.us-west-004.backblazeb2.com
# S3_BUCKET=edgejump-recordings
# S3_ACCESS_KEY_ID=004...
# S3_SECRET_ACCESS_KEY=K004...
```

> **提示**：`.env` 已在 `.gitignore` 中默认排除，不会意外提交到 Git 代码库。

### 步骤 3：执行一键部署

直接运行部署脚本（脚本将自动载入 `.env`）：

```bash
npm run deploy
```

部署脚本会自动连接 Cloudflare 执行：
1. 自动载入 `.env` 环境变量并校验配置；
2. 解析账户并自动定位或创建 D1 `edgejump-db`；
3. 自动定位或创建 KV `edgejump-kv`；
4. 自动生成加解密主密钥并通过管道（`wrangler secret bulk`）安全存入 Worker；
5. 编译前端单页应用并应用 D1 远端数据库迁移；
6. 完成 Worker 发布并打印访问域名；初始化使用你在 `.env` 中保存的 `BOOTSTRAP_TOKEN`。

---

## 本地开发与日常运维

### 本地开发

```bash
# 启动前端热重载开发服务器
npm run dev:web

# 运行本地 Miniflare 仿真开发
npm run dev

# 运行单元、安全、API 与真实 SSH 集成回归
npm test

# 安装一次 Chromium 并运行真实浏览器验收
npx playwright install chromium
npm run test:browser

# 检查类型
npm run typecheck
```

浏览器验收在 loopback 启动真实 SSH 服务，使用本地 SQLite D1 适配器与内存录像存储，运行实际 Worker/DO 路由；不连接 Cloudflare 资源。测试只在连接器中将已校验的公网测试目标映射至本地 SSH，生产 SSRF 规则保持开启。

### 升级已有部署

先应用 `migrations/0003_v1_review_fixes.sql` 与 `migrations/0004_recording_cleanup_progress.sql`，再发布新 Worker；自动部署脚本会执行全部未应用迁移。0003 增加 MFA 挑战、受限登录状态、退出码和待批准指纹，并补齐凭证 payload AAD 版本；0004 增加录像清理进度表。手工发布还需设置独立的 `SESSION_TICKET_SECRET` Secret，保留 `PASSWORD_KDF` 绑定和 `v2-password-kdf` DO migration；不能使用 Pepper 或 KEK 代替票据密钥。

历史 `user_` / `sess_` ID 保持有效；新建用户统一 `usr_`，新建登录会话用 `auth_`。实体继续使用稳定 UUID；内置角色、权限与设置保留稳定语义键。

需要 KEK 轮转时，先配置 `CREDENTIAL_KEK_V2`，再调用受 `credential.replace` 保护且有审计的 `POST /api/admin/credentials/:id/rewrap`，请求体为 `{"version":"v2"}`。它只重新包裹 DEK，保留凭证载荷的原 AAD 版本。完成所有凭证轮转前保留旧 KEK；TOTP Secret 目前仍依赖 `CREDENTIAL_KEK_V1`，因此 V1 必须继续保留该 Secret。

### 运维诊断与常用命令

```bash
# 实时跟踪远程 Worker 运行日志与错误
npx wrangler tail

# 查询远程 D1 数据库中的会话记录
npx wrangler d1 execute edgejump-db --remote --command "SELECT id, username_snapshot, asset_name_snapshot, status FROM ssh_sessions;"
```
