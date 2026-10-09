EdgeJump — Cloudflare Native SSH Bastion
========================================

> 项目代号：**EdgeJump**  
> 定位：基于 Cloudflare Workers 的轻量级、无传统中转服务器的 SSH 堡垒机 / JumpServer  
> 参考项目：**EdgeSSH**、**JumpServer**  
> 当前阶段：V1 需求与技术架构  
> 协议范围：**SSH Only**  
> 运行依赖：**Cloudflare Workers + Durable Objects + D1 + R2 (可选) + KV**

* * *

1. 项目目标
   =======

EdgeJump 的目标不是开发一个普通 WebSSH，而是实现一个具备企业堡垒机核心能力的 Cloudflare-native SSH 管理平台。

核心目标：

1. 浏览器直接访问 Web Terminal。

2. 目标服务器 SSH 密码 / 私钥统一托管。

3. 普通用户永远无法查看目标服务器凭证明文。

4. 多用户、多用户组、多角色管理。

5. 用户只能访问经过明确授权的资产和 SSH 账号。

6. 支持资产组和批量授权。

7. 支持授权生效时间和失效时间。

8. SSH Session 使用 Durable Object 独立管理。

9. 支持在线会话查看和管理员强制终止。

10. 所有 SSH Session 可审计、可回放。

11. 所有高风险后台操作产生审计记录。

12. SSH Host Key 必须校验，防止 MITM。

13. 凭证必须应用层加密后才能写入 D1。

14. 整个系统不依赖传统 JumpServer/Koko/Redis/PostgreSQL/独立 SSH Gateway。

15. 尽量复用 EdgeSSH 已验证的 SSH、PTY、TCP Socket、xterm.js 等实现。

最终链路：
    Browser   │   │ HTTPS / WebSocket   ▼Cloudflare Worker   │   ├── Authentication   ├── RBAC   ├── Asset Management   ├── Authorization   ├── Credential Management   ├── Audit API   │   ▼Session Durable Object   │   ├── SSH Protocol   ├── PTY   ├── Session Lifecycle   ├── Recording   └── Live Monitoring   │   ▼Cloudflare TCP Socket   │   ▼Target SSH Server

* * *

2. 非目标
   ======

V1 明确不实现：

* RDP

* VNC

* Kubernetes

* 数据库代理

* Telnet

* 原生 SSH Client 接入堡垒机

* ProxyJump

* SSH Agent Forwarding

* 通用 TCP Proxy

* RemoteApp

* LDAP

* AD

* OAuth/OIDC

* Cloudflare Access 依赖

* 审批工作流

* Session Sharing

* WebRTC

* 多租户 SaaS

* 计费系统

V1 重点只做：
    多用户+权限管理+资产管理+凭证托管+WebSSH+Session Audit+安全控制

SFTP、Port Forward、审批等功能放到后续版本。

* * *

3. 基本架构原则
   =========

3.1 Control Plane 与 Session Plane 分离
------------------------------------

逻辑上必须分成：
    Control Plane├── Authentication├── Users├── Groups├── Roles├── Assets├── Credentials├── Authorization Rules└── AuditSession Plane├── SSH Connection├── WebSocket├── PTY├── SSH Authentication├── Recording├── Monitoring└── Session Termination

代码可以暂时部署在同一个 Worker Project，但代码模块必须保持隔离。

后续允许拆成多个 Worker + Service Binding。

* * *

4. Cloudflare 组件职责
   ==================

Workers
-------

负责：

* HTTP API

* Authentication

* Session Cookie

* CSRF / Origin 验证

* RBAC

* Asset ACL

* Credential API

* Session 创建

* Session Ticket

* SSH Session 路由

* Audit API

* 前端静态资源

* WebSocket Upgrade

* * *

Durable Objects
---------------

核心用途：

### SSHSessionDO

每一个 SSH Session 对应一个独立 Durable Object。

例如：
    session_id = 01JXXXXXXXXXXXXSSHSessionDO(session_id)

负责：

* WebSocket

* TCP Socket

* SSH Handshake

* SSH Authentication

* PTY

* resize

* keepalive

* stdin/stdout

* Session Recording

* Live Monitoring

* Session Timeout

* Session Termination

* SSH Disconnect

DO 是 Session 的唯一实时状态持有者。

禁止把 SSH Session 实时状态放进 D1 或 KV。

* * *

D1
--

D1 是系统 authoritative database。

保存：
    UsersGroupsRolesPermissionsAssetsAsset GroupsAccountsCredentialsAuthorization RulesLogin SessionsSSH Session MetadataAudit EventsCommand AuditSSH Host KeysSystem Settings

安全相关授权判断必须最终以 D1 数据为准。

* * *

R2 (可选)
-------

R2 保存大对象和历史录像（若未配置 R2 则跳过录像存储，仅不提供会话回放）：
    session recordingssession manifestsfuture export files

建议目录：
    recordings/  2026/    10/      07/        <session-id>/          manifest.json          chunk-000001.jsonl.gz          chunk-000002.jsonl.gz          chunk-000003.jsonl.gz

禁止把完整 Terminal Recording 放入 D1。

* * *

KV
--

KV 只允许保存：

* 非敏感配置缓存

* UI 配置缓存

* Feature Flags

* 非安全关键 metadata

* 可重新生成的 cache

禁止保存：
    SSH PasswordSSH Private KeyAuth Session TokenMFA SecretCredential DEKAuthoritative Permission StateAudit Recording

权限判断不能只依赖 KV，因为 KV 不适合作为安全授权 authoritative store。

* * *

5. 用户体系
   =======

V1 使用系统自带 Local Account。

用户字段：
    idusernamedisplay_nameemailpassword_hashpassword_algorithmpassword_paramspassword_saltstatusmfa_enabledcreated_atupdated_atlast_login_atcreated_by

状态：
    activedisabledlocked

username 全局唯一。

* * *

6. 登录安全
   =======

登录方式：
    Username+Password+TOTP MFA

管理员默认强制 MFA。

普通用户是否强制 MFA 应由系统策略控制。

* * *

6.1 Password
------------

禁止：
    MD5SHA1SHA256(password)AES(password)plaintext

V1 优先使用 Workers Runtime 中可靠实现的安全 Password KDF。

若采用 WebCrypto PBKDF2：
    PBKDF2-HMAC-SHA256unique random salt per useriterations >= 600000

迭代数必须作为用户 password record 的参数保存，以便未来升级。

增加 Worker Secret：
    AUTH_PEPPER

作为 defense-in-depth。

* * *

7. Web Login Session
   ====================

登录成功后生成：
    random 256-bit session token

浏览器只保存：
    HttpOnlySecureSameSite=Strict

Cookie。

D1 只保存：
    SHA-256(session_token)

禁止保存 session token 明文。

Session 数据：
    iduser_idtoken_hashcreated_atlast_seen_atexpires_atipuser_agentrevoked_at

建议默认：
    absolute TTL: 8 hoursidle TTL: 30 minutes

可在系统设置修改。

* * *

8. MFA
   ======

V1 支持 TOTP。

保存：
    encrypted_totp_secret

TOTP Secret 与 SSH Credential 一样必须加密保存。

同时生成 Recovery Codes。

Recovery Code 只显示一次。

D1 只保存 Recovery Code Hash。

* * *

9. Bootstrap
   ============

首次部署没有用户时允许初始化 Super Admin。

推荐：
    BOOTSTRAP_TOKEN

作为 Worker Secret。

流程：
    /setupBOOTSTRAP_TOKEN        │        ▼Create Super Admin        │        ▼setup_complete = true

初始化完成之后：
    BOOTSTRAP_TOKEN

必须永久失效。

不得允许再次初始化管理员。

* * *

10. 两层权限体系
    ==========

这是系统最重要的设计之一。

必须将：
    后台管理权限

和：
    资产访问权限

完全分开。

不能简单使用一个 `role = admin/user` 解决所有问题。

* * *

11. System RBAC
    ===============

用于决定用户能管理 EdgeJump 的什么内容。

权限建议采用 Permission String。

例如：
    user.readuser.createuser.updateuser.disablegroup.readgroup.writeasset.readasset.createasset.updateasset.deletecredential.createcredential.replacecredential.deleteauthorization.readauthorization.writesession.view_ownsession.view_allsession.monitorsession.terminateaudit.readsettings.readsettings.write

* * *

12. Built-in Roles
    ==================

默认提供：
Super Admin
-----------

    *

拥有所有权限。

* * *

Asset Admin
-----------

主要负责：
    asset.*credential.*authorization.*

不能：
    user.*settings.*

* * *

Security Auditor
----------------

主要负责：
    session.view_allsession.monitoraudit.read

默认不能修改资产和权限。

是否允许：
    session.terminate

单独配置。

* * *

User
----

默认：
    session.view_own

资产访问必须通过 Asset Authorization Rule 获得。

* * *

13. User Group
    ==============

支持用户组：
    DevOpsDBADevelopersExternalProduction-ReadOnly

一个用户可以属于多个 Group。

结构：
    usersgroupsgroup_members    group_id    user_id

* * *

14. Asset Model
    ===============

Asset 表示一台可 SSH 访问的服务器。

字段：
    idnamehostnameportdescriptionplatformenvironmentenabledhost_key_policylast_seen_host_keycreated_atupdated_atcreated_by

示例：
    Name:prod-web-01Hostname:203.0.113.10Port:22Platform:linuxEnvironment:production

* * *

15. Asset Group
    ===============

参考 JumpServer Node / Asset Tree。

支持：
    Production├── Web├── Database└── MiddlewareStaging├── Web└── DatabaseDevelopment

V1 不要求实现无限复杂树。

建议数据库支持：
    parent_id

从一开始允许树状结构。

* * *

16. SSH Account 与 Credential 分离
    ===============================

不要把：
    AssetUsernamePassword

全部写进一条 Host Record。

应该拆成：
    AssetSSH AccountCredential

关系：
    Asset  │  ├── root  │      │  │      └── credential A  │  └── deploy         │         └── credential B

这样可以支持：
    同一台资产多个 SSH 用户

以及：
    多个资产共享一个 Credential

* * *

17. Credential Type
    ===================

V1 支持：
    passwordprivate_key

Private Key 支持能力优先复用 EdgeSSH。

初期至少：
    Ed25519RSAECDSA

如果 EdgeSSH SSH stack 当前已经支持，则直接复用现有实现。

Encrypted Private Key 可以暂时不支持。

* * *

18. Credential Security
    =======================

Credential API 必须遵循：

> Write Only / Replace Only

创建 Credential 时：
    Browser   │   │ HTTPS   ▼Worker   │   ▼Encrypt   │   ▼D1

之后任何 GET API：

**不得返回 Credential 明文。**

UI 只显示：
    Credential configuredCredential type: Private KeyUpdated: 2026-10-07

修改凭证意味着：
    Replace Credential

而不是查看原凭证。

* * *

19. Credential Envelope Encryption
    ==================================

不要简单采用：
    one AES key encrypt everything

推荐 Envelope Encryption。

每一个 Credential 创建：
    Random 256-bit DEK

Credential：
    plaintext   │AES-256-GCM(DEK)   │ciphertext

然后：
    DEK │AES-256-GCM(MASTER_KEK) │encrypted_DEK

D1 保存：
    credential_ciphertextcredential_nonceencrypted_dekdek_noncekey_versionalgorithm

Master KEK 只允许存在于：
    Workers Secret

例如：
    CREDENTIAL_KEK_V1

绝对不能进入：
    D1KVR2BrowserGitwrangler.toml plaintextlogs

* * *

20. Encryption AAD
    ==================

AES-GCM 必须使用 AAD 绑定 Credential Identity。

例如：
    credential_idcredential_typekey_version

避免 ciphertext 被替换到其他 Credential Record。

* * *

21. Key Rotation
    ================

设计必须从 V1 支持：
    key_version

未来添加：
    CREDENTIAL_KEK_V2

允许：
    decrypt encrypted_DEK using V1        │        ▼re-encrypt DEK using V2

无需重新获得 SSH 密码或私钥。

* * *

22. SSH Credential 使用原则
    =======================

只有 SSH Session DO 在建立 SSH Connection 时允许获得解密后的 Credential。

Credential 明文生命周期：
    D1 ciphertext     │     ▼Worker memory     │     ▼SSH Authentication     │     ▼discard

不得：

* 写日志

* 写 D1

* 写 R2

* 写 KV

* 返回浏览器

* 放 Session Ticket

* 放 WebSocket Message

* 放 Audit Event

* * *

23. Asset Authorization
    =======================

参考 JumpServer 模型：
    Subject   ×Asset   ×SSH Account   ×Action   ×Time

* * *

24. Authorization Subject
    =========================

规则可绑定：
    User或User Group

支持多个 User / Group。

* * *

25. Authorization Target
    ========================

规则可以绑定：
    Asset或Asset Group

授权 Asset Group 时自动作用于组中的 Asset。

* * *

26. Authorized Account
    ======================

授权必须明确：

用户可以使用目标服务器的哪个 SSH Account。

例如：
    Developers    │    ▼Production Web    │    ▼deploy

不能因为用户获得：
    prod-web-01

访问权限，就自动获得：
    root

权限。

* * *

27. Authorization Actions
    =========================

V1 至少支持：
    connect

提前为以后预留：
    sftp_readsftp_uploadsftp_downloadport_forward

V1 UI 可以只开放 `connect`。

* * *

28. Authorization Validity
    ==========================

每个 Rule 支持：
    valid_fromvalid_untilenabled

示例：
    User: contractor01Asset Group:Production/WebAccount:deployvalid_from:2026-10-07 09:00valid_until:2026-10-07 18:00

超过有效时间立即禁止创建新 Session。

* * *

29. Authorization Model
    =======================

V1 使用：

> Allow-only Model

没有匹配 Allow Rule：
    DENY

不要在 V1 引入：
    explicit denyprioritynested policy languageABAC DSL

避免权限冲突变得无法预测。

原则：
    Default DenyExplicit Allow

* * *

30. Permission Resolution
    =========================

用户登录后资产列表必须根据 Authorization 生成。

普通用户只能看到：
    Authorized Assets

不能：
    看到所有服务器然后连接时报 403

必须做到：
    Unauthorized Assets are invisible

连接时还必须再次服务器端验证。

禁止相信前端已经过滤。

* * *

31. Authorization Double Check
    ==============================

创建 SSH Session：
    POST /api/sessions

Worker 必须：
    1. validate login session2. validate user status3. validate asset enabled4. validate SSH account enabled5. evaluate authorization6. validate valid_from / valid_until7. validate account mapping8. validate Host Key state9. create session10. issue session ticket

WebSocket Upgrade 时再次检查：
    user_idsession_idticketexpiry

* * *

32. SSH Session Ticket
    ======================

浏览器不得获得 SSH Credential。

创建 Session 后只返回：
    session_idshort-lived ticketwebsocket endpoint

Ticket 包含或绑定：
    session_iduser_idasset_idaccount_idexpires_atnonce

Ticket 有效期建议：
    30-60 seconds

Ticket：
    single use

Ticket 不允许包含：
    passwordprivate keyDEK

* * *

33. SSHSessionDO
    ================

每一个 Session：
    DO_ID = session_id

SSHSessionDO 内部状态：
    session_iduser_idasset_idaccount_idwebsockettcp_socketssh_statepty_statecreated_atlast_activity_atrecording_statewatchersstatus

* * *

34. SSH 实现
    ==========

SSH 协议部分优先直接复用或改造 EdgeSSH：
    SSH 2.0HandshakeKey ExchangeHost KeyPassword AuthenticationKeyboard InteractivePublic Key AuthenticationPTYShell ChannelWindow ResizeKeepaliveDisconnect

不要从零重新写 SSH Protocol。

优先将 EdgeSSH 的：
    src/sshsrc/backendSSH Durable ObjectTCP Socket plumbing

提炼出来。

* * *

35. Terminal Frontend
    =====================

前端优先继续使用：
    xterm.js

支持：
    PTYUTF-8resizefullscreenclipboard pastereconnect UI

浏览器：
    WebSocket      │      ▼SSHSessionDO      │      ▼SSH Channel

* * *

36. Network Security / SSRF
    ===========================

由于 Worker 实际具有：
    connect(host, port)

能力，因此 Asset Management 本质上也是一个 SSRF / TCP SSRF 入口。

必须严格限制。

用户绝对不能在：
    /api/session

直接传：
    hostportusername

并让 Worker 连接。

正确流程：
    asset_idaccount_id

Worker 从 D1 获取真实目标。

* * *

37. 地址限制
    ========

V1 默认禁止连接：
    127.0.0.0/8::1169.254.0.0/16link-localmulticastunspecified addressesCloud metadata endpointsRFC1918 private ranges

除非未来专门加入 Private Network / VPC 模式。

连接 hostname 时必须防止：
    DNS Rebinding

尽量复用 EdgeSSH 已有 SSRF Protection 实现。

* * *

38. V1 网络前提
    ===========

在只采用：
    WorkersDOD1R2KV

的 V1 架构中，目标 SSH Server 必须能够从 Cloudflare Worker TCP 网络到达。

因此：
    Public IP / Public DNS reachable SSH

是 V1 基本网络条件。

私网服务器接入作为后续扩展项目，不在本阶段实现。

* * *

39. SSH Host Key Verification
    =============================

必须保留并强化 EdgeSSH 的 Host Key Verification。

保存：
    asset_idalgorithmfingerprintpublic_keyverified_atverified_bystatus

状态：
    unverifiedverifiedchanged

* * *

40. First Connection (TOFU 首次自动信任)
    ======================================

第一次连接 Asset：

先完成：
    SSH Key Exchange

获取：
    Host Key Fingerprint

采用 TOFU（Trust On First Use）首次信任策略：

系统自动将提取到的 Host Key 算法、公钥与指纹持久化写入 D1 `ssh_host_keys`，状态直接标记为：
    verified

并产生审计事件：
    HOST_KEY_TRUSTED

随后继续发送 SSH Password / Private Key 完成认证并建立终端会话。无需管理员预先手动审批，保证普通用户开箱即连的平滑体验。

* * *

41. Host Key Management
    =======================

首次连接自动 Trust 后，Host Key 进入严格比对与持久化管理状态：

1. 管理员可在后台资产详情中查看所有资产已信任的 Host Key 算法、Fingerprint 与记录时间。

2. 管理员具备手动重置或更新资产 Host Key 的管理能力。

3. 普通用户连接已知资产时，后台透明校验指纹一致性，无需弹框打扰。

但在 Host Key 指纹发生变动时（changed），立即启动最高等级安全防护阻断（详见第 42 条）。

* * *

42. Host Key Changed
    ====================

如果已验证服务器 Fingerprint 改变：

立即：
    BLOCK CONNECTION

状态改为：
    changed

产生 Security Audit Event。

必须 Asset Admin 手动重新确认。

绝对禁止：
    auto accept changed host key

* * *

43. Session Metadata
    ====================

每次 SSH Session 创建 D1 Record：
    iduser_idusername_snapshotasset_idasset_name_snapshotaccount_idaccount_name_snapshotsource_ipuser_agentstarted_atended_atstatusdisconnect_reasonclient_closedterminated_byrecording_statusrecording_pathrecording_hashcreated_at

使用 snapshot 字段避免资产或用户名修改后历史记录失去意义。

* * *

44. Session Status
    ==================

建议：
    creatingconnectingactiveclosingclosedfailedterminatedtimeout

* * *

45. Session Timeout
    ===================

系统设置：
    session_max_durationsession_idle_timeout

建议默认：
    idle timeout = 30 minutesmax duration = 8 hours

DO 负责强制执行。

不能只依赖 Browser Timer。

* * *

46. Browser Disconnect
    ======================

支持策略：
    disconnect_on_browser_close = true / false

V1 可以默认：
    true

后续再支持短时间 reconnect grace period。

* * *

47. Online Sessions
    ===================

管理员 Audit 页面支持：
    UserAssetSSH AccountSource IPStart TimeDurationStatus

管理员可点击：
    MonitorTerminate

* * *

48. Live Monitor
    ================

Security Auditor / Admin 可以只读连接到已有 Session DO。

例如：
    Operator Browser       │       ▼SSHSessionDO       │       ├── User WebSocket       │       └── Auditor Watch WebSocket

Auditor：
    receive stdoutreceive terminal resize

默认：
    read-only

不能向 SSH Session 输入字符。

* * *

49. Force Termination
    =====================

拥有：
    session.terminate

权限的用户可以：
    POST /api/admin/sessions/:id/terminate

Worker：
    lookup DO    │    ▼terminate()

DO：
    close SSH Channelclose TCPclose User WebSocketflush recordingupdate D1

Audit Event：
    SESSION_TERMINATEDactorsessionreasontimestamp

* * *

50. Session Recording
    =====================

Session Recording 是审计核心。

R2 Recording 使用事件流。

建议：
    {"seq":1,"t":0,"type":"stdout","data":"Last login...\r\n"}{"seq":2,"t":164,"type":"stdout","data":"user@host:~$ "}{"seq":3,"t":3420,"type":"resize","cols":160,"rows":48}

`t`：
    milliseconds since session start

用于 Replay。

* * *

51. Recording 内容
    ================

默认录像至少保存：
    stdoutstderr / channel outputresizeconnectdisconnecttimestamps

对于 raw stdin 必须谨慎。

原因：
    sudo passworddatabase passwordAPI tokensecret

都可能经过 Terminal Input。

默认：
    record_raw_stdin = false

不要为了“审计”把用户秘密全部复制进 R2。

* * *

52. Command Audit
    =================

SSH PTY 本质上不是 Command Protocol。

因此：
    command audit != authoritative

V1 可以通过 stdin line buffer 尝试重建：
    ls -ladocker pssystemctl restart nginx

但数据库字段必须明确：
    source = heuristic

不能声称 100% 准确。

处理：
    EnterBackspaceCtrl+CCtrl+UArrow keys

尽量实现基础 terminal line reconstruction。

发现类似：
    password:passphrase:token:

提示后，应该暂停下一行 command capture 或标记：
    [REDACTED]

Terminal Recording 才是最终 Session 审计依据。

* * *

53. Recording Chunk
    ===================

避免整个 Session 保存在 DO Memory。

建议满足任一条件立即 flush：
    512 KiB

或：
    15 seconds

生成：
    chunk-000001chunk-000002...

Session 结束生成：
    manifest.json

* * *

54. Recording Integrity
    =======================

每个 chunk 计算：
    SHA-256

并做 hash chain：
    hash_1 = SHA256(chunk_1)hash_2 = SHA256(hash_1 || chunk_2)hash_3 = SHA256(hash_2 || chunk_3)

Manifest 保存：
    first_chunklast_chunkchunk_countfinal_hashstarted_atended_at

D1 保存：
    recording_final_hash

用于检测录像是否被修改。

* * *

55. R2 Retention
    ================

生产环境建议 R2 Audit Bucket 配置 Retention / Bucket Lock。

例如：
    180 days365 days

Retention 策略不一定由应用 API 修改。

推荐通过基础设施配置完成。

系统应假定：
    audit recording may be immutable

因此应用不能依赖删除旧对象来完成正常业务逻辑。

* * *

56. Session Replay
    ==================

历史 Session 页面：
    PlayPause1x2x4xTimeline

重新按照 timestamp 将 terminal events 喂给：
    xterm.js

完成录像回放。

* * *

57. Audit Events
    ================

除 SSH Recording 外，所有管理操作必须记录 Audit Event。

包括：
    LOGIN_SUCCESSLOGIN_FAILEDLOGOUTUSER_CREATEDUSER_UPDATEDUSER_DISABLEDUSER_ENABLEDGROUP_CREATEDGROUP_UPDATEDGROUP_DELETEDASSET_CREATEDASSET_UPDATEDASSET_DELETEDACCOUNT_CREATEDACCOUNT_UPDATEDACCOUNT_DELETEDCREDENTIAL_CREATEDCREDENTIAL_REPLACEDCREDENTIAL_DELETEDAUTHORIZATION_CREATEDAUTHORIZATION_UPDATEDAUTHORIZATION_DELETEDHOST_KEY_TRUSTEDHOST_KEY_CHANGEDSESSION_CREATEDSESSION_CONNECTEDSESSION_FAILEDSESSION_CLOSEDSESSION_TERMINATEDSETTING_CHANGED

* * *

58. Audit Event Structure
    =========================
    
    idtimestampactor_user_idactor_username_snapshotactionresource_typeresource_idresource_name_snapshotsource_ipuser_agentresultmetadata_json

metadata 禁止出现：
    passwordprivate_keyTOTP secretsession cookieraw authorization headerDEKKEK

* * *

59. Audit Log 不允许普通管理员随意删除
    ==========================

V1 不提供：
    DELETE /audit

Super Admin UI 也不提供删除 Audit Event 功能。

如需数据 retention：

通过：
    system maintenance

统一策略处理。

* * *

60. User Disable
    ================

管理员 Disable User 时：

立即：
    deny new loginrevoke login sessionsdeny SSH session creation

配置项：
    terminate_active_sessions_on_disable

建议默认：
    true

需要找到该用户 active sessions，并通知对应 DO terminate。

* * *

61. Authorization Change
    ========================

如果管理员删除某用户资产权限：

默认：
    禁止创建新 Session

对于已经存在的 active Session：

V1 可以配置：
    terminate_sessions_on_permission_revocation

建议默认：
    false

后续可以加强为即时断开。

* * *

62. Rate Limiting
    =================

登录接口必须限速。

不要依赖 KV 做严格 Rate Limit。

推荐：
    RateLimit Durable Object

按：
    source IPusername

组合限制。

示例策略：
    5 failed attempts / 5 minutes

超过后指数退避或临时锁定。

所有锁定事件进入 Audit。

* * *

63. CSRF
    ========

所有 mutation API：
    POSTPUTPATCHDELETE

必须：

1. SameSite Cookie。

2. 校验 Origin。

3. 使用 CSRF Token。

WebSocket Upgrade 同样必须验证 Origin。

* * *

64. Security Headers
    ====================

至少：
    Content-Security-PolicyX-Content-Type-Options: nosniffReferrer-PolicyPermissions-PolicyStrict-Transport-Securityframe-ancestors 'none'

Terminal 页面不得允许第三方 iframe 嵌入。

* * *

65. Sensitive Logging
    =====================

Application Log 禁止输出：
    passwordprivate keycookieauthorization headerTOTPcredential ciphertextDEKKEKfull WebSocket terminal data

生产环境 error logging 必须进行 sanitization。

* * *

66. API 设计
    ==========

建议：
    /api/auth/*/api/me/api/assets/*/api/groups/*/api/accounts/*/api/sessions/*/api/admin/users/*/api/admin/groups/*/api/admin/assets/*/api/admin/credentials/*/api/admin/authorizations/*/api/admin/sessions/*/api/admin/audit/*/api/admin/settings/*

* * *

67. Auth API
    ============
    
    POST /api/auth/loginPOST /api/auth/mfaPOST /api/auth/logoutGET  /api/me

* * *

68. User Asset API
    ==================
    
    GET /api/assetsGET /api/assets/:idGET /api/assets/:id/accounts

只返回当前用户有权使用的数据。

* * *

69. Session API
    ===============
    
    POST /api/sessionsGET  /api/sessions/:idGET  /api/sessions/:id/wsPOST /api/sessions/:id/resume-ticketPOST /api/sessions/:id/disconnect

创建：
    {  "asset_id": "...",  "account_id": "..."}

绝不接受：
    {  "hostname": "...",  "port": 22,  "password": "..."}

* * *

70. Admin User API
    ==================
    
    GET    /api/admin/usersPOST   /api/admin/usersPATCH  /api/admin/users/:idPOST   /api/admin/users/:id/disablePOST   /api/admin/users/:id/enablePOST   /api/admin/users/:id/reset-password

管理员不能读取用户 Password Hash。

* * *

71. Credential API
    ==================
    
    GET    /api/admin/credentialsPOST   /api/admin/credentialsPUT    /api/admin/credentials/:idDELETE /api/admin/credentials/:id

GET 返回：
    idnametypecreated_atupdated_atkey_version

禁止返回 encrypted blob 给前端。

虽然 ciphertext 不是 plaintext，也没有业务需要发送给浏览器。

* * *

72. Authorization API
    =====================
    
    GET    /api/admin/authorizationsPOST   /api/admin/authorizationsPATCH  /api/admin/authorizations/:idDELETE /api/admin/authorizations/:id

* * *

73. Session Audit API
    =====================
    
    GET  /api/admin/sessionsGET  /api/admin/sessions/:idGET  /api/admin/sessions/:id/recordingGET  /api/admin/sessions/:id/commandsGET  /api/admin/sessions/:id/monitorPOST /api/admin/sessions/:id/terminate

* * *

74. UI 页面
    =========

Login
-----

    UsernamePasswordMFA

* * *

Dashboard
---------

展示：
    Authorized AssetsRecent SessionsFavorite AssetsActive Sessions

* * *

Assets
------

类似 JumpServer：
    Asset TreeProduction├── Web│   ├── prod-web-01│   └── prod-web-02└── Database    └── prod-db-01

* * *

Web Terminal
------------

顶部：
    AssetSSH AccountSession DurationConnection Status

主区域：
    xterm.js

* * *

Admin / Users
-------------

    UsersGroupsRolesMFA StatusLast LoginStatus

* * *

Admin / Assets
--------------

    Asset GroupsAssetsSSH AccountsCredentialsHost Keys

* * *

Admin / Authorization
---------------------

核心 UI：
    Rule NameUsers / Groups        ↓Assets / Asset Groups        ↓SSH Accounts        ↓Actions        ↓Valid From / Until

* * *

Audit / Online Sessions
-----------------------

    UserAssetAccountSource IPStartedDurationMonitorTerminate

* * *

Audit / Historical Sessions
---------------------------

    UserAssetAccountStartEndDurationResultReplayCommandsEvents

* * *

75. D1 数据表建议
    ============

至少包含：
    usersauth_sessionsmfa_recovery_codesrolespermissionsrole_permissionsuser_rolesgroupsgroup_membersassetsasset_groupsasset_group_memberscredentialsasset_accountsauthorization_rulesauthorization_rule_usersauthorization_rule_groupsauthorization_rule_assetsauthorization_rule_asset_groupsauthorization_rule_accountsauthorization_rule_actionsssh_host_keysssh_sessionssession_commandsaudit_eventssystem_settings

所有表使用稳定 UUID / ULID。

推荐 ULID：
    sortableglobally uniquefrontend friendly

* * *

76. Database Migration
    ======================

所有 D1 Schema 修改必须走：
    migrations/

禁止运行时：
    CREATE TABLE IF NOT EXISTS

偷偷修改生产 Schema。

每个 migration：
    immutableversionedreviewable

* * *

77. Frontend 与 Backend 类型
    =========================

推荐 TypeScript 全栈。

Shared Types：
    src/shared/

保存：
    API TypesPermission TypesSession TypesAudit TypesAsset Types

前后端尽量共享类型。

* * *

78. 推荐目录结构
    ==========
    
    edgejump/├── frontend/│   ├── auth/│   ├── dashboard/│   ├── assets/│   ├── terminal/│   ├── admin/│   │   ├── users/│   │   ├── assets/│   │   ├── credentials/│   │   ├── authorization/│   │   └── audit/│   └── components/│├── src/│   ├── auth/│   ├── rbac/│   ├── authorization/│   ├── assets/│   ├── credentials/│   ├── crypto/│   ├── audit/│   ├── sessions/│   ├── ssh/│   ├── durable/│   │   ├── SSHSessionDO.ts│   │   └── RateLimitDO.ts│   ├── api/│   ├── shared/│   └── worker.ts│├── migrations/├── tests/│   ├── unit/│   ├── integration/│   ├── security/│   └── browser/│├── wrangler.toml└── README.md

* * *

79. EdgeSSH 复用策略
    ================

不要直接在现有 EdgeSSH 的 Single-admin Model 上硬塞 RBAC。

优先将 EdgeSSH 当成：
    SSH Engine+Terminal Reference Implementation

复用：
    SSH protocol implementationTCP SocketSSHSession Durable Object ideasxterm.jsHost Key VerificationPTYResizeKeepalivePassword AuthPrivate Key AuthSession Ticket concepts

重构：
    Single Admin AuthHost StorageCredential StorageHost OwnershipAPI Authorization

替换为 EdgeJump 的多人模型。

* * *

79.1 JumpServer 核心模型映射策略
    ===============================

参考本地已拉取的 JumpServer 官方代码库（`jumpserver/apps`），EdgeJump 将其成熟的企业级权限与资产模型精炼映射到 Cloudflare 原生无服务架构中：

1. 资产授权模型（对标 `jumpserver/apps/perms/models/asset_permission.py`）：
   - 映射 JumpServer 的 `AssetPermission` 为 EdgeJump 的 D1 `authorization_rules` 表体系。
   - 授权五要素完全对齐：
     - 主体（Subject）：`users` / `groups`
     - 目标（Target）：`assets` / `asset_groups`
     - 账号（Account）：`asset_accounts`（支持指定具体 SSH 账号或模式）
     - 动作（Action）：默认 `connect`（为后续扩展预留）
     - 时间与状态（Time & Status）：`valid_from`, `valid_until`, `enabled`
   - 继承 JumpServer 的 Default Deny + 动态解析机制：用户只能看到并连接经明确授权的资产，未授权资产完全不可见。

2. 资产组织架构（对标 `jumpserver/apps/assets/models/node.py`）：
   - 映射 JumpServer 的 Node 树结构为 EdgeJump 的 D1 `asset_groups`（支持 `parent_id` 树形嵌套）。
   - 授权作用于资产组时，组内包含及后续新加入的资产自动继承该访问权限。

3. 账号与凭据物理隔离（对标 `jumpserver/apps/accounts/models/account.py`）：
   - 映射 JumpServer 将登录账号与登录凭证解耦的理念。
   - EdgeJump 将账号信息（`asset_accounts`）与核心机密（`credentials`）严格分离，凭证采用独创的 AES-256-GCM 信封加密（DEK + Master KEK），杜绝明文落地与前端窥探。

4. 会话、指令与回放审计（对标 `jumpserver/apps/terminal/models/session/`）：
   - 会话元数据对标 JumpServer `Session`（用户快照、资产快照、账号快照、起止时间、退出码）。
   - 指令审计对标 JumpServer `terminal_command`（输入流回车断行重构、敏感密码输入自动脱敏 `[REDACTED]`）。
   - 录像回放对标 JumpServer 的 `.cast.gz` / `.replay.gz` 审计回放体验：EdgeJump 摆脱传统 Celery / Redis / 本地磁盘中转，直接由 `SSHSessionDO` 在内存流式压缩成分块并追加写入 R2，同时附加 SHA-256 哈希链确保审计防篡改。

* * *

80. 不建议保留的 EdgeSSH 功能
    =====================

为了减少堡垒机攻击面，V1 不需要：
    Globe VisualizationCode SnippetsProcess MonitorPort ForwardingHTTP PreviewSFTP File Manager

这些可以后续逐个重新加入。

V1 应优先：
    SecurityRBACAuthorizationAuditReliability

而不是功能数量。

* * *

81. Port Forwarding
    ===================

V1 必须关闭。

原因：

SSH Port Forward 可以轻易变成：
    Internal Network Pivot

以后若实现：

必须新增：
    port_forward

独立 Authorization Action。

还必须限制：
    destinationportprotocol

不能简单继承 `connect` 权限。

* * *

82. SFTP
    ========

V1 可以暂不提供。

V1.1 可增加：
    sftp_readsftp_downloadsftp_upload

权限必须独立。

File Transfer 必须进入 Audit：
    userassetaccountpathdirectionsizetimestampresult

* * *

83. Threat Model
    ================

至少考虑以下攻击：
    D1 leakR2 leakCredential ciphertext theftstolen login cookieCSRFXSSSSRFDNS rebindingmalicious assetSSH MITMhost key replacementprivilege escalationbroken access controlIDORaudit deletioncredential disclosuresession hijackingWebSocket hijackingbrute force login

每一个 API 开发时都应该以：
    Assume browser is malicious

作为前提。

* * *

84. IDOR 原则
    ===========

任何：
    /api/assets/:id/api/sessions/:id/api/accounts/:id

都不能因为用户知道 ID 就允许读取。

每一个资源访问都必须做服务器端：
    user→ permission→ resource

验证。

* * *

85. Credential Threat Boundary
    ==============================

必须明确：

EdgeJump Worker 是 SSH Client。

因此：
    Worker runtime

属于 Trusted Computing Base。

系统不是：
    End-to-End Encrypted SSH Gateway

Cloudflare Worker 在建立 SSH 连接时必然短暂接触 SSH Credential。

我们保护的是：
    Browser UserDatabase LeakR2 LeakUnauthorized EdgeJump UserFrontend compromise scope

不是保护 Credential 不被 Worker Runtime 看见。

* * *

86. Test Requirements
    =====================

Permission Matrix Test
----------------------

必须大量覆盖：
    User → AssetGroup → AssetUser → Asset GroupGroup → Asset Groupvalid authorizationexpired authorizationfuture authorizationdisabled authorizationwrong accountunauthorized accountdisabled assetdisabled user

* * *

87. Crypto Tests
    ================

覆盖：
    encrypt/decryptwrong KEKwrong AADmodified ciphertextmodified noncekey versionDEK rewrapcredential replacement

* * *

88. SSH Security Tests
    ======================

覆盖：
    untrusted host keyvalid host keychanged host keywrong passwordinvalid private keyconnection timeoutSSH disconnectmalformed SSH packet

* * *

89. SSRF Tests
    ==============

必须验证以下目标无法通过 Asset API 连接：
    localhost127.0.0.1::1link-localmetadata addressesprivate IPmalformed hostnameDNS rebinding candidate

* * *

90. Audit Tests
    ===============

验证：
    session startsession endfailed connectionadmin terminaterecording flushrecording replaychunk hashmanifest hashcommand heuristiccredential replace audit

* * *

91. Browser Tests
    =================

推荐 Playwright。

至少：
    loginMFAasset listingunauthorized asset invisibilityopen terminalresizedisconnectadmin asset CRUDauthorization CRUDaudit replay

* * *

92. Security Acceptance Criteria
    ================================

以下任何一条失败都不能算 V1 完成：

1. Browser 无法获取 SSH Credential。

2. Credential API 无明文读取接口。

3. D1 中没有 SSH Credential 明文。

4. Worker Log 没有 SSH Credential。

5. 普通用户无法访问未授权 Asset。

6. 普通用户无法使用未授权 SSH Account。

7. 修改 asset_id/account_id 无法绕过授权。

8. Disabled User 无法创建 Session。

9. Expired Authorization 无法创建 Session。

10. Host Key Changed 时连接被阻止。

11. 用户无法自行信任 changed Host Key。

12. Session Ticket 短时且单次有效。

13. WebSocket 无法跨 Origin 劫持。

14. Session Recording 可以回放。

15. 管理员可以终止在线 Session。

16. 所有敏感管理行为有 Audit Event。

17. Audit Event 中无 Credential 明文。

18. SSRF 防护有效。

19. Login 有 Rate Limit。

20. CSRF 防护有效。

* * *

93. Functional Acceptance Criteria
    ==================================

V1 Demo 应可以完整演示：
    1. Super Admin 登录2. 创建：   Developers Group3. 创建：   Alice   Bob4. Alice 加入 Developers5. 创建 Asset Group：   Production/Web6. 创建 Asset：   prod-web-017. 创建 Credential：   prod-deploy-key8. 创建 SSH Account：   deploy9. deploy Account 绑定：   prod-deploy-key10. 创建 Authorization：    Developers        ↓    Production/Web        ↓    deploy        ↓    connect11. Alice 登录12. Alice 可以看到 prod-web-0113. Alice 看不到其它未授权资产14. Alice 打开 Web Terminal15. Browser 不获得 Private Key16. Worker 连接目标服务器17. Terminal 正常使用18. Auditor 能看到 Online Session19. Auditor 打开 Live Monitor20. Auditor 强制 Terminate21. Alice Terminal 被断开22. Historical Session 出现记录23. 可以 Replay24. Audit Log 显示完整操作链路

完成以上流程后，才认为核心架构闭环。

* * *

94. Implementation Priority
    ===========================

Phase 1 — SSH Core Extraction
-----------------------------

目标：

基于 EdgeSSH 跑通新的 Session Engine。

完成：
    SSHSessionDOSSH EngineTCP Socketxterm.jsHost KeyPassword AuthPrivate Key AuthSession Ticket

暂时可以使用测试 Asset。

* * *

Phase 2 — Authentication
------------------------

完成：
    BootstrapLocal UserPasswordLogin SessionLogoutTOTPRate LimitCSRF

* * *

Phase 3 — Assets & Credentials
------------------------------

完成：
    Asset GroupsAssetsSSH AccountsCredentialsEnvelope EncryptionHost Key Management

* * *

Phase 4 — RBAC
--------------

完成：
    RolesPermissionsGroupsSystem RBAC Middleware

* * *

Phase 5 — Asset Authorization
-----------------------------

完成：
    Authorization RulesUser/GroupAsset/Asset GroupSSH AccountTime WindowPermission Resolver

这一阶段完成后才允许非管理员真正 SSH。

* * *

Phase 6 — Audit
---------------

完成：
    Session MetadataAudit EventsOnline SessionsForce TerminateLive Monitor

* * *

Phase 7 — Recording
-------------------

完成：
    R2 Chunk RecordingManifestHash ChainReplayCommand Heuristic

* * *

Phase 8 — Hardening
-------------------

完成：
    SSRFDNS SafetySecurity HeadersSensitive Log RedactionIDOR TestsRate Limit TestsHost Key TestsPermission Matrix TestsBrowser Tests

* * *

95. Codex 开发要求
    ==============

开发时遵循：
Rule 1
------

不要为了快速完成而把 Credential 发给 Browser。

* * *

Rule 2
------

不要使用前端权限判断作为安全边界。

所有 Authorization 必须 Server-side。

* * *

Rule 3
------

不要绕过 Host Key Verification。

* * *

Rule 4
------

不要把 KV 当权限数据库。

* * *

Rule 5
------

不要把完整 Session Recording 塞进 D1。

* * *

Rule 6
------

不要自己重新实现已经可以从 EdgeSSH 可靠复用的 SSH Protocol。

* * *

Rule 7
------

涉及认证、权限、Credential、Session 的代码必须有测试。

* * *

Rule 8
------

任何敏感 API 默认：
    deny

只有明确授权后：
    allow

* * *

Rule 9
------

任何异常日志都必须考虑 Secret Redaction。

* * *

Rule 10
-------

如需求与安全原则冲突：
    Security > Convenience

* * *

96. MVP 最终形态
    ============

V1 完成后，系统应该是：
                        EdgeJump              ┌─────────────────┐              │     Browser     │              │                 │              │ Users / Admin   │              │ xterm.js        │              └────────┬────────┘                       │                HTTPS / WebSocket                       │                       ▼              ┌─────────────────┐              │ Cloudflare      │              │ Worker          │              │                 │              │ Auth            │              │ RBAC            │              │ Assets          │              │ Authorization   │              │ Audit           │              └───────┬─────────┘                      │          ┌───────────┼───────────┐          │           │           │          ▼           ▼           ▼         D1          R2           KV          │       Recordings     Cache          │          ▼   SSHSession Durable Object          │          │ SSH Client          │          ▼   Cloudflare TCP Socket          │          ▼       SSH Server

用户看到：
    AssetsTerminalMy Sessions

管理员看到：
    UsersGroupsRolesAssetsAsset GroupsSSH AccountsCredentialsAuthorization RulesOnline SessionsHistorical SessionsSession ReplayAudit LogsSettings

* * *

97. V1 成功标准
    ===========

EdgeJump V1 不追求复制整个 JumpServer。

核心成功标准是：

> 在完全不部署传统堡垒机服务器的情况下，使用 Cloudflare Workers / DO / D1 / R2 构建一套真正具备多人协作、精细化权限管控、凭证安全托管、在线终端会话管理与会话审计回放能力的 Cloudflare 原生 SSH 堡垒机系统。
