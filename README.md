# CF-SUB

通过 Cloudflare Workers 提供个人订阅链接与轻量管理后台。节点配置保存在 Workers KV；Session、CSRF 与登录限流由 Durable Object 原子管理。

当前版本重点加固了配置数据保护、服务端 Session 撤销、登录暴破防护、CSRF、HTML 注入、订阅编码和部署配置校验。

## 功能

- `GET /sub?token=...`：按客户端 UA 返回 Base64 订阅。
- `GET /admin`：登录页或节点管理页。
- `POST /admin`：登录或保存节点配置。
- `POST /logout`：服务端撤销当前 Session 并清除 Cookie。
- 后台查看订阅地区与近似请求统计。
- 支持 128 KiB 以内节点配置；超限返回 `413`。该上限按 Workers Free 的 10ms CPU 限额实测确定。

## 架构与存储

- `NODE_KV`：`data` 保存 `{ "nodes": "..." }`，`stat:<country>` 保存近似统计。
- `AUTH`：一个 Session Durable Object 保存 Session/CSRF 和 `config:initialized` 强一致初始化标记；登录失败与分钟级限流按 IP 哈希分片到 256 个 Durable Object。
- 不引入运行时第三方依赖，入口保持为单文件 `_worker.js`。

## 前置要求

- Node.js 22+
- Cloudflare 账号
- Wrangler CLI（由项目依赖提供）
- 一个 Workers KV namespace
- Durable Objects（`wrangler.toml` 已配置 SQLite-backed class）

## 配置

安装依赖：

```bash
npm ci
```

### 1. 创建 KV

```bash
npx wrangler kv namespace create NODE_KV
```

把返回的 namespace id 写入 `wrangler.toml`：

```toml
[[kv_namespaces]]
binding = "NODE_KV"
id = "你的 KV namespace id"
```

### 2. Durable Object 配置

`wrangler.toml` 已包含以下配置，不要删除：

```toml
[[durable_objects.bindings]]
name = "AUTH"
class_name = "AuthDurableObject"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["AuthDurableObject"]
```

首次部署会创建 `AuthDurableObject`。后续不要修改已部署的 `v1` 迁移语义；需要新增 class 时使用新的迁移 tag。

### 3. 配置 Secrets

不要把密钥写进仓库或 `wrangler.toml`：

```bash
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put SUB_TOKEN
```

两个 token 至少 32 个字符，建议使用密码管理器生成 48 字符以上的随机值。`ADMIN_TOKEN` 用于后台登录，`SUB_TOKEN` 用于订阅链接，二者必须不同。`SUB_TOKEN` 的高熵值本身就是防止订阅 token 被枚举的主要边界。

### 4. 本地开发

按需创建 `.dev.vars`：

```dotenv
ADMIN_TOKEN="local-admin-token-change-me-0123456789abcdef"
SUB_TOKEN="local-sub-token-change-me-0123456789abcdef"
```

运行：

```bash
npm run dev
```

访问 `http://localhost:8787/admin`。生产环境必须使用 HTTPS。

### 5. 部署

先替换 `wrangler.toml` 中的 KV namespace 占位符，再执行：

```bash
npm run deploy
```

`predeploy` 会检查 KV id、`NODE_KV`/`AUTH` binding、SQLite 迁移和残留占位符；检查失败会阻止部署。请使用 `npm run deploy`，不要直接调用 `npx wrangler deploy` 绕过检查。部署后访问：

```text
https://你的域名/admin
```

登录后页面会显示订阅链接。

### 6. Workers 部署后验收

用环境变量指向已部署的 Worker，执行只读 smoke（登录、后台访问、订阅读取、登出撤销，不会改写节点配置）：

```bash
WORKER_URL="https://你的域名" \
ADMIN_TOKEN="你的 ADMIN_TOKEN" \
SUB_TOKEN="你的 SUB_TOKEN" \
npm run smoke:workers
```

PowerShell 写法：

```powershell
$env:WORKER_URL = "https://你的域名"
$env:ADMIN_TOKEN = "你的 ADMIN_TOKEN"
$env:SUB_TOKEN = "你的 SUB_TOKEN"
npm run smoke:workers
```

如果刚部署还没保存节点，`/sub` 会返回 `500`，smoke 会明确提示先完成首次配置。

## 安全设计

- 配置读取 fail-closed：KV 读取异常、JSON 损坏、结构不合法或超过 128 KiB 时返回 `500`/`413`，不会回退为空配置。
- 保存时先在 Durable Object 写强一致 `config:initialized`，再写 KV `data`；第二步失败会留下可检测的 fail-closed 状态，不会把旧配置误判为全新部署。升级后首次读取既有 KV 配置也会懒迁移写入该标记：后台读取同步完成，订阅请求通过 `waitUntil()` 尽力完成，无需先保存一次。
- Session 使用 `__Host-cf_sub_session` Cookie：`Path=/`、`Secure`、`HttpOnly`、`SameSite=Strict`，15 分钟过期。
- Session、CSRF 与登录失败状态存放在 Durable Object，登出后旧 Cookie 立即失效，不依赖 KV 最终一致性。
- Session 绑定 `ADMIN_TOKEN` 的 SHA-256 指纹；轮换管理员 token 会自动撤销全部既有 Session。
- 所有管理 POST 校验 `Origin === url.origin`；保存和登出还要求 Session 绑定的 CSRF token。
- 登录尝试由 Durable Object 原子预占，失败 5 次后锁定 15 分钟；另有每 IP 约 10 次/分钟的短时限流。限流按 IP 哈希前缀分片，避免所有来源挤占同一个实例。
- 管理页使用每次请求生成的 CSP nonce，禁止内联事件处理器和外部资源；动态值按 HTML 上下文转义。
- 订阅 token 采用常量时间比较；Base64 按 UTF-8 字节分块生成，避免大配置触发参数上限。
- 请求体硬限制为 448 KiB（`3 * 128 KiB + 64 KiB`，容纳 UTF-8 内容的 URL 编码膨胀），解析前即拒绝超限流式请求。
- 所有敏感响应带 `Cache-Control: no-store`、CSP、HSTS、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy` 和 `Permissions-Policy`。
- 非 localhost 的 HTTP 请求直接 308 到 HTTPS，不信任客户端可伪造的 `X-Forwarded-Proto`。
- 登录失败记录按来源 IP 隔离，不写配置 key，也不会形成全账号统一锁死。

## 运维注意

- 升级后旧 Session 失效，需要重新登录。
- 旧版本 Cookie 名称为 `admin_session`，新版本只读取 `__Host-cf_sub_session`。
- `GET /logout` 返回 `405`，登出必须使用后台页面表单或 `POST /logout`。
- 管理 POST 需要浏览器发送同源 `Origin` 头；使用 curl 调试时要手动添加。
- 不要把订阅链接、后台 token 或 `.dev.vars` 提交到 Git。
- 如果发现密钥泄露，立即用 `npx wrangler secret put` 轮换；轮换 `ADMIN_TOKEN` 会自动使全部既有 Session 失效。
- 升级后首次访问后台或订阅时可能会补写初始化标记，这是预期行为。
- KV 统计存在并发丢写和最终一致性，仅用于趋势参考；需要精确统计时应换 Analytics Engine。
- 当前限流按 IP 生效，无法抵御大量分布式 IP 的定向暴破；高风险场景建议叠加 Cloudflare WAF / Access。

如果 Durable Object 中的 `config:initialized` 仍存在但 KV `data` 丢失，服务会故意返回 `500`，不要删除初始化标记来强制重建。请从备份恢复 `data`：

```bash
npx wrangler kv key put data --binding NODE_KV --path restored-data.json --remote
```

其中 `restored-data.json` 的内容必须是 `{"nodes":"..."}`，且换算后的 UTF-8 字节数不超过 128 KiB。

## 测试与校验

```bash
npm ci
npm run ci
npm run deploy:dry
```

`npm run ci` 会执行语法检查和全部 Node 测试。CI 还会用 `check:deploy-config:ci` 校验配置结构、用 `deploy:dry` 验证 Worker 打包与 binding。正式部署前请再运行严格检查：

```bash
npm run check:deploy-config
```

测试覆盖配置 fail-closed、标记写失败、Session 撤销与 token 轮换、并发登录锁定、CSRF/Origin、XSS 编码、安全响应头、统计读取、128 KiB 边界、URL 编码请求体、分块 Base64 和流式请求体超限。

## 免责声明

仅供学习与个人使用。请遵守当地法律法规和 Cloudflare 服务条款。
