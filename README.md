# CF-SUB

通过 Cloudflare Workers 提供个人订阅链接与轻量管理后台。单文件入口，运行时只依赖一个 Workers KV 绑定，不需要 Durable Objects。

当前版本面向“后台粘贴 `_worker.js` + 绑定 KV + 设置变量”的部署方式；`wrangler.toml` 仅用于本地开发或命令行部署。

## 功能

- `GET /sub?token=...`：返回 Base64 订阅，不依赖客户端 UA。
- `GET /admin`：登录页或节点管理页。
- `POST /admin`：登录或保存节点配置。
- `POST /logout`：删除服务端 Session 并清除 Cookie。
- 后台查看历史订阅地区统计（只读）。
- 节点配置上限 128 KiB，超限返回 `413`。

## 部署前准备

需要准备三项配置：

| 名称 | 类型 | 要求 |
| --- | --- | --- |
| `NODE_KV` | KV namespace binding | 名称必须完全一致 |
| `ADMIN_TOKEN` | Secret / 环境变量 | 至少 32 个字符 |
| `SUB_TOKEN` | Secret / 环境变量 | 至少 32 个字符，且不能与 `ADMIN_TOKEN` 相同 |

`NODE_KV` 不是普通环境变量，必须在 Worker 的绑定设置中添加。只添加 `ADMIN_TOKEN`、`SUB_TOKEN` 而缺少 KV 绑定时，页面会返回 `Server misconfigured: missing NODE_KV binding`。

## 在 Cloudflare 后台部署

1. 在 Cloudflare 创建 Workers KV namespace。
2. 进入 Worker 的 `Settings > Bindings`，添加 `KV Namespace`：
   - Variable name：`NODE_KV`
   - KV namespace：选择刚创建的 namespace
3. 在 `Settings > Variables and Secrets` 添加：
   - `ADMIN_TOKEN`：至少 32 字符的随机值
   - `SUB_TOKEN`：至少 32 字符的另一个随机值
4. 将仓库中 `_worker.js` 的全部内容粘贴到 Worker 编辑器，部署。
5. 访问 `https://你的域名/admin` 登录并保存节点配置。

注意：

- 变量名区分大小写，不要给值额外加引号。
- 不需要配置 `AUTH` binding，也不需要 Durable Objects。
- 建议在 Worker 设置中将 compatibility date 设为 `2026-10-23` 或更新日期。
- 使用 Secret 类型保存两个 token，不要写进代码或仓库。

## 使用 Wrangler 部署

安装依赖：

```bash
npm ci
```

创建 KV：

```bash
npx wrangler kv namespace create NODE_KV
```

将返回的 namespace id 写入 `wrangler.toml`：

```toml
[[kv_namespaces]]
binding = "NODE_KV"
id = "你的 KV namespace id"
```

写入两个 Secret：

```bash
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put SUB_TOKEN
```

部署：

```bash
npm run deploy
```

`predeploy` 会检查单文件入口、KV binding 和占位符。正式部署前可先运行：

```bash
npm run check:deploy-config
npm run deploy:dry
```

## 本地开发

按需创建 `.dev.vars`：

```dotenv
ADMIN_TOKEN="local-admin-token-change-me-0123456789abcdef"
SUB_TOKEN="local-sub-token-change-me-0123456789abcdef"
```

运行：

```bash
npm run dev
```

访问 `http://localhost:8787/admin`。生产环境强制 HTTPS。

## KV 数据结构

- `data`：`{ "nodes": "..." }`，节点配置。
- `session:<uuid>`：Session、CSRF 与管理员 token 指纹，TTL 15 分钟。
- `login:<ipHash>`：登录失败计数，TTL 15 分钟。
- `rate:<ipHash>:<窗口>`：每 IP 每分钟登录频率限制。
- `config:initialized`：配置初始化标记，用于避免 KV 数据丢失后被误判为全新部署。
- `stat:<country>`：历史订阅统计，当前版本只读，不再随订阅请求写入。

## 安全设计

- 订阅 token 使用 SHA-256 摘要后的常量时间比较，避免直接字符串比较。
- 订阅响应在单个 isolate 内缓存 60 秒的 Base64 结果，缓存命中时不读 KV、不解析 JSON、不重复编码；后台保存配置会立即清除本 isolate 缓存，其他 isolate 最多 60 秒后更新。
- 订阅拉取不写入任何 KV 统计 key；仅在首次读取已有配置时可能补写 `config:initialized` 初始化标记。后台统计只读取历史数据。
- 订阅只校验 `SUB_TOKEN`，不把 User-Agent 当安全边界；Clash、mihomo、v2rayN、sing-box 等任意客户端都可拉取。
- 管理页使用每次请求生成的 CSP nonce，禁止内联事件处理器和外部资源。
- 所有管理 POST 校验同源 `Origin`，保存和登出还要求 Session 绑定的 CSRF token。
- Session 使用 `__Host-cf_sub_session` Cookie：`Path=/`、`Secure`、`HttpOnly`、`SameSite=Strict`，15 分钟过期。
- Session 记录管理员 token 的 SHA-256 指纹；轮换 `ADMIN_TOKEN` 后既有 Session 自动失效。
- `SUB_TOKEN` 是 URL 中的 Bearer Secret：不要公开分享；怀疑泄露时直接更换并重新部署。
- 订阅 URL 可能出现在 Cloudflare 访问日志、浏览器历史或第三方客户端日志中；不要把链接发给不可信对象。
- `/sub` 不在代码内做 KV 计数或限流，避免每次拉取产生写入；需要抗滥用时使用 Cloudflare WAF Rate Limiting。
- 登录失败 5 次后锁定 15 分钟；另有每 IP 约 10 次/分钟的短时限制。
- 请求体流式读取并在解析前硬限制为 448 KiB，节点内容限制为 128 KiB。
- 订阅与后台响应带 `Cache-Control: no-store`、CSP、HSTS、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy` 和 `Permissions-Policy`。
- 非 localhost 的 HTTP 请求返回 308 跳转到 HTTPS。
- 配置读取 fail-closed：KV 读取异常、JSON 损坏、结构不合法或超限时返回 `500`/`413`，不会回退为空配置。
- 保存时先写 `data` 再写初始化标记；如果标记写入失败，配置已经落盘，后续后台读取可继续补写标记。

### KV 一致性限制

Session、登录计数和限流状态保存在 Workers KV。KV 是最终一致性存储，跨地区读取可能短暂看到旧值；代码只在单个 isolate 内对同一 key 的读改写做串行化，无法提供 Durable Object 级别的全局强一致。后台历史统计属于只读展示，个人低并发场景足够使用；高风险场景建议叠加 Cloudflare Access / WAF。

## 常见问题

### 页面显示 `Server misconfigured`

按提示检查：

- `Server misconfigured: missing NODE_KV binding`：没有绑定 KV，或绑定名不是 `NODE_KV`。
- `Server misconfigured: ADMIN_TOKEN must be at least 32 characters`：变量缺失、名称错误或长度不足。
- `Server misconfigured: SUB_TOKEN must be at least 32 characters`：同上。
- `Server misconfigured: ADMIN_TOKEN and SUB_TOKEN must be different`：两个 token 相同。

修改绑定或变量后需要重新部署 Worker 才会生效。

### `/sub` 返回 `500`

通常是尚未在后台保存节点配置，或 KV 中 `data` 丢失/损坏。登录 `/admin` 保存一次即可；如果已有初始化标记但 `data` 丢失，服务会故意保持 fail-closed。

### 登录后立即跳回登录页

KV 写入跨地区传播存在延迟，等待几秒后重试。若持续出现，检查是否绑定到了正确的 KV namespace。

## 测试

```bash
npm ci
npm run ci
npm run deploy:dry
```

测试覆盖登录与 Session、CSRF/Origin、登录限流、XSS 编码、安全响应头、订阅缓存与配置刷新、零统计写入、历史统计读取、128 KiB 边界、URL 编码请求体、分块 Base64 和流式请求体超限。

## 免责声明

仅供学习与个人使用。请遵守当地法律法规和 Cloudflare 服务条款。
