# CF-SUB 安全与实现加固设计

## 目标

在不改变产品定位和赛博朋克管理界面的前提下，修复配置丢失、登录暴破、Session 无法撤销、CSRF、HTML/JS 注入、订阅编码失败和部署配置漂移问题，并补齐可回归测试与安全运维说明。

## 非目标

- 不引入多用户账户体系。
- 不改变订阅链接形态（仍为 `/sub?token=...`）。
- 不把节点配置迁移到 Durable Object、D1 或外部数据库。
- 不保留旧认证、旧 Cookie 或旧渲染逻辑的兼容层。
- 不重新设计 UI，只调整必要的交互结构和样式类。

## 约束

- 保持单文件 Worker 入口 `_worker.js`，继续支持单文件审阅和 Wrangler 部署。
- Workers KV 保存节点配置与近似统计。
- 一个 Session Durable Object 保存 Session/CSRF 与配置初始化标记；登录失败与分钟级限流按 IP 哈希分片到 256 个 Durable Object。
- 不引入运行时第三方依赖。
- 所有敏感响应使用 `Cache-Control: no-store`。
- 生产 secrets 通过 `wrangler secret put` 配置，不写入仓库。

## 关键决策

### 1. 配置存储

继续使用 KV key `data` 保存节点配置，避免升级丢失既有节点。该 key 只保存 `{ "nodes": "..." }`，不再混入登录状态。

读取规则：

- `data` 存在：校验 JSON、结构和 128 KiB UTF-8 上限，异常时 fail closed。若 DO 标记为 false（旧部署升级），后台读取同步懒迁移写入 true，订阅请求通过 `waitUntil()` 尽力完成。
- `data` 不存在、Durable Object 中 `config:initialized` 为 false：视为全新部署，后台可显示空编辑器。
- `data` 不存在、Durable Object 中 `config:initialized` 为 true：视为配置丢失，返回 `500`，禁止静默重建。
- 保存时先在 Durable Object 写强一致初始化标记，再写 KV `data`；第二步失败会保持 fail-closed，不受 KV 传播窗口影响。升级后首次读取既有 KV 配置也会补写标记，避免旧部署在重新保存前失去丢失检测。
- 配置丢失的恢复方式是通过 Wrangler 从备份写回 `data`；不允许删除初始化标记来绕过保护。

### 2. Session、CSRF 与登录状态

- Cookie：`__Host-cf_sub_session`，`Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900`。
- Durable Object key：`session:<uuid>`，值为 `{ csrf, created, credential }`。Worker 通过内部请求头传递 credential 摘要，不放入 DO 请求 URL。
- Session 同时保存 `ADMIN_TOKEN` 的 SHA-256 指纹；轮换管理员 token 会自动撤销全部既有 Session。
- Session 固定 15 分钟有效；读取时校验时间，alarm 每小时清理过期记录。
- 登出仅接受 `POST /logout`，删除服务端 Session 并清除 Cookie。
- 管理表单和登出表单都携带 Session 绑定 CSRF token。
- 所有管理 POST 在读取 Session 前校验 `Origin === url.origin`。

### 3. 登录限流

- `/admin` POST 先进入 Durable Object 的分钟级 IP 限流，阈值约 10 次/分钟。
- 登录尝试通过 `POST /login-attempt/<sha256(ip)>` 原子预占：读取、判断、递增在单一存储序列中完成。
- 第 5 次失败后锁定 15 分钟；第 6 次及之后的尝试返回 `429`。
- 登录成功删除该 IP 的失败记录。
- 失败/限流状态只存在 Durable Object，不写 KV 配置 key。
- 分布式多 IP 暴破不在单实例限流能力内，生产高风险场景应叠加 Cloudflare WAF / Access。

### 4. 渲染与响应安全

- 非 localhost 的 HTTP 请求直接 308 到 HTTPS；只信任请求 URL 的 scheme，不信任 `X-Forwarded-Proto`。
- 所有动态 HTML 值使用单遍 HTML 实体转义。
- 订阅链接先 `encodeURIComponent`，再作为 HTML 属性转义。
- 移除所有内联事件处理器；复制、保存 loading、Toast 全部使用外部脚本中的 `addEventListener`。
- 登录页和管理页使用每次请求生成的 CSP nonce。
- CSP 禁止内联事件、外部脚本、外部表单提交、嵌套页面与对象加载。
- 统一增加 `X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy`、`Permissions-Policy`、`Strict-Transport-Security` 和 `Cache-Control: no-store`。

### 5. 订阅与请求体

- 只接受 `GET /sub`。
- Token 使用 SHA-256 摘要后的常量时间比较。
- 节点内容按 UTF-8 字节分块 Base64，避免字符串参数展开上限。
- 节点内容上限为 128 KiB；请求体上限为 `3 * 128 KiB + 64 KiB`，覆盖 URL 编码膨胀。
- 128 KiB 上限按 Workers Free 的 10ms CPU 预算确定；订阅编码实测约 6ms，避免 5 MiB 路径触发 1102。
- 流式读取请求体并在超限时取消 reader，不能只信任 `Content-Length`。
- 统计写入 `ctx.waitUntil()`，失败不影响订阅；KV 统计明确标注为近似值。
- 国家代码仅接受两位大写字母/数字，否则归为 `XX`。

### 6. 部署与测试

- `wrangler.toml` 配置 `NODE_KV` 与 `AUTH` Durable Object，使用 `new_sqlite_classes` 迁移。
- `scripts/check-deploy-config.mjs` 在正式部署前检查占位符、KV id、binding、迁移和旧限流配置。
- GitHub Actions 使用 Node 22，执行 `npm ci`、语法检查、单测和 Wrangler dry-run。
- Node `node:test` 直接导入 Worker，以 mock KV、Durable Object storage 和 `ctx.waitUntil()` 覆盖关键行为。

## 验收标准

- KV 读取异常或结构损坏时，登录不会清空原有节点，订阅返回 `500`。
- 登出后旧 Cookie 不能再次访问管理页。
- 并发错误登录最多放行 5 次，配置 key 不被修改；成功登录清零失败计数。
- 统计通过 KV `get(keys)` 分批读取并展示。
- 128 KiB 边界可以正常返回 Base64；URL 编码边界可正确保存，超限返回 `413`。
- 恶意 Origin、缺失或错误 CSRF 返回 `403`。
- 管理页 token 不能闭合 `input` 属性或 `<script>`。
- 管理页和订阅响应包含安全头。
- `npm ci`、`npm run ci`、`npm run deploy:dry` 全部通过，dry-run 显示 `AUTH` Durable Object binding。
