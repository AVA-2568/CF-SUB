# CF-SUB 安全与实现加固实施计划

**Goal:** 修复 CF-SUB 的配置数据丢失、Session 撤销、登录暴破、HTML/JS 注入、订阅编码和部署配置问题，并补齐测试、CI 与运维文档。

**Architecture:** 保持单个 `_worker.js` 入口。节点配置与统计存 KV；Session/CSRF 与强一致配置初始化标记存一个 `AuthDurableObject`，登录失败和分钟级限流按 IP 哈希分片到 256 个 `AuthDurableObject`。测试直接导入 Worker，通过 mock KV、Durable Object storage 与 `ctx.waitUntil()` 驱动。

**Tech Stack:** Cloudflare Workers、Workers KV、Durable Objects（SQLite-backed）、原生 Web APIs、Node `node:test`、Wrangler。

**Spec:** `docs/superpowers/specs/2026-10-23-security-hardening-design.md`

## Global Constraints

- 单文件 Worker 入口为 `_worker.js`。
- 不引入运行时第三方依赖。
- Cookie 名为 `__Host-cf_sub_session`，`Path=/`，`Secure`，`HttpOnly`，`SameSite=Strict`。
- 配置 key 保持 `data`，只保存 `{nodes}`。
- Session TTL 为 900 秒；登录失败 5 次后锁定 900 秒。
- 节点内容上限 128 KiB；请求体上限 `3 * 128 KiB + 64 KiB`。
- 所有敏感响应使用 `Cache-Control: no-store`。
- 所有管理 POST 校验同源 Origin；保存/登出校验 CSRF。
- 不保留旧 `admin_session` Cookie、旧 KV Session 或旧 Rate Limiting binding。

## Review Focus

- KV 读取异常时配置保持不变，且不会静默回退为空配置。
- 登出后旧 Cookie 重放不能访问后台。
- 并发登录失败被原子限制为 5 次，成功登录清零失败状态。
- `SUB_TOKEN` 含引号、`</script>`、`&` 时管理页结构完整且链接可用。
- 128 KiB 边界、URL 编码膨胀、超大流式表单与缺失 Content-Type 返回正确状态码。
- `wrangler.toml` binding 与代码访问路径一致，CI 可从零安装并完成 dry-run。

---

### Task 1: 建立测试基线并锁定回归行为

**Files:** `package.json`、`tests/worker.test.js`、`tests/helpers.js`、`package-lock.json`

- [x] 写配置 fail-closed、Session 撤销与 token 轮换、登录限流、CSRF、XSS、安全头、统计和 128 KiB 边界测试。
- [x] 运行旧实现确认行为失败，而非测试语法失败。
- [x] 实现 `MockKV`、`MockDOStorage`、`MockAuthNamespace`、`MockCtx`。
- [x] 提交测试基线 `94f8f11`。

### Task 2: 重写配置、Session、登录和路由

**Files:** `_worker.js`、`tests/worker.test.js`

**Interfaces:** `getConfig(env, options)`、`saveConfig(env, nodes)`、`createSession(env)`、`getSession(req, env)`、`handleLogout(req, env, url)`、`AuthDurableObject`。

- [x] 配置读取 fail-closed；使用 KV `data` + Durable Object `config:initialized` 区分全新部署与配置丢失。
- [x] 升级时对既有 KV 配置懒迁移初始化标记：后台同步等待，订阅通过 `waitUntil()` 尽力完成。
- [x] 保存只写节点；读取校验 JSON、结构与 UTF-8 字节上限。
- [x] Session/CSRF 迁移到 Durable Object，Cookie 使用 `__Host-` 前缀，Session 绑定 ADMIN_TOKEN 指纹。
- [x] 登录尝试在 Durable Object 内原子预占；5 次失败锁定 15 分钟，成功登录清除失败记录。
- [x] 分钟级 IP 限流迁移到按 IP 哈希分片的 Durable Object，移除 Rate Limiting binding。
- [x] 登出改为 `POST`，删除服务端 Session。
- [x] `/sub`、`/admin`、`/logout` 做严格方法限制，`405/413/415` 映射完整。
- [x] 测试覆盖并发锁定上限、成功登录清零、旧 Cookie 失效和 token 轮换撤销。

### Task 3: 加固 HTML 渲染与响应头

**Files:** `_worker.js`、`tests/worker.test.js`

- [x] 移除全部内联事件处理器，复制、保存 loading、Toast 改用 `addEventListener`。
- [x] 订阅 token 先 URL 编码，再按 HTML 属性上下文转义。
- [x] 节点内容、CSRF、统计字段均上下文转义。
- [x] 每次请求生成 CSP nonce，覆盖 style/script。
- [x] 统一 CSP、`no-store`、HSTS、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`、`Permissions-Policy`。
- [x] 测试覆盖恶意 token、CSP nonce、无内联 handler 与安全响应头。

### Task 4: 修复订阅编码、统计和输入边界

**Files:** `_worker.js`、`tests/worker.test.js`

- [x] UTF-8 字节分块 Base64，覆盖上限 128 KiB 内容。
- [x] 请求体流式硬限制为 `3 * 128 KiB + 64 KiB`，覆盖 URL 编码膨胀。
- [x] 精确校验节点 UTF-8 字节数，超限返回 `413`。
- [x] 统计通过 KV `get(keys)` 每批 100 个读取，分页处理 cursor。
- [x] 统计写入 `ctx.waitUntil()`，失败只记录日志；UI 标注为 KV 尽力统计。
- [x] 订阅 token 使用常量时间比较；国家代码严格限定两位大写字母/数字。

### Task 5: 部署配置、CI 与文档

**Files:** `wrangler.toml`、`.github/workflows/ci.yml`、`.gitignore`、`README.md`、`scripts/check-deploy-config.mjs`

- [x] `wrangler.toml` 配置 `NODE_KV`、`AUTH` binding 与 `new_sqlite_classes` 迁移。
- [x] 增加部署前检查脚本，拒绝占位符、非法 KV id、错误 binding 和旧 `[[ratelimits]]`。
- [x] GitHub Actions 使用 Node 22，执行 `npm ci`、`npm run ci`、`npm run deploy:dry`。
- [x] README 更新 KV、Durable Object、secrets、部署、安全设计与运维注意事项。
- [x] 设计文档同步为 Durable Object 架构。
- [x] CI 增加 `check:deploy-config:ci`，以结构校验覆盖真实 `wrangler.toml` 并允许本地占位符。

### Task 6: 全量验证

- [x] `npm ci` 从锁文件重装依赖，依赖审计 0 漏洞。
- [x] `npm run ci` 全部通过（39/39）。
- [x] `npm run deploy:dry` 通过，并显示 `AUTH` Durable Object binding。
- [x] `wrangler dev`（workerd）链路验证：登录、保存、`/sub` Base64、128 KiB UTF-8 配置、登出后旧 Cookie 失效。
- [x] 复核 git diff，确认无 secrets、无 `.dev.vars`、无构建产物。

## Self-Review

- [x] 配置、Session、限流、CSRF、CSP、统计、Base64、输入边界均有回归测试。
- [x] 代码中的存储绑定与 `wrangler.toml` 一致。
- [x] 未保留旧 `login_fail`、旧 Session KV、旧 Cookie 或旧 Rate Limiting 路径。
- [x] 单文件入口和现有 UI 方向保持不变。
