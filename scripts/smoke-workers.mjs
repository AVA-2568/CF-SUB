import assert from 'node:assert/strict';

const workerUrl = process.env.WORKER_URL;
const adminToken = process.env.ADMIN_TOKEN;
const subToken = process.env.SUB_TOKEN;
const missing = [
  ['WORKER_URL', workerUrl],
  ['ADMIN_TOKEN', adminToken],
  ['SUB_TOKEN', subToken],
].filter(([, value]) => !value).map(([name]) => name);

if (missing.length > 0) {
  console.error(`缺少环境变量: ${missing.join(', ')}`);
  process.exit(1);
}

const origin = new URL(workerUrl).origin;
// 注意：CF-Connecting-IP 仅在本地 wrangler dev 生效，Cloudflare 线上边缘节点会自动覆盖为真实客户端 IP。
const clientIp = process.env.SMOKE_CLIENT_IP || `203.0.113.${(Date.now() % 200) + 1}`;

function request(path, init = {}) {
  return fetch(new URL(path, origin), {
    redirect: 'manual',
    ...init,
    signal: init.signal || AbortSignal.timeout(15_000),
    headers: {
      'CF-Connecting-IP': clientIp,
      ...(init.headers || {}),
    },
  });
}

let response = await request('/admin');
assert.equal(response.status, 200, `GET /admin 应为 200，实际 ${response.status}`);
assert.match(await response.text(), /ADMIN ACCESS/);

response = await request('/admin', {
  method: 'POST',
  headers: {
    Origin: origin,
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({ password: adminToken }),
});
if (response.status === 429) {
  throw new Error('登录被限流（429），请等待 1-15 分钟后重试');
}
assert.equal(response.status, 303, `登录应返回 303，实际 ${response.status}`);

const setCookie = response.headers.get('set-cookie') || '';
assert.match(setCookie, /^__Host-sid=/);
assert.match(setCookie, /Secure/);
assert.match(setCookie, /HttpOnly/);
assert.match(setCookie, /SameSite=Strict/);
const cookie = setCookie.split(';')[0];

response = await request('/admin', { headers: { Cookie: cookie } });
assert.equal(response.status, 200, `登录后 GET /admin 应为 200，实际 ${response.status}`);
const adminHtml = await response.text();
assert.match(adminHtml, /NODE CONTROL/);
const csrf = adminHtml.match(/name="csrf"\s+value="([^"]+)"/)?.[1];
assert.ok(csrf, '管理页缺少 CSRF token');

response = await request(`/sub?token=${encodeURIComponent(subToken)}`);
if (response.status === 500) {
  throw new Error('订阅返回 500：请先在后台保存节点配置，或检查 NODE_KV 绑定与配置初始化标记');
}
assert.equal(response.status, 200, `GET /sub 应为 200，实际 ${response.status}`);
assert.equal(response.headers.get('cache-control'), 'no-store');
assert.match(response.headers.get('content-security-policy') || '', /default-src 'none'/);
assert.ok(response.headers.get('profile-update-interval'), '订阅响应缺少 Profile-Update-Interval');

const encoded = await response.text();
assert.match(encoded, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/, '订阅响应不是合法的标准 Base64');
const nodes = Buffer.from(encoded, 'base64').toString('utf8');
assert.equal(nodes.includes('\r'), false, '订阅解码内容不应包含 CR 回车符');

response = await request('/logout', {
  method: 'POST',
  headers: {
    Cookie: cookie,
    Origin: origin,
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({ csrf }),
});
assert.equal(response.status, 303, `登出应返回 303，实际 ${response.status}`);

response = await request('/admin', { headers: { Cookie: cookie } });
assert.equal(response.status, 200);
assert.equal((await response.text()).includes('NODE CONTROL'), false, '登出后旧 Cookie 仍能访问后台');

console.log(`Workers smoke 通过: ${origin}，订阅节点 ${nodes.length} 字符，Base64 与安全头均合法，旧 Cookie 已失效。`);
