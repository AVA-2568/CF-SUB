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
assert.match(setCookie, /^__Host-cf_sub_session=/);
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
const encoded = await response.text();
const nodes = Buffer.from(encoded, 'base64').toString('utf8');

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

console.log(`Workers smoke 通过: ${origin}，订阅节点 ${nodes.length} 字符，旧 Cookie 已失效。`);
