import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MockCtx,
  MockKV,
  assertSecurityHeaders,
  createEnv,
  extractCsrf,
  form,
  getAdminHtml,
  getCookie,
  loadWorker,
  login,
  makeRequest,
  seedConfig,
} from './helpers.js';

const MAX_NODES_BYTES = 128 * 1024;

test('login never reads or writes config, so a config read failure cannot wipe nodes', async () => {
  const worker = await loadWorker();
  const kv = new MockKV();
  await kv.put('data', JSON.stringify({ nodes: 'ORIGINAL-NODES' }));
  kv.failKeys.add('data');
  const env = createEnv({ NODE_KV: kv });
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 303);
  kv.failKeys.delete('data');
  const stored = JSON.parse(await kv.get('data'));
  assert.equal(stored.nodes, 'ORIGINAL-NODES');
});

test('authenticated admin page fails closed when config cannot be read', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  env.NODE_KV.failKeys.add('data');
  const response = await worker.fetch(makeRequest('/admin', {
    headers: { Cookie: cookie },
  }), env, new MockCtx());
  assert.equal(response.status, 500);
});

test('login cookie is host-scoped to / and logout revokes the server session', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { response, cookie } = await login(worker, env);
  assert.equal(response.status, 303);
  const setCookie = response.headers.get('set-cookie') || '';
  assert.match(setCookie, /^__Host-sid=/);
  assert.match(setCookie, /Path=\//);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.match(setCookie, /Max-Age=900/);
  const admin = await getAdminHtml(worker, env, cookie);
  assert.equal(admin.response.status, 200);
  const csrf = extractCsrf(admin.html);
  assert.ok(csrf);
  const logout = await worker.fetch(makeRequest('/logout', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ csrf }),
  }), env, new MockCtx());
  assert.equal(logout.status, 303);
  const after = await getAdminHtml(worker, env, cookie);
  assert.equal(after.html.includes('NODE CONTROL'), false);
});

test('CSRF tokens are bound to their own session', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const first = await login(worker, env);
  const second = await login(worker, env);
  const firstAdmin = await getAdminHtml(worker, env, first.cookie);
  const firstCsrf = extractCsrf(firstAdmin.html);
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: second.cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'CROSS-SESSION', csrf: firstCsrf }),
  }), env, new MockCtx());
  assert.equal(response.status, 403);
});

test('rotating ADMIN_TOKEN invalidates existing sessions', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  env.ADMIN_TOKEN = 'rotated-admin-secret-0123456789abcdef';
  const admin = await getAdminHtml(worker, env, cookie);
  assert.equal(admin.response.status, 200);
  assert.equal(admin.html.includes('NODE CONTROL'), false);
});

test('concurrent failed logins are capped at five in one isolate and never touch config', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'PRESERVED-NODES');
  const requests = Array.from({ length: 6 }, () => worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({ password: 'wrong-password' }),
  }), env, new MockCtx()));
  const responses = await Promise.all(requests);
  assert.equal(responses.filter((response) => response.status === 401).length, 5);
  assert.equal(responses.filter((response) => response.status === 429).length, 1);
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes, 'PRESERVED-NODES');
  assert.equal('login_fail' in stored, false);
});

test('a correct password clears previous failures without weakening the lockout', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const headers = { Origin: 'https://example.com', 'CF-Connecting-IP': '203.0.113.20' };

  for (let i = 0; i < 4; i += 1) {
    const response = await worker.fetch(makeRequest('/admin', {
      method: 'POST',
      headers,
      body: form({ password: 'wrong-password' }),
    }), env, new MockCtx());
    assert.equal(response.status, 401);
  }

  const success = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers,
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(success.status, 303);

  for (let i = 0; i < 5; i += 1) {
    const response = await worker.fetch(makeRequest('/admin', {
      method: 'POST',
      headers,
      body: form({ password: 'wrong-password' }),
    }), env, new MockCtx());
    assert.equal(response.status, 401);
  }

  const failureKeys = await env.NODE_KV.list({ prefix: 'login:' });
  assert.equal(failureKeys.keys.length, 1);
  const failure = JSON.parse(await env.NODE_KV.get(failureKeys.keys[0].name));
  assert.equal(failure.count, 5);
});

test('historical stats are loaded from KV multi-get and rendered in admin', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  await env.NODE_KV.put('stat:US', '7');
  const { html } = await getAdminHtml(worker, env, cookie);
  assert.match(html, /<td>US<\/td>/);
  assert.match(html, /<td>7<\/td>/);
});

test('maximum-size subscription payload encodes successfully', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const nodes = 'a'.repeat(MAX_NODES_BYTES);
  await seedConfig(env, nodes);
  const response = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(response.status, 200);
  const encoded = await response.text();
  assert.ok(encoded.length > MAX_NODES_BYTES);
  assert.equal(atob(encoded).length, nodes.length);
});

test('subscription body is served from isolate cache without rereading KV', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'CACHE-NODES');
  const ctx = new MockCtx();
  const first = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, ctx);
  assert.equal(first.status, 200);
  await ctx.flush();

  env.NODE_KV.failKeys.add('data');
  const second = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(second.status, 200);
  assert.equal(Buffer.from(await second.text(), 'base64').toString('utf8'), 'CACHE-NODES');
});

test('saving config invalidates the cached subscription body', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'OLD-NODES');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);

  const first = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(Buffer.from(await first.text(), 'base64').toString('utf8'), 'OLD-NODES');

  const save = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'NEW-NODES', csrf }),
  }), env, new MockCtx());
  assert.equal(save.status, 303);

  const second = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(Buffer.from(await second.text(), 'base64').toString('utf8'), 'NEW-NODES');
});

test('subscription Base64 preserves UTF-8 content', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const nodes = '节点-北京 🚀\nss://YWVzLTI1Ni1nY206cGFzcw==@example.com:443#🇭🇰';
  await seedConfig(env, nodes);
  const response = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'sing-box/1.10' },
  }), env, new MockCtx());
  assert.equal(response.status, 200);
  const encoded = await response.text();
  const bytes = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
  assert.equal(new TextDecoder().decode(bytes), nodes);
});

test('nodes larger than 128 KiB are rejected', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'x'.repeat(MAX_NODES_BYTES + 1), csrf }),
  }), env, new MockCtx());
  assert.equal(response.status, 413);
});

test('a maximum-size URL-encoded node payload survives form parsing', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'ORIGINAL');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  const nodes = '中'.repeat(Math.floor(MAX_NODES_BYTES / 3));
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: new URLSearchParams({ nodes, csrf }),
  }), env, new MockCtx());
  assert.equal(response.status, 303);
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes, nodes);
});

test('authenticated saves require same origin and a valid CSRF token', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'ORIGINAL');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  const badOrigin = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://attacker.example.com' },
    body: form({ nodes: 'ATTACKER', csrf }),
  }), env, new MockCtx());
  assert.equal(badOrigin.status, 403);
  const missingCsrf = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'NO-CSRF' }),
  }), env, new MockCtx());
  assert.equal(missingCsrf.status, 403);
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes, 'ORIGINAL');
});

test('admin page escapes subscription token and uses nonce CSP without inline handlers', async () => {
  const worker = await loadWorker();
  const env = createEnv({ SUB_TOKEN: `safe</script><img src=x onerror=alert(1)>" onfocus="alert(2)&` });
  const { cookie } = await login(worker, env);
  const { response, html } = await getAdminHtml(worker, env, cookie);
  assert.equal(response.status, 200);
  assert.equal(html.includes('</script><img'), false);
  assert.equal(html.includes('" onfocus="'), false);
  assert.equal(/onclick\s*=/i.test(html), false);
  assert.match(html, /nonce="[^"]+"/);
});

test('admin and subscription responses include security headers', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  const loginResponse = await worker.fetch(makeRequest('/admin'), env, new MockCtx());
  assert.equal(loginResponse.status, 200);
  assertSecurityHeaders(loginResponse);
  const sub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(sub.status, 200);
  assert.equal(sub.headers.get('cache-control'), 'no-store');
  assert.equal(sub.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(sub.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(sub.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');
  assert.match(sub.headers.get('strict-transport-security') || '', /max-age=/);
});

test('only documented methods are accepted', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const getLogout = await worker.fetch(makeRequest('/logout'), env, new MockCtx());
  assert.equal(getLogout.status, 405);
  const postSub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    method: 'POST',
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(postSub.status, 405);
});

test('a missing NODE_KV binding fails closed', async () => {
  const worker = await loadWorker();
  const env = createEnv({ NODE_KV: undefined });
  const response = await worker.fetch(makeRequest('/admin'), env, new MockCtx());
  assert.equal(response.status, 500);
  assert.match(await response.text(), /NODE_KV/);
});

test('a valid CSRF save persists only nodes', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'NEW-NODES', csrf }),
  }), env, new MockCtx());
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), '/admin?saved=1');
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.deepEqual(stored, { nodes: 'NEW-NODES' });
  assert.equal(await env.NODE_KV.get('config:initialized'), '1');
});

test('a marker write failure keeps the saved config and can recover', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'ORIGINAL-NODES');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  await env.NODE_KV.delete('config:initialized');
  env.NODE_KV.failPuts.add('config:initialized');
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'REPLACEMENT', csrf }),
  }), env, new MockCtx());
  assert.equal(response.status, 500);
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes, 'REPLACEMENT');
  assert.equal(await env.NODE_KV.get('config:initialized'), null);

  env.NODE_KV.failPuts.delete('config:initialized');
  const recoveredWorker = await loadWorker();
  const recovered = await getAdminHtml(recoveredWorker, env, cookie);
  assert.equal(recovered.response.status, 200);
  assert.match(recovered.html, /REPLACEMENT/);
  assert.equal(await env.NODE_KV.get('config:initialized'), '1');
});

test('a data write failure leaves a fresh deployment retryable', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  env.NODE_KV.failPuts.add('data');
  const save = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'LOST-WRITE', csrf }),
  }), env, new MockCtx());
  assert.equal(save.status, 500);
  assert.equal(await env.NODE_KV.get('data'), null);
  assert.equal(await env.NODE_KV.get('config:initialized'), null);

  env.NODE_KV.failPuts.delete('data');
  const retryPage = await getAdminHtml(worker, env, cookie);
  assert.equal(retryPage.response.status, 200);
  const retryCsrf = extractCsrf(retryPage.html);
  const retry = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'RETRY-NODES', csrf: retryCsrf }),
  }), env, new MockCtx());
  assert.equal(retry.status, 303);
  assert.equal(JSON.parse(await env.NODE_KV.get('data')).nodes, 'RETRY-NODES');
  assert.equal(await env.NODE_KV.get('config:initialized'), '1');
});

test('a data write failure on an existing config preserves the old nodes', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'ORIGINAL-NODES');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  env.NODE_KV.failPuts.add('data');
  const save = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'REPLACEMENT', csrf }),
  }), env, new MockCtx());
  assert.equal(save.status, 500);
  assert.equal(JSON.parse(await env.NODE_KV.get('data')).nodes, 'ORIGINAL-NODES');
  assert.equal(await env.NODE_KV.get('config:initialized'), '1');
});

test('subscription accepts any client user agent and still requires the token', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  const missingToken = await worker.fetch(makeRequest('/sub', {
    headers: { 'User-Agent': 'clash.meta/1.19.0' },
  }), env, new MockCtx());
  assert.equal(missingToken.status, 404);
  const badToken = await worker.fetch(makeRequest('/sub?token=wrong', {
    headers: { 'User-Agent': 'clash.meta/1.19.0' },
  }), env, new MockCtx());
  assert.equal(badToken.status, 404);
  const valid = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'clash.meta/1.19.0' },
  }), env, new MockCtx());
  assert.equal(valid.status, 200);
});

test('subscription fetch does not write KV statistics', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  await env.NODE_KV.put('config:initialized', '1');
  const writesBefore = env.NODE_KV.puts.length;
  const ctx = new MockCtx();
  const first = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0', 'CF-IPCountry': 'US' },
  }), env, ctx);
  assert.equal(first.status, 200);
  await ctx.flush();

  const second = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0', 'CF-IPCountry': 'US' },
  }), env, new MockCtx());
  assert.equal(second.status, 200);
  assert.equal(env.NODE_KV.puts.length, writesBefore);
  assert.equal(await env.NODE_KV.get('stat:US'), null);
});

test('admin POST rejects unsupported content types', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com', 'Content-Type': 'text/plain' },
    body: 'password=admin-test-secret-0123456789abcdef',
  }), env, new MockCtx());
  assert.equal(response.status, 415);
});

test('subscription fails closed when config cannot be read', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'ORIGINAL-SUB-NODES');
  env.NODE_KV.failKeys.add('data');
  const response = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(response.status, 500);
  env.NODE_KV.failKeys.delete('data');
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes, 'ORIGINAL-SUB-NODES');
});

test('localhost HTTP is allowed for local development', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(new Request('http://localhost:8787/admin', { redirect: 'manual' }), env, new MockCtx());
  assert.equal(response.status, 200);
});

test('admin and subscription tokens must be different', async () => {
  const worker = await loadWorker();
  const env = createEnv({ SUB_TOKEN: 'admin-test-secret-0123456789abcdef' });
  const response = await worker.fetch(makeRequest('/admin'), env, new MockCtx());
  assert.equal(response.status, 500);
});

test('admin password shorter than 8 characters is rejected', async () => {
  const worker = await loadWorker();
  const envShort = createEnv({ ADMIN_TOKEN: '1234567' });
  const resShort = await worker.fetch(makeRequest('/admin'), envShort, new MockCtx());
  assert.equal(resShort.status, 500);

  const envValid = createEnv({ ADMIN_TOKEN: '12345678' });
  const resValid = await worker.fetch(makeRequest('/admin'), envValid, new MockCtx());
  assert.equal(resValid.status, 200);
});

test('subscription token shorter than 16 characters is rejected', async () => {
  const worker = await loadWorker();
  const envShort = createEnv({ SUB_TOKEN: '123456789012345' });
  const resShort = await worker.fetch(makeRequest('/admin'), envShort, new MockCtx());
  assert.equal(resShort.status, 500);

  const envValid = createEnv({ SUB_TOKEN: '1234567890123456' });
  const resValid = await worker.fetch(makeRequest('/admin'), envValid, new MockCtx());
  assert.equal(resValid.status, 200);
});

test('login succeeds without Origin header when valid Referer is present (Safari behavior)', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: {
      Referer: 'https://example.com/admin',
    },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 303);
  const cookie = getCookie(response);
  assert.ok(cookie);
});

test('login succeeds without Origin header when Sec-Fetch-Site is same-origin', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: {
      'Sec-Fetch-Site': 'same-origin',
    },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 303);
});

test('login rejects cross-site requests via Sec-Fetch-Site', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: {
      'Sec-Fetch-Site': 'cross-site',
      Origin: 'https://example.com',
    },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 403);
});

test('login rejects cross-site Referer when Origin is absent', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: {
      Referer: 'https://attacker.example.com/login',
    },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 403);
});

test('fresh deployment serves 500 for /sub but still lets admin initialize config', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const sub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(sub.status, 500);
  const { cookie } = await login(worker, env);
  const { response, html } = await getAdminHtml(worker, env, cookie);
  assert.equal(response.status, 200);
  assert.match(html, /<textarea name="nodes"/);
});

test('a missing data key with an initialization marker fails closed', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await login(worker, env);
  await env.NODE_KV.put('config:initialized', '1');
  const sub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(sub.status, 500);
  const { cookie } = await login(worker, env);
  const admin = await getAdminHtml(worker, env, cookie);
  assert.equal(admin.response.status, 500);
});

test('existing KV config is marked initialized on authenticated read', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'LEGACY-NODES');
  const { cookie } = await login(worker, env);
  const { response, html } = await getAdminHtml(worker, env, cookie);
  assert.equal(response.status, 200);
  assert.match(html, /LEGACY-NODES/);
  assert.equal(await env.NODE_KV.get('config:initialized'), '1');
});

test('subscription lazily migrates the marker for existing data', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'LEGACY-SUB-NODES');
  const ctx = new MockCtx();
  const response = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, ctx);
  assert.equal(response.status, 200);
  await ctx.flush();
  assert.equal(await env.NODE_KV.get('config:initialized'), '1');
});

test('x-forwarded-proto cannot bypass the HTTPS redirect on a non-local host', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const request = new Request('http://example.com/admin', {
    headers: { 'x-forwarded-proto': 'https' },
  });
  const response = await worker.fetch(request, env, new MockCtx());
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://example.com/admin');
});

test('sessions are stored in KV with a 15-minute TTL and token-bound credential', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const id = cookie.split('=')[1];
  const raw = await env.NODE_KV.get(`session:${id}`);
  assert.ok(raw);
  const session = JSON.parse(raw);
  assert.match(session.credential, /^[0-9a-f]{64}$/);
  const put = env.NODE_KV.puts.find((entry) => entry.key === `session:${id}`);
  assert.equal(put.options.expirationTtl, 900);
});

test('oversized stored config is rejected on read', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await env.NODE_KV.put('data', JSON.stringify({ nodes: 'x'.repeat(MAX_NODES_BYTES + 1) }));
  const sub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(sub.status, 413);
});

test('stats reads handle more than 100 KV keys in batches', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  for (let i = 0; i < 101; i += 1) {
    const country = String.fromCharCode(65 + Math.floor(i / 26)) + String.fromCharCode(65 + (i % 26));
    await env.NODE_KV.put(`stat:${country}`, String(i + 1));
  }
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  assert.match(html, /<td>AA<\/td>/);
  assert.equal(html.includes('NO DATA'), false);
});

test('stats UI is labelled as historical and read-only', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  assert.match(html, /历史订阅请求/);
  assert.match(html, /统计已停写/);
  assert.equal(html.includes('实时'), false);
});

test('percent-encoded cookie names cannot masquerade as __Host cookies', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const encoded = cookie.replace('__Host-sid=', '%5F%5FHost-sid=');
  const response = await worker.fetch(makeRequest('/admin', {
    headers: { Cookie: encoded },
  }), env, new MockCtx());
  const html = await response.text();
  assert.equal(html.includes('NODE CONTROL'), false);
});

test('chunked request bodies are hard-limited before form parsing', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const chunk = new TextEncoder().encode('x'.repeat(256 * 1024));
  const body = new ReadableStream({
    start(controller) {
      for (let i = 0; i < 2; i += 1) controller.enqueue(chunk);
      controller.close();
    },
  });
  const request = new Request('https://example.com/admin', {
    method: 'POST',
    headers: {
      'x-forwarded-proto': 'https',
      Origin: 'https://example.com',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
    duplex: 'half',
    redirect: 'manual',
  });
  const response = await worker.fetch(request, env, new MockCtx());
  assert.equal(response.status, 413);
});

test('POST without Origin, Referer, or Sec-Fetch-Site is rejected (fail-closed)', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 403);
});

test('POST with Sec-Fetch-Site same-site is rejected', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { 'Sec-Fetch-Site': 'same-site', Origin: 'https://example.com' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 403);
});

test('login rate limit caps at 10 per minute and stops writing KV once exceeded', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const headers = { Origin: 'https://example.com', 'CF-Connecting-IP': '198.51.100.77' };
  const statuses = [];
  for (let i = 0; i < 14; i += 1) {
    const res = await worker.fetch(makeRequest('/admin', {
      method: 'POST',
      headers,
      body: form({ password: env.ADMIN_TOKEN }),
    }), env, new MockCtx());
    statuses.push(res.status);
  }
  assert.equal(statuses.slice(0, 10).every((s) => s === 303), true);
  assert.equal(statuses.slice(10).every((s) => s === 429), true);
  const ratePuts = env.NODE_KV.puts.filter((p) => p.key.startsWith('rate:'));
  assert.equal(ratePuts.length, 10);
});

test('KV 429 write rate limit during login degrades to 429 instead of 500', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  env.NODE_KV.failPut429Prefixes.add('rate:');
  const rateRes = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com', 'CF-Connecting-IP': '198.51.100.88' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(rateRes.status, 429);

  env.NODE_KV.failPut429Prefixes.delete('rate:');
  env.NODE_KV.failPut429Prefixes.add('login:');
  const failRes = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com', 'CF-Connecting-IP': '198.51.100.89' },
    body: form({ password: 'wrong-password' }),
  }), env, new MockCtx());
  assert.equal(failRes.status, 429);
});

test('successful login skips unnecessary login-failure writes and revokes existing session', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const first = await login(worker, env);
  assert.equal(first.response.status, 303);
  assert.equal(env.NODE_KV.puts.filter((p) => p.key.startsWith('login:')).length, 0);
  assert.equal(env.NODE_KV.deletes.filter((k) => k.startsWith('login:')).length, 0);

  const firstSessionId = first.cookie.split('=')[1];
  const second = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: first.cookie, Origin: 'https://example.com' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(second.status, 303);
  assert.equal(await env.NODE_KV.get(`session:${firstSessionId}`), null);
});

test('subscription response includes strict CSP and standard normalized Base64 without CRLF or BOM', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);

  const dirtyNodes = '\uFEFF  vless://uuid@example.com:443#NodeA  \r\n\r\n  ss://abc@example.com:8388#节点B \r\n  ';
  const save = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: dirtyNodes, csrf }),
  }), env, new MockCtx());
  assert.equal(save.status, 303);

  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes.includes('\r'), false);
  assert.equal(stored.nodes.startsWith('\uFEFF'), false);

  const sub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef'), env, new MockCtx());
  assert.equal(sub.status, 200);
  assert.equal(sub.headers.get('content-security-policy'), "default-src 'none'; frame-ancestors 'none'");
  const encoded = await sub.text();
  assert.match(encoded, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  assert.equal(decoded, 'vless://uuid@example.com:443#NodeA\nss://abc@example.com:8388#节点B');
});

test('logout rejects cross-origin requests and missing CSRF', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);

  const badOrigin = await worker.fetch(makeRequest('/logout', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://evil.example.com' },
    body: form({ csrf }),
  }), env, new MockCtx());
  assert.equal(badOrigin.status, 403);

  const noCsrf = await worker.fetch(makeRequest('/logout', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({}),
  }), env, new MockCtx());
  assert.equal(noCsrf.status, 403);
});

test('corrupted JSON or non-string nodes in KV fail closed with 500', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await env.NODE_KV.put('data', '{invalid-json');
  const res1 = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef'), env, new MockCtx());
  assert.equal(res1.status, 500);

  await env.NODE_KV.put('data', JSON.stringify({ nodes: 12345 }));
  const res2 = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef'), env, new MockCtx());
  assert.equal(res2.status, 500);
});

test('0.0.0.0 HTTP is redirected to HTTPS and incomplete KV binding fails closed', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const redirectRes = await worker.fetch(new Request('http://0.0.0.0:8787/admin', { redirect: 'manual' }), env, new MockCtx());
  assert.equal(redirectRes.status, 308);
  assert.equal(redirectRes.headers.get('location'), 'https://0.0.0.0:8787/admin');

  const badKvEnv = createEnv({ NODE_KV: { get() {}, put() {} } });
  const badKvRes = await worker.fetch(makeRequest('/admin'), badKvEnv, new MockCtx());
  assert.equal(badKvRes.status, 500);
});

test('loadStats caps KV subrequests to stay within Workers Free limits', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  for (let i = 0; i < 2500; i += 1) {
    await env.NODE_KV.put(`stat:C${String(i).padStart(4, '0')}`, '1');
  }
  const { cookie } = await login(worker, env);
  const getsBefore = env.NODE_KV.gets.length;
  const listsBefore = env.NODE_KV.listCalls;
  const { response } = await getAdminHtml(worker, env, cookie);
  assert.equal(response.status, 200);
  const batchGets = env.NODE_KV.gets.slice(getsBefore).filter((g) => Array.isArray(g.key)).length;
  const lists = env.NODE_KV.listCalls - listsBefore;
  assert.ok(batchGets + lists <= 20, `stats subrequests should be capped at 20, got ${batchGets + lists}`);
});

test('default 404 and invalid /sub token return identical bodies to prevent route fingerprinting', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const unknownRes = await worker.fetch(makeRequest('/does-not-exist'), env, new MockCtx());
  const badSubRes = await worker.fetch(makeRequest('/sub?token=wrong'), env, new MockCtx());
  assert.equal(unknownRes.status, 404);
  assert.equal(badSubRes.status, 404);
  assert.equal(await unknownRes.text(), await badSubRes.text());
});

test('unauthenticated logout without cookie does not leak session cookie name', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const res = await worker.fetch(makeRequest('/logout', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({}),
  }), env, new MockCtx());
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('set-cookie'), null);
});

test('custom ADMIN_PATH and SUB_PATH hide default endpoints and update rendered links', async () => {
  const worker = await loadWorker();
  const env = createEnv({ ADMIN_PATH: '/p9x2k', SUB_PATH: '/s8q4w' });
  await seedConfig(env, 'vless://hidden@example.com:443#Hidden');

  const oldAdmin = await worker.fetch(makeRequest('/admin'), env, new MockCtx());
  const oldSub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef'), env, new MockCtx());
  assert.equal(oldAdmin.status, 404);
  assert.equal(oldSub.status, 404);

  const loginRes = await worker.fetch(makeRequest('/p9x2k', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(loginRes.status, 303);
  assert.equal(loginRes.headers.get('location'), '/p9x2k');

  const cookie = getCookie(loginRes);
  const adminPage = await worker.fetch(makeRequest('/p9x2k', {
    headers: { Cookie: cookie },
  }), env, new MockCtx());
  const html = await adminPage.text();
  assert.match(html, /s8q4w\?token=/);
  assert.match(html, /action="&#x2F;p9x2k&#x2F;logout"/);

  const subRes = await worker.fetch(makeRequest('/s8q4w?token=sub-test-secret-0123456789abcdef'), env, new MockCtx());
  assert.equal(subRes.status, 200);
  assert.equal(Buffer.from(await subRes.text(), 'base64').toString('utf8'), 'vless://hidden@example.com:443#Hidden');
});

test('custom route paths reject double slashes and dot-dot traversal, and saveConfig degrades KV 429', async () => {
  const worker = await loadWorker();
  const badPath1 = await worker.fetch(makeRequest('/admin'), createEnv({ ADMIN_PATH: '//evil.com' }), new MockCtx());
  const badPath2 = await worker.fetch(makeRequest('/admin'), createEnv({ SUB_PATH: '/../sub' }), new MockCtx());
  assert.equal(badPath1.status, 500);
  assert.equal(badPath2.status, 500);

  const env = createEnv();
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  env.NODE_KV.failPut429Prefixes.add('data');
  const saveRes = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'vless://test', csrf }),
  }), env, new MockCtx());
  assert.equal(saveRes.status, 429);
  assert.equal(saveRes.headers.get('retry-after'), '1');
});
