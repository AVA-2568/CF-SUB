import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MockCtx,
  MockDOStorage,
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
import { AuthDurableObject } from '../_worker.js';

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
  assert.match(setCookie, /^__Host-cf_sub_session=/);
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

test('concurrent failed logins are atomically capped at five and never touch config', async () => {
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

  const failures = await env.AUTH.listAll('login:');
  assert.equal(failures.length, 1);
  assert.equal(failures[0][1].count, 5);
});

test('stats are loaded from KV multi-get and rendered in admin', async () => {
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

test('a missing auth store fails closed instead of disabling protection', async () => {
  const worker = await loadWorker();
  const env = createEnv({ AUTH: undefined });
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 500);
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
  assert.equal(await env.AUTH.objects.get('auth-session').state.storage.get('config:initialized'), true);
});

test('a marker write failure prevents an existing config from being overwritten', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'ORIGINAL-NODES');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  const coreStorage = env.AUTH.objects.get('auth-session').state.storage;
  await coreStorage.delete('config:initialized');
  coreStorage.failPuts.add('config:initialized');
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'REPLACEMENT', csrf }),
  }), env, new MockCtx());
  assert.equal(response.status, 500);
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes, 'ORIGINAL-NODES');
  assert.equal(await coreStorage.get('config:initialized'), null);
});

test('a data write failure leaves the initialization marker fail-closed', async () => {
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
  assert.equal(await env.AUTH.objects.get('auth-session').state.storage.get('config:initialized'), true);
  env.NODE_KV.failPuts.delete('data');
  const admin = await getAdminHtml(worker, env, cookie);
  assert.equal(admin.response.status, 500);
});

test('subscription rejects a bad token or disallowed user agent', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  const badToken = await worker.fetch(makeRequest('/sub?token=wrong', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(badToken.status, 404);
  const badUa = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'curl/8.0' },
  }), env, new MockCtx());
  assert.equal(badUa.status, 404);
});

test('subscription statistics are written through waitUntil', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  const ctx = new MockCtx();
  const sub = await worker.fetch(makeRequest('/sub?token=sub-test-secret-0123456789abcdef', {
    headers: { 'User-Agent': 'v2rayN/6.0', 'CF-IPCountry': 'US' },
  }), env, ctx);
  assert.equal(sub.status, 200);
  await ctx.flush();
  assert.equal(await env.NODE_KV.get('stat:US'), '1');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  assert.match(html, /<td>US<\/td>/);
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

test('secrets shorter than 32 characters are rejected', async () => {
  const worker = await loadWorker();
  const env = createEnv({ ADMIN_TOKEN: 'a'.repeat(31) });
  const response = await worker.fetch(makeRequest('/admin'), env, new MockCtx());
  assert.equal(response.status, 500);
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
  await env.AUTH.objects.get('auth-session').state.storage.put('config:initialized', true);
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
  assert.equal(await env.AUTH.objects.get('auth-session').state.storage.get('config:initialized'), true);
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
  assert.equal(await env.AUTH.objects.get('auth-session').state.storage.get('config:initialized'), true);
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

test('session credentials are sent in a header, not a Durable Object URL', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  await getAdminHtml(worker, env, cookie);
  assert.equal(env.AUTH.requests.some(({ url }) => url.includes('credential=')), false);
  assert.equal(env.AUTH.requests.some(({ init }) => init?.headers?.['x-session-credential']), true);
});

test('initialization marker alone does not keep the cleanup alarm scheduled', async () => {
  const storage = new MockDOStorage();
  await storage.put('config:initialized', true);
  const object = new AuthDurableObject({ storage }, {});
  await object.alarm();
  assert.equal(await storage.getAlarm(), null);
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

test('stats UI is labelled as approximate rather than real-time', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  await seedConfig(env, 'NODES');
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  assert.match(html, /累计订阅请求/);
  assert.match(html, /KV 尽力统计/);
  assert.equal(html.includes('实时'), false);
});

test('percent-encoded cookie names cannot masquerade as __Host cookies', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const encoded = cookie.replace('__Host-cf_sub_session=', '%5F%5FHost-cf_sub_session=');
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
