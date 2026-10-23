import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MockCtx,
  MockKV,
  MockRateLimiter,
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

test('config read failure returns 500 and never wipes stored nodes', async () => {
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
  assert.equal(response.status, 500);
  const stored = JSON.parse(await kv.get('data'));
  assert.equal(stored.nodes, 'ORIGINAL-NODES');
});

test('login cookie is host-scoped to / and logout revokes the server session', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { response, cookie } = await login(worker, env);
  assert.equal(response.status, 303);
  const setCookie = response.headers.get('set-cookie') || '';
  assert.match(setCookie, /^__Host-cf_sub_session=/);
  assert.match(setCookie, /Path=\//);
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

test('concurrent failed logins are rate limited and do not write login state into config', async () => {
  const worker = await loadWorker();
  const env = createEnv({ LOGIN_RATE_LIMITER: new MockRateLimiter(3, 60) });
  await seedConfig(env, 'PRESERVED-NODES');
  const requests = Array.from({ length: 6 }, () => worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({ password: 'wrong-password' }),
  }), env, new MockCtx()));
  const responses = await Promise.all(requests);
  assert.ok(responses.some((response) => response.status === 429));
  const stored = JSON.parse(await env.NODE_KV.get('data'));
  assert.equal(stored.nodes, 'PRESERVED-NODES');
  assert.equal('login_fail' in stored, false);
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

test('large subscription payload encodes successfully', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const nodes = 'a'.repeat(200_000);
  await seedConfig(env, nodes);
  const response = await worker.fetch(makeRequest('/sub?token=sub-secret-123456', {
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(response.status, 200);
  const encoded = await response.text();
  assert.ok(encoded.length > 200_000);
  assert.equal(atob(encoded).length, nodes.length);
});

test('nodes larger than 5 MiB are rejected', async () => {
  const worker = await loadWorker();
  const env = createEnv();
  const { cookie } = await login(worker, env);
  const { html } = await getAdminHtml(worker, env, cookie);
  const csrf = extractCsrf(html);
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'https://example.com' },
    body: form({ nodes: 'x'.repeat(5 * 1024 * 1024 + 1), csrf }),
  }), env, new MockCtx());
  assert.equal(response.status, 413);
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
  const loginResponse = await worker.fetch(makeRequest('/admin'), env, new MockCtx());
  assert.equal(loginResponse.status, 200);
  assertSecurityHeaders(loginResponse);
  const sub = await worker.fetch(makeRequest('/sub?token=sub-secret-123456', {
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
  const postSub = await worker.fetch(makeRequest('/sub?token=sub-secret-123456', {
    method: 'POST',
    headers: { 'User-Agent': 'v2rayN/6.0' },
  }), env, new MockCtx());
  assert.equal(postSub.status, 405);
});

test('a missing rate limiter fails closed instead of disabling protection', async () => {
  const worker = await loadWorker();
  const env = createEnv({ LOGIN_RATE_LIMITER: undefined });
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, new MockCtx());
  assert.equal(response.status, 500);
});

