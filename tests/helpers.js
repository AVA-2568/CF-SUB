import assert from 'node:assert/strict';

export class MockKV {
  constructor() {
    this.map = new Map();
    this.failKeys = new Set();
    this.failPuts = new Set();
    this.puts = [];
  }

  async get(key, type) {
    if (Array.isArray(key)) {
      if (key.length > 100) throw new Error('KV get(keys) supports at most 100 keys');
      for (const k of key) {
        if (this.failKeys.has(k)) throw new Error(`KV read failure: ${k}`);
      }
      const result = new Map();
      for (const k of key) result.set(k, this.map.get(k) ?? null);
      return result;
    }
    if (this.failKeys.has(key)) throw new Error(`KV read failure: ${key}`);
    const value = this.map.get(key) ?? null;
    if (value === null) return null;
    return type === 'json' ? JSON.parse(value) : value;
  }

  async put(key, value, options) {
    if (this.failPuts.has(key)) throw new Error(`KV write failure: ${key}`);
    this.puts.push({ key, value, options });
    this.map.set(key, String(value));
  }

  async delete(key) {
    this.map.delete(key);
  }

  async list({ prefix = '', cursor } = {}) {
    const names = [...this.map.keys()].filter((name) => name.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0;
    const page = names.slice(start, start + 1000);
    const complete = start + 1000 >= names.length;
    return {
      keys: page.map((name) => ({ name })),
      cursor: complete ? undefined : String(start + 1000),
      list_complete: complete,
    };
  }
}

export class MockCtx {
  constructor() {
    this.pending = [];
  }

  waitUntil(promise) {
    this.pending.push(Promise.resolve(promise));
  }

  async flush() {
    const pending = this.pending;
    this.pending = [];
    await Promise.allSettled(pending);
  }
}

export function createEnv(overrides = {}) {
  return {
    NODE_KV: new MockKV(),
    ADMIN_TOKEN: 'admin-test-secret-0123456789abcdef',
    SUB_TOKEN: 'sub-test-secret-0123456789abcdef',
    ...overrides,
  };
}

export function form(fields) {
  const data = new FormData();
  for (const [key, value] of Object.entries(fields)) data.set(key, value);
  return data;
}

export function makeRequest(path, { method = 'GET', headers = {}, body } = {}) {
  return new Request(new URL(path, 'https://example.com'), {
    method,
    headers: {
      'x-forwarded-proto': 'https',
      'CF-Connecting-IP': '203.0.113.10',
      'CF-IPCountry': 'US',
      ...headers,
    },
    body,
    redirect: 'manual',
  });
}

export function getCookie(response) {
  const setCookie = response.headers.get('set-cookie');
  return setCookie ? setCookie.split(';')[0] : null;
}

export function extractCsrf(html) {
  const match = html.match(/name="csrf"\s+value="([^"]+)"/);
  return match ? match[1] : null;
}

export async function loadWorker() {
  return (await import(`../_worker.js?test=${crypto.randomUUID()}`)).default;
}

export async function login(worker, env, ctx = new MockCtx()) {
  const response = await worker.fetch(makeRequest('/admin', {
    method: 'POST',
    headers: { Origin: 'https://example.com' },
    body: form({ password: env.ADMIN_TOKEN }),
  }), env, ctx);
  return { response, cookie: getCookie(response), ctx };
}

export async function seedConfig(env, nodes = 'node-a\nnode-b') {
  await env.NODE_KV.put('data', JSON.stringify({ nodes }));
}

export async function getAdminHtml(worker, env, cookie, ctx = new MockCtx()) {
  const response = await worker.fetch(makeRequest('/admin', {
    headers: { Cookie: cookie },
  }), env, ctx);
  return { response, html: await response.text() };
}

export function assertSecurityHeaders(response) {
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(response.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
  assert.match(response.headers.get('strict-transport-security') || '', /max-age=/);
  assert.match(response.headers.get('permissions-policy') || '', /camera=\(\)/);
}
