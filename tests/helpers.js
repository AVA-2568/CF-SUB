import assert from 'node:assert/strict';
import { AuthDurableObject } from '../_worker.js';

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

export class MockDOStorage {
  constructor() {
    this.map = new Map();
    this.alarm = null;
    this.failPuts = new Set();
  }

  async get(key) {
    return this.map.get(key) ?? null;
  }

  async put(key, value) {
    if (this.failPuts.has(key)) throw new Error(`DO write failure: ${key}`);
    this.map.set(key, value);
  }

  async delete(key) {
    this.map.delete(key);
  }

  async list({ prefix = '', limit } = {}) {
    const entries = [...this.map.entries()]
      .filter(([key]) => key.startsWith(prefix))
      .sort(([a], [b]) => a.localeCompare(b));
    return new Map(limit ? entries.slice(0, limit) : entries);
  }

  async getAlarm() {
    return this.alarm;
  }

  async setAlarm(time) {
    this.alarm = time;
  }
}

export class MockAuthNamespace {
  constructor() {
    this.objects = new Map();
    this.queues = new Map();
    this.requests = [];
  }

  idFromName(name) {
    return name;
  }

  get(id) {
    let object = this.objects.get(id);
    if (!object) {
      object = new AuthDurableObject({ storage: new MockDOStorage() }, {});
      this.objects.set(id, object);
    }

    const queue = this.queues.get(id) || Promise.resolve();
    return {
      fetch: (url, init) => {
        this.requests.push({ id, url, init });
        const request = new Request(url, init);
        const run = () => object.fetch(request);
        const result = queue.then(run, run);
        this.queues.set(id, result.then(() => undefined, () => undefined));
        return result;
      },
    };
  }

  async listAll(prefix) {
    const entries = [];
    for (const object of this.objects.values()) {
      for (const [key, value] of await object.state.storage.list({ prefix })) entries.push([key, value]);
    }
    return entries;
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
    AUTH: new MockAuthNamespace(),
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
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.match(response.headers.get('strict-transport-security') || '', /max-age=/);
  assert.match(response.headers.get('permissions-policy') || '', /camera=\(\)/);
}
