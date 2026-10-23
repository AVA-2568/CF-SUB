/**
 * CF-SUB Worker
 *
 * 路由：
 *   GET  /sub?token=...   返回 Base64 订阅
 *   GET  /admin           登录页或管理页
 *   POST /admin           登录或保存节点
 *   POST /logout          撤销当前 Session
 *
 * 存储：
 *   Durable Object         Session、CSRF、登录限流、失败计数与配置初始化标记
 *   KV data                节点配置（只保存 { nodes }）
 *   KV stat:<country>      订阅次数尽力统计
 */

const SUB_UPDATE_TIME = 6;
const ALLOWED_UA = /(v2ray|sing-box|singbox|xray|nekobox|v2rayn|quantumult|loon|shadowrocket)/i;

const SESSION_COOKIE_NAME = '__Host-cf_sub_session';
const SESSION_TTL = 15 * 60;
const SESSION_MAX_AGE = SESSION_TTL;

const LOGIN_FAIL_LIMIT = 5;
const LOGIN_FAIL_TIMEOUT = 15 * 60 * 1000;
const LOGIN_FAIL_TTL_SECONDS = Math.ceil(LOGIN_FAIL_TIMEOUT / 1000);

const CONFIG_KEY = 'data';
const STAT_BATCH_SIZE = 100;
// Workers Free 每次请求只有 10ms CPU；128 KiB 经实测 Base64 编码约 6ms，留出响应处理余量。
const MAX_NODES_BYTES = 128 * 1024;
// URL 编码会把每个 UTF-8 字节最多扩展为 3 个 ASCII 字节，余量留给表单字段。
const MAX_BODY_BYTES = MAX_NODES_BYTES * 3 + 64 * 1024;
const MIN_SECRET_LENGTH = 32;

const textEncoder = new TextEncoder();

class HttpError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.headers = headers;
  }
}


export class AuthDurableObject {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === 'POST' && path === '/session') return this.createSession(request);
      if (request.method === 'POST' && path === '/login-rate') return this.checkRate(request);
      if (path === '/config-state') {
        if (request.method === 'GET') return this.getConfigState();
        if (request.method === 'POST') return this.markConfigInitialized();
      }

      const sessionMatch = path.match(/^\/session\/([0-9a-f-]{36})$/i);
      if (sessionMatch) {
        if (request.method === 'GET') return this.getSession(sessionMatch[1], request.headers.get('x-session-credential'));
        if (request.method === 'DELETE') return this.deleteSession(sessionMatch[1]);
      }

      const attemptMatch = path.match(/^\/login-attempt\/([0-9a-f]{64})$/i);
      if (attemptMatch && request.method === 'POST') return this.reserveLoginAttempt(attemptMatch[1]);

      const failureMatch = path.match(/^\/login-failure\/([0-9a-f]{64})$/i);
      if (failureMatch && request.method === 'DELETE') return this.clearFailure(failureMatch[1]);

      return jsonResponse({ error: 'not found' }, 404);
    } catch (err) {
      console.error('AuthDurableObject failed', { message: err.message });
      return jsonResponse({ error: 'internal' }, 500);
    }
  }

  async createSession(request) {
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: 'bad request' }, 400);
    }

    const credential = typeof body?.credential === 'string' && /^[0-9a-f]{64}$/i.test(body.credential)
      ? body.credential.toLowerCase()
      : null;
    if (!credential) return jsonResponse({ error: 'bad request' }, 400);

    const id = crypto.randomUUID();
    const csrf = makeNonce();
    await this.state.storage.put(`session:${id}`, { csrf, created: Date.now(), credential });
    await this.ensureAlarm();
    return jsonResponse({ id, csrf });
  }

  async getConfigState() {
    return jsonResponse({ initialized: (await this.state.storage.get('config:initialized')) === true });
  }

  async markConfigInitialized() {
    await this.state.storage.put('config:initialized', true);
    return jsonResponse({ ok: true });
  }

  async getSession(id, credential) {
    if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/i.test(credential)) {
      return jsonResponse({ error: 'bad request' }, 400);
    }

    const session = await this.state.storage.get(`session:${id}`);
    if (!session) return jsonResponse({ error: 'not found' }, 404);
    if (!(await safeEqual(session.credential, credential.toLowerCase()))) {
      await this.state.storage.delete(`session:${id}`);
      return jsonResponse({ error: 'not found' }, 404);
    }
    if (Date.now() - session.created > SESSION_TTL * 1000) {
      await this.state.storage.delete(`session:${id}`);
      return jsonResponse({ error: 'expired' }, 404);
    }
    return jsonResponse({ session: { csrf: session.csrf, created: session.created } });
  }

  async deleteSession(id) {
    await this.state.storage.delete(`session:${id}`);
    return jsonResponse({ ok: true });
  }

  async reserveLoginAttempt(key) {
    const failure = await this.readFailure(key);
    if (failure.count >= LOGIN_FAIL_LIMIT) {
      return jsonResponse({
        allowed: false,
        count: failure.count,
        retryAfter: Math.max(1, Math.ceil((failure.last + LOGIN_FAIL_TIMEOUT - Date.now()) / 1000)),
      });
    }

    const next = { count: failure.count + 1, last: Date.now() };
    await this.state.storage.put(`login:${key}`, next);
    await this.ensureAlarm();
    return jsonResponse({ allowed: true, count: next.count });
  }

  async clearFailure(key) {
    await this.state.storage.delete(`login:${key}`);
    return jsonResponse({ ok: true });
  }

  async checkRate(request) {
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: 'bad request' }, 400);
    }

    const keyHash = typeof body?.key === 'string' && /^[0-9a-f]{64}$/i.test(body.key)
      ? body.key.toLowerCase()
      : null;
    if (!keyHash) return jsonResponse({ error: 'bad request' }, 400);

    const key = `rate:${keyHash}`;
    const now = Date.now();
    let entry = await this.state.storage.get(key);
    if (!entry || now - entry.start >= 60_000) entry = { start: now, count: 0 };
    entry.count += 1;
    await this.state.storage.put(key, entry);
    await this.ensureAlarm();

    return jsonResponse({
      allowed: entry.count <= 10,
      retryAfter: Math.max(1, Math.ceil((entry.start + 60_000 - now) / 1000)),
    });
  }

  async readFailure(key) {
    const failure = await this.state.storage.get(`login:${key}`);
    if (!failure || Date.now() - failure.last > LOGIN_FAIL_TIMEOUT) return { count: 0, last: 0 };
    return { count: failure.count, last: failure.last };
  }

  async ensureAlarm() {
    if (typeof this.state.storage.getAlarm !== 'function' || typeof this.state.storage.setAlarm !== 'function') return;
    const current = await this.state.storage.getAlarm();
    if (current === null || current <= Date.now()) {
      await this.state.storage.setAlarm(Date.now() + 60 * 60 * 1000);
    }
  }

  async alarm() {
    const now = Date.now();
    let hasRemaining = false;

    for (const [key, value] of await this.state.storage.list({ prefix: 'session:' })) {
      if (now - value.created > SESSION_TTL * 1000) await this.state.storage.delete(key);
      else hasRemaining = true;
    }
    for (const [key, value] of await this.state.storage.list({ prefix: 'login:' })) {
      if (now - value.last > LOGIN_FAIL_TIMEOUT) await this.state.storage.delete(key);
      else hasRemaining = true;
    }
    for (const [key, value] of await this.state.storage.list({ prefix: 'rate:' })) {
      if (now - value.start >= 60_000) await this.state.storage.delete(key);
      else hasRemaining = true;
    }

    if (hasRemaining) await this.state.storage.setAlarm(now + 60 * 60 * 1000);
  }
}
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;

    try {
      validateEnv(env);

      if (!isSecureConnection(url)) {
        const secureUrl = new URL(url);
        secureUrl.protocol = 'https:';
        return redirect(secureUrl.toString(), 308);
      }

      switch (path) {
        case '/sub':
          if (req.method !== 'GET') return methodNotAllowed('GET');
          return await handleSub(req, env, ctx);
        case '/admin':
          if (!['GET', 'POST'].includes(req.method)) return methodNotAllowed('GET, POST');
          return await handleAdmin(req, env, url);
        case '/logout':
          if (req.method !== 'POST') return methodNotAllowed('POST');
          return await handleLogout(req, env, url);
        default:
          return textResponse('404', 404);
      }
    } catch (err) {
      if (err instanceof HttpError) {
        return textResponse(err.message, err.status, err.headers);
      }
      console.error(`[${path}]`, { message: err.message, name: err.name });
      return textResponse('Internal Server Error', 500);
    }
  }
};

function validateEnv(env) {
  if (!env || !env.NODE_KV || typeof env.NODE_KV.get !== 'function' || typeof env.NODE_KV.put !== 'function') {
    throw new HttpError(500, 'Server misconfigured');
  }
  if (typeof env.ADMIN_TOKEN !== 'string' || env.ADMIN_TOKEN.length < MIN_SECRET_LENGTH) {
    throw new HttpError(500, 'Server misconfigured');
  }
  if (typeof env.SUB_TOKEN !== 'string' || env.SUB_TOKEN.length < MIN_SECRET_LENGTH) {
    throw new HttpError(500, 'Server misconfigured');
  }
  if (env.ADMIN_TOKEN === env.SUB_TOKEN) {
    throw new HttpError(500, 'Server misconfigured');
  }
}

function getAuthStub(env, name = 'auth-session') {
  if (!env.AUTH || typeof env.AUTH.idFromName !== 'function' || typeof env.AUTH.get !== 'function') {
    throw new HttpError(500, 'Server misconfigured');
  }
  return env.AUTH.get(env.AUTH.idFromName(name));
}

async function authFetch(env, path, init = {}, name = 'auth-session') {
  return getAuthStub(env, name).fetch(`https://auth.internal${path}`, init);
}

function isSecureConnection(url) {
  if (url.protocol === 'https:') return true;
  return ['localhost', '127.0.0.1', '0.0.0.0', '[::1]'].includes(url.hostname);
}

function methodNotAllowed(allow) {
  return textResponse('Method Not Allowed', 405, { Allow: allow });
}

// -------------------------
// 订阅
// -------------------------
async function handleSub(req, env, ctx) {
  const url = new URL(req.url);
  const token = url.searchParams.get('token') || '';
  const ua = (req.headers.get('User-Agent') || '').toLowerCase();

  if (!(await safeEqual(token, env.SUB_TOKEN))) throw new HttpError(404, 'Not Found');
  if (!ALLOWED_UA.test(ua)) throw new HttpError(404, 'Not Found');

  const rawCountry = req.headers.get('CF-IPCountry') || 'XX';
  const country = /^[A-Z0-9]{2}$/.test(rawCountry) ? rawCountry : 'XX';
  const config = await getConfig(env);
  const markerTask = ensureConfigInitialized(env).catch((err) => {
    console.error('config marker migration failed', { message: err.message });
  });
  const statTask = incrementStat(env, country).catch((err) => {
    console.error('stat update failed', { message: err.message });
  });
  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(markerTask);
    ctx.waitUntil(statTask);
  } else {
    await Promise.all([markerTask, statTask]);
  }

  const body = encodeBase64Utf8(config.nodes || '');

  return new Response(body, {
    status: 200,
    headers: {
      ...baseHeaders(),
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': String(SUB_UPDATE_TIME),
    },
  });
}

function encodeBase64Utf8(value) {
  const bytes = textEncoder.encode(value);
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

// -------------------------
// 管理后台
// -------------------------
async function handleAdmin(req, env, url) {
  const nonce = makeNonce();
  if (req.method === 'POST') assertSameOrigin(req, url);
  const session = await getSession(req, env);

  if (req.method === 'GET') {
    if (!session) return htmlResponse(renderLogin('', nonce), { nonce });
    const config = await getConfig(env, { allowUninitialized: true });
    let stats = {};
    try {
      stats = await loadStats(env);
    } catch (err) {
      console.error('loadStats failed', { message: err.message });
    }
    return htmlResponse(renderAdmin({
      nodes: config.nodes,
      stats,
      token: env.SUB_TOKEN,
      origin: url.origin,
      csrf: session.csrf,
      nonce,
    }), { nonce });
  }

  const ipHash = await sha256Hex(getClientIp(req));
  const rateStore = authRateStore(ipHash);
  const rateResponse = await authFetch(env, '/login-rate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ key: ipHash }),
  }, rateStore);
  if (!rateResponse.ok) throw new HttpError(500, 'Auth store error');
  const rate = await rateResponse.json();
  if (!rate.allowed) {
    return htmlResponse(renderLogin('操作过于频繁，请稍后再试', nonce), {
      status: 429,
      nonce,
      extra: { 'Retry-After': String(rate.retryAfter || 60) },
    });
  }

  const form = await parseForm(req);

  if (form.has('password')) {
    return handleLogin(form, env, ipHash, rateStore, nonce);
  }

  if (!session) return redirect('/admin');

  await requireCsrf(form, session);
  const nodes = getStringField(form, 'nodes');
  validateNodesSize(nodes);
  await saveConfig(env, nodes);
  return redirect('/admin?saved=1');
}

async function handleLogin(form, env, ipHash, rateStore, nonce) {
  const password = getStringField(form, 'password');
  if (password.length > 512) throw new HttpError(400, 'Bad Request');

  const attempt = await reserveLoginAttempt(env, ipHash, rateStore);
  if (!attempt.allowed) {
    return htmlResponse(renderLogin('尝试次数过多，请稍后再试', nonce), {
      status: 429,
      nonce,
      extra: { 'Retry-After': String(attempt.retryAfter || LOGIN_FAIL_TTL_SECONDS) },
    });
  }

  if (!(await safeEqual(password, env.ADMIN_TOKEN))) {
    return htmlResponse(renderLogin('密码错误', nonce), { status: 401, nonce });
  }

  await clearLoginFailure(env, ipHash, rateStore);
  const session = await createSession(env);
  return redirectWithCookie('/admin', session.cookie);
}

async function handleLogout(req, env, url) {
  assertSameOrigin(req, url);
  const session = await getSession(req, env);

  if (!session) {
    return redirect('/admin', 303, { 'Set-Cookie': clearSessionCookie() });
  }

  const form = await parseForm(req);
  await requireCsrf(form, session);
  await deleteSession(env, session.id);

  return redirect('/admin', 303, { 'Set-Cookie': clearSessionCookie() });
}

async function createSession(env) {
  const credential = await sha256Hex(env.ADMIN_TOKEN);
  const response = await authFetch(env, '/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential }),
  });
  if (!response.ok) throw new HttpError(500, 'Auth store error');

  const data = await response.json();
  if (typeof data.id !== 'string' || typeof data.csrf !== 'string') {
    throw new HttpError(500, 'Auth store error');
  }

  return {
    id: data.id,
    csrf: data.csrf,
    cookie: sessionCookie(data.id),
  };
}

async function getSession(req, env) {
  const cookies = parseCookies(req.headers.get('Cookie') || '');
  const id = cookies[SESSION_COOKIE_NAME];
  if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/i.test(id)) return null;

  const credential = await sha256Hex(env.ADMIN_TOKEN);
  const response = await authFetch(env, `/session/${id}`, {
    headers: { 'x-session-credential': credential },
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new HttpError(500, 'Auth store error');

  const data = await response.json();
  if (!data.session || typeof data.session.csrf !== 'string' || typeof data.session.created !== 'number') {
    throw new HttpError(500, 'Auth store error');
  }

  return { id, csrf: data.session.csrf, created: data.session.created };
}

async function deleteSession(env, id) {
  const response = await authFetch(env, `/session/${id}`, { method: 'DELETE' });
  if (!response.ok) throw new HttpError(500, 'Auth store error');
}

function sessionCookie(id) {
  return `${SESSION_COOKIE_NAME}=${id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;
}

async function requireCsrf(form, session) {
  const submitted = form.get('csrf');
  if (typeof submitted !== 'string' || !(await safeEqual(submitted, session.csrf))) {
    throw new HttpError(403, 'Forbidden');
  }
}

async function reserveLoginAttempt(env, key, storeName) {
  const response = await authFetch(env, `/login-attempt/${key}`, { method: 'POST' }, storeName);
  if (!response.ok) throw new HttpError(500, 'Auth store error');
  return response.json();
}

async function clearLoginFailure(env, key, storeName) {
  const response = await authFetch(env, `/login-failure/${key}`, { method: 'DELETE' }, storeName);
  if (!response.ok) throw new HttpError(500, 'Auth store error');
}

function authRateStore(ipHash) {
  return `auth-rate-${ipHash.slice(0, 2)}`;
}

// -------------------------
// KV 数据
// -------------------------
async function getConfig(env, { allowUninitialized = false } = {}) {
  const raw = await env.NODE_KV.get(CONFIG_KEY);

  if (raw === null) {
    if (allowUninitialized) {
      if (!(await isConfigInitialized(env))) return { nodes: '' };
    }
    throw new HttpError(500, 'Configuration missing');
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new HttpError(500, 'Configuration invalid');
  }

  if (!data || typeof data !== 'object' || typeof data.nodes !== 'string') {
    throw new HttpError(500, 'Configuration invalid');
  }
  validateNodesSize(data.nodes);
  if (allowUninitialized) await ensureConfigInitialized(env);
  return { nodes: data.nodes };
}

async function saveConfig(env, nodes) {
  // 先在强一致 Durable Object 落标记；即使后续 KV 数据写入失败，也不会被误判为全新部署。
  await markConfigInitialized(env);
  await env.NODE_KV.put(CONFIG_KEY, JSON.stringify({ nodes }));
}

// 旧部署可能已有 KV 数据但没有 DO 标记；首次读到数据时补写，避免后续数据丢失被误判为全新部署。
// 同一个 isolate 内复用 Promise，避免订阅请求每次触发多一次 DO 往返。
let configMarkerPromise = null;

async function ensureConfigInitialized(env) {
  if (!configMarkerPromise) {
    configMarkerPromise = (async () => {
      if (!(await isConfigInitialized(env))) await markConfigInitialized(env);
    })().catch((err) => {
      configMarkerPromise = null;
      throw err;
    });
  }
  return configMarkerPromise;
}

async function isConfigInitialized(env) {
  const response = await authFetch(env, '/config-state');
  if (!response.ok) throw new HttpError(500, 'Auth store error');
  const data = await response.json();
  if (typeof data.initialized !== 'boolean') throw new HttpError(500, 'Auth store error');
  return data.initialized;
}

async function markConfigInitialized(env) {
  const response = await authFetch(env, '/config-state', { method: 'POST' });
  if (!response.ok) throw new HttpError(500, 'Auth store error');
}

async function loadStats(env) {
  const result = {};
  let cursor;

  do {
    const list = await env.NODE_KV.list({ prefix: 'stat:', cursor });
    const keys = list.keys.map((key) => key.name);
    cursor = list.cursor;

    for (let i = 0; i < keys.length; i += STAT_BATCH_SIZE) {
      const values = await env.NODE_KV.get(keys.slice(i, i + STAT_BATCH_SIZE));
      for (const [key, value] of values) {
        const country = key.slice('stat:'.length);
        const count = Number.parseInt(value || '0', 10);
        if (country && Number.isFinite(count)) result[country] = count;
      }
    }

    if (list.list_complete === true || !cursor) break;
  } while (true);

  return result;
}

async function incrementStat(env, country) {
  const key = `stat:${country}`;
  const current = Number.parseInt((await env.NODE_KV.get(key)) || '0', 10);
  const next = Number.isFinite(current) ? current + 1 : 1;
  await env.NODE_KV.put(key, String(next));
}

// -------------------------
// 请求工具
// -------------------------
async function parseForm(req) {
  const contentType = req.headers.get('content-type') || '';
  if (!/^(application\/x-www-form-urlencoded|multipart\/form-data)(;|$)/i.test(contentType)) {
    throw new HttpError(415, 'Unsupported Media Type');
  }

  const contentLength = Number(req.headers.get('content-length') || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    throw new HttpError(413, 'Payload Too Large');
  }

  if (!req.body) throw new HttpError(400, 'Bad Request');

  const reader = req.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        try { await reader.cancel(); } catch {}
        throw new HttpError(413, 'Payload Too Large');
      }
      chunks.push(value);
    }
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(400, 'Bad Request');
  }

  try {
    const body = new Blob(chunks, { type: contentType });
    return await new Response(body, { headers: { 'content-type': contentType } }).formData();
  } catch {
    throw new HttpError(400, 'Bad Request');
  }
}

function getStringField(form, name) {
  const value = form.get(name);
  if (typeof value !== 'string') throw new HttpError(400, 'Bad Request');
  return value;
}

function validateNodesSize(nodes) {
  if (textEncoder.encode(nodes).byteLength > MAX_NODES_BYTES) {
    throw new HttpError(413, 'Payload Too Large');
  }
}

function getClientIp(req) {
  return req.headers.get('CF-Connecting-IP') || 'unknown';
}

function assertSameOrigin(req, url) {
  if (req.headers.get('Origin') !== url.origin) {
    throw new HttpError(403, 'Forbidden');
  }
}

// -------------------------
// 页面渲染
// -------------------------
function renderLogin(msg = '', nonce) {
  return `
<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login</title>
<style nonce="${nonce}">${baseStyle()}</style>
</head>
<body>
<div class="login-wrapper">
  <div class="card glow">
    <div class="logo-container">
      <svg viewBox="0 0 24 24" width="56" height="56" fill="currentColor">
        <path d="M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z"/>
      </svg>
    </div>
    <h1>ADMIN ACCESS</h1>
    ${msg ? `<div class="toast error show">${escapeHTML(msg)}</div>` : ''}
    <form method="post">
      <input type="password" name="password" placeholder="Enter Access Key" required autocomplete="current-password">
      <button type="submit">LOGIN</button>
    </form>
  </div>
</div>
</body>
</html>`;
}

function renderAdmin({ nodes, stats, token, origin, csrf, nonce }) {
  const link = `${origin}/sub?token=${encodeURIComponent(token)}`;
  const totalUsers = Object.values(stats).reduce((sum, value) => sum + value, 0);
  const regionCount = Object.keys(stats).length;

  const rows = Object.entries(stats)
    .sort(([, a], [, b]) => b - a)
    .map(([country, count]) => `<tr><td>${escapeHTML(country)}</td><td>${Number(count)}</td></tr>`)
    .join('');

  return `
<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Node Admin</title>
<style nonce="${nonce}">${baseStyle()}</style>
</head>
<body>
<div class="container">
  <div class="toast success" id="toast">✔ 配置已保存</div>

  <div class="header-section">
    <div class="brand">
      <svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor">
        <path d="M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z"/>
      </svg>
      <span>NODE CONTROL</span>
    </div>
    <form method="post" action="/logout" class="logout-form">
      <input type="hidden" name="csrf" value="${escapeHTML(csrf)}">
      <button class="logout-btn" type="submit" title="登出" aria-label="登出">⏻</button>
    </form>
  </div>

  <div class="stats-overview">
    <div class="stat-card">
      <div class="stat-icon">📊</div>
      <div class="stat-value">${totalUsers}</div>
      <div class="stat-label">累计订阅请求</div>
    </div>
    <div class="stat-card">
      <div class="stat-icon">🌍</div>
      <div class="stat-value">${regionCount}</div>
      <div class="stat-label">覆盖地区</div>
    </div>
    <div class="stat-card">
      <div class="stat-icon">🕐</div>
      <div class="stat-value">近似</div>
      <div class="stat-label">KV 尽力统计</div>
    </div>
  </div>

  <div class="card">
    <h2>节点配置</h2>
    <form method="post" id="nodesForm">
      <input type="hidden" name="csrf" value="${escapeHTML(csrf)}">
      <textarea name="nodes" spellcheck="false" placeholder="在此粘贴节点配置...">${escapeHTML(nodes)}</textarea>
      <button type="submit" id="saveBtn">
        <span class="btn-text">SAVE CONFIG</span>
        <span class="btn-loader" id="saveLoader">⏳</span>
      </button>
    </form>
  </div>

  <div class="card">
    <h2>订阅链接</h2>
    <div class="link-wrapper">
      <input id="subLink" type="text" value="${escapeHTML(link)}" readonly>
      <button class="copy-btn" type="button" id="copyBtn">COPY</button>
    </div>
  </div>

  <div class="card">
    <h2>订阅统计</h2>
    <table>
      <thead><tr><th>REGION</th><th>COUNT</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="2">NO DATA</td></tr>'}</tbody>
    </table>
  </div>
</div>

<script nonce="${nonce}">
(function(){
  const params = new URLSearchParams(window.location.search);
  if (params.get('saved') === '1') {
    const toast = document.getElementById('toast');
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
    history.replaceState({}, '', window.location.pathname);
  }
})();

const copyBtn = document.getElementById('copyBtn');
if (copyBtn) {
  copyBtn.addEventListener('click', async () => {
    const input = document.getElementById('subLink');
    try {
      await navigator.clipboard.writeText(input.value);
      copyBtn.textContent = 'COPIED!';
      copyBtn.classList.add('copied');
      setTimeout(() => {
        copyBtn.textContent = 'COPY';
        copyBtn.classList.remove('copied');
      }, 1500);
    } catch (err) {
      input.select();
      try {
        document.execCommand('copy');
        copyBtn.textContent = 'COPIED!';
        setTimeout(() => { copyBtn.textContent = 'COPY'; }, 1500);
      } catch {
        alert('复制失败，请手动复制');
      }
    }
  });
}

const nodesForm = document.getElementById('nodesForm');
if (nodesForm) {
  nodesForm.addEventListener('submit', function() {
    const btn = document.getElementById('saveBtn');
    const loader = document.getElementById('saveLoader');
    if (btn) btn.disabled = true;
    if (loader) loader.classList.add('is-loading');
  });
}
</script>
</body>
</html>`;
}

function baseStyle() {
  return `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  min-height:100vh;
  background:linear-gradient(135deg,#0a0a1f 0%,#1a1a3e 50%,#0d0d2b 100%);
  color:#00f6ff;
  font-family:Consolas,"Courier New",monospace;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:16px;
  position:relative;
  overflow-x:hidden;
}
body::before{
  content:'';
  position:absolute;
  top:0;left:0;right:0;bottom:0;
  background-image:
    linear-gradient(rgba(0,246,255,0.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,246,255,0.03) 1px,transparent 1px);
  background-size:40px 40px;
  pointer-events:none;
  z-index:-1;
}
.login-wrapper{width:100%;max-width:400px;animation:fadeInUp 0.6s ease-out}
@keyframes fadeInUp{from{opacity:0;transform:translateY(30px);}to{opacity:1;transform:translateY(0);}}
.container{width:100%;max-width:960px;animation:fadeIn 0.5s ease-out}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
.header-section{
  display:flex;
  align-items:center;
  justify-content:space-between;
  margin-bottom:24px;
  padding:0 4px;
}
.brand{
  display:flex;
  align-items:center;
  gap:12px;
  font-size:clamp(1.2rem,3vw,1.5rem);
  font-weight:bold;
  letter-spacing:3px;
  text-shadow:0 0 10px rgba(0,246,255,0.5);
}
.brand svg{
  filter:drop-shadow(0 0 8px rgba(0,246,255,0.6));
  animation:pulse 2s infinite;
}
@keyframes pulse{
  0%,100%{filter:drop-shadow(0 0 8px rgba(0,246,255,0.6));}
  50%{filter:drop-shadow(0 0 16px rgba(0,246,255,0.9));}
}
.stats-overview{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:16px;
  margin-bottom:24px;
}
.stat-card{
  background:rgba(10,10,30,.85);
  border:1px solid #00f6ff55;
  border-radius:12px;
  padding:20px;
  text-align:center;
  backdrop-filter:blur(10px);
  transition:all .3s;
  position:relative;
  overflow:hidden;
}
.stat-card::before{
  content:'';
  position:absolute;
  top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,rgba(0,246,255,0.8),transparent);
  animation:scan 3s linear infinite;
}
@keyframes scan{
  0%{transform:translateX(-100%);}
  100%{transform:translateX(100%);}
}
.stat-card:hover{
  transform:translateY(-4px);
  box-shadow:0 10px 30px rgba(0,246,255,0.2);
  border-color:#00f6ff;
}
.stat-icon{font-size:2rem;margin-bottom:8px}
.stat-value{
  font-size:clamp(1.5rem,4vw,2rem);
  font-weight:bold;
  color:#00f6ff;
  text-shadow:0 0 10px rgba(0,246,255,0.5);
}
.stat-label{font-size:0.85rem;color:#00f6ff88;margin-top:4px}
.card{
  background:rgba(10,10,30,.85);
  border:1px solid #00f6ff55;
  border-radius:12px;
  padding:24px;
  margin-bottom:20px;
  backdrop-filter:blur(20px);
  transition:all .3s;
}
.card:hover{
  box-shadow:0 0 30px rgba(0,246,255,0.15);
  border-color:#00f6ff88;
}
.glow{box-shadow:0 0 40px rgba(0,246,255,0.2)}
h1,h2{
  text-align:center;
  letter-spacing:2px;
  font-size:clamp(1rem,3vw,1.3rem);
  margin-bottom:20px;
  color:#00f6ff;
  text-shadow:0 0 10px rgba(0,246,255,0.3);
}
.logo-container{
  text-align:center;
  margin-bottom:16px;
  animation:bounceIn 0.8s ease-out;
}
@keyframes bounceIn{
  0%{transform:scale(0.5);opacity:0;}
  50%{transform:scale(1.1);}
  100%{transform:scale(1);opacity:1;}
}
.logo-container svg{
  filter:drop-shadow(0 0 15px rgba(0,246,255,0.6));
}
textarea,input[type="text"],input[type="password"]{
  width:100%;
  background:#050510;
  border:1px solid #00f6ff55;
  color:#00f6ff;
  padding:14px;
  border-radius:8px;
  margin-top:12px;
  font-family:inherit;
  font-size:14px;
  outline:none;
  transition:all .2s;
}
textarea:focus,input:focus{
  border-color:#00f6ff;
  box-shadow:0 0 15px rgba(0,246,255,0.3);
  transform:translateY(-2px);
}
textarea{height:240px;resize:vertical;min-height:160px;line-height:1.6}
button{
  width:100%;
  margin-top:16px;
  padding:16px;
  background:linear-gradient(135deg,#00f6ff,#00c4cc);
  border:none;
  border-radius:8px;
  color:#050510;
  font-weight:bold;
  font-size:15px;
  cursor:pointer;
  letter-spacing:2px;
  transition:all .3s;
  position:relative;
  overflow:hidden;
}
button::before{
  content:'';
  position:absolute;
  top:0;left:-100%;
  width:100%;
  height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);
  transition:left .5s;
}
button:hover::before{left:100%}
button:hover{
  background:linear-gradient(135deg,#00c4cc,#00a8aa);
  transform:translateY(-2px);
  box-shadow:0 8px 25px rgba(0,246,255,0.4);
}
button:active{transform:translateY(0)}
button:disabled{
  opacity:0.6;
  cursor:not-allowed;
}
.copy-btn{
  width:auto;
  margin-left:12px;
  padding:14px 24px;
  margin-top:12px;
  background:linear-gradient(135deg,#00f6ff,#00c4cc);
}
.copy-btn:hover{
  background:linear-gradient(135deg,#00c4cc,#00a8aa);
}
.copy-btn.copied{
  background:linear-gradient(135deg,#00c853,#00a83d);
}
.link-wrapper{
  display:flex;
  gap:12px;
  flex-wrap:wrap;
}
.link-wrapper input{
  flex:1;
  min-width:200px;
}
table{
  width:100%;
  border-collapse:collapse;
  margin-top:16px;
}
th,td{
  border:1px solid #00f6ff33;
  padding:12px 10px;
  text-align:center;
  font-size:14px;
}
th{
  background:rgba(0,246,255,.1);
  font-weight:bold;
  color:#00f6ff;
}
tr:nth-child(even){
  background:rgba(0,246,255,0.03);
}
tr:hover{
  background:rgba(0,246,255,0.08);
}
.toast{
  position:fixed;
  top:20px;
  left:50%;
  transform:translateX(-50%) translateY(-120px);
  padding:14px 32px;
  border-radius:8px;
  font-weight:bold;
  font-size:14px;
  z-index:999;
  transition:transform .35s cubic-bezier(.4,0,.2,1);
  pointer-events:none;
  box-shadow:0 8px 30px rgba(0,0,0,0.3);
}
.toast.show{
  transform:translateX(-50%) translateY(0);
}
.toast.success{
  background:linear-gradient(135deg,#00c853,#00a83d);
  color:#fff;
}
.toast.error{
  background:linear-gradient(135deg,#ff1744,#d50000);
  color:#fff;
  position:static;
  transform:none;
  margin-bottom:16px;
  text-align:center;
}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:#050510}
::-webkit-scrollbar-thumb{
  background:linear-gradient(135deg,#00f6ff,#00c4cc);
  border-radius:4px;
}
::-webkit-scrollbar-thumb:hover{
  background:linear-gradient(135deg,#00c4cc,#00a8aa);
}
.btn-loader{display:none;margin-left:8px}
.btn-loader.is-loading{display:inline-block}
.logout-form{display:flex;align-items:center;margin:0}
.header-section .logout-btn{
  width:auto;
  margin:0;
  padding:8px 12px;
  border:none;
  border-radius:6px;
  color:#ff4d6a;
  background:rgba(255,77,106,0.1);
  font-size:1.4rem;
  line-height:1;
  letter-spacing:0;
}
.header-section .logout-btn::before{display:none}
.header-section .logout-btn:hover{
  background:#ff4d6a;
  color:#fff;
  transform:scale(1.1);
  box-shadow:none;
}
@media (max-width:768px){
  body{padding:12px;align-items:flex-start;padding-top:20px}
  .card{padding:18px;border-radius:10px}
  textarea{height:200px;font-size:13px}
  button{padding:14px;font-size:14px}
  th,td{padding:10px 6px;font-size:13px}
  .header-section .logout-btn{font-size:1.2rem}
  .stats-overview{gap:12px}
  .stat-card{padding:16px}
  .stat-value{font-size:1.5rem}
  .toast{top:10px;padding:10px 20px;font-size:12px}
}
@media (max-width:480px){
  body{padding:8px}
  .card{padding:16px;border-radius:8px}
  textarea{height:160px;font-size:12px}
  button{padding:12px;font-size:13px}
  th,td{padding:8px 4px;font-size:12px}
  .header-section .logout-btn{font-size:1.1rem}
  .stats-overview{grid-template-columns:1fr}
  .stat-card{padding:14px}
  .stat-icon{font-size:1.5rem}
  .stat-value{font-size:1.3rem}
  .stat-label{font-size:0.8rem}
  .link-wrapper{flex-direction:column}
  .copy-btn{width:100%;margin-left:0}
}
`;
}

// -------------------------
// 响应与通用工具
// -------------------------
function baseHeaders() {
  return {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000',
  };
}

function htmlResponse(body, { status = 200, nonce, extra = {} } = {}) {
  const csp = [
    "default-src 'none'",
    `style-src 'nonce-${nonce}'`,
    `script-src 'nonce-${nonce}'`,
    "img-src 'none'",
    "font-src 'none'",
    "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');

  return new Response(body, {
    status,
    headers: {
      ...baseHeaders(),
      'Content-Security-Policy': csp,
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Content-Type': 'text/html; charset=utf-8',
      ...extra,
    },
  });
}

function textResponse(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: {
      ...baseHeaders(),
      'Content-Type': 'text/plain; charset=utf-8',
      ...extra,
    },
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function redirect(location, status = 303, extra = {}) {
  return new Response(null, {
    status,
    headers: {
      ...baseHeaders(),
      Location: location,
      ...extra,
    },
  });
}

function redirectWithCookie(location, cookie) {
  return redirect(location, 303, { 'Set-Cookie': cookie });
}

function makeNonce() {
  return crypto.randomUUID().replace(/-/g, '');
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const [left, right] = await Promise.all([
    crypto.subtle.digest('SHA-256', textEncoder.encode(a)),
    crypto.subtle.digest('SHA-256', textEncoder.encode(b)),
  ]);
  const leftBytes = new Uint8Array(left);
  const rightBytes = new Uint8Array(right);
  let diff = 0;
  for (let i = 0; i < leftBytes.length; i += 1) diff |= leftBytes[i] ^ rightBytes[i];
  return diff === 0;
}

function parseCookies(str) {
  const cookies = Object.create(null);
  if (!str) return cookies;

  for (const part of str.split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;

    const key = part.slice(0, separator).trim();
    if (!key) continue;

    const rawValue = part.slice(separator + 1).trim();
    let value = rawValue;
    try {
      value = decodeURIComponent(rawValue);
    } catch {}

    if (Object.prototype.hasOwnProperty.call(cookies, key)) {
      cookies[key] = null;
    } else {
      cookies[key] = value;
    }
  }

  return cookies;
}

function escapeHTML(value) {
  if (typeof value !== 'string') return '';
  const entities = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  };
  return value.replace(/[&<>"'/]/g, (char) => entities[char]);
}
