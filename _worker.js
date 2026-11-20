/**
 * CF-SUB Worker
 *
 * 路由：
 *   GET  /sub?token=...   返回 Base64 订阅
 *   GET  /admin           登录页或管理页
 *   POST /admin           登录或保存节点
 *   POST /logout          撤销当前 Session
 *
 * 存储（只依赖一个 KV binding：NODE_KV）：
 *   KV data                 节点配置（只保存 { nodes }）
 *   KV session:<uuid>       Session + CSRF（TTL 15 分钟）
 *   KV login:<ipHash>       登录失败计数
 *   KV rate:<ipHash>:<窗口>  登录频率限制
 *   KV config:initialized   配置初始化标记
 *   KV stat:<country>       历史订阅统计（当前版本只读）
 */

const SUB_UPDATE_TIME = 6;

const SESSION_COOKIE_NAME = '__Host-sid';
const SESSION_TTL = 15 * 60;
const SESSION_MAX_AGE = SESSION_TTL;
const SUB_CACHE_TTL_MS = 60_000;

const LOGIN_FAIL_LIMIT = 5;
const LOGIN_FAIL_TIMEOUT = 15 * 60 * 1000;
const LOGIN_FAIL_TTL_SECONDS = Math.ceil(LOGIN_FAIL_TIMEOUT / 1000);

const CONFIG_KEY = 'data';
const CONFIG_INITIALIZED_KEY = 'config:initialized';
const STAT_BATCH_SIZE = 100;
// Workers Free 单次请求上限 50 个 subrequests（含 KV list/get），预留余量避免统计查询拖垮管理页。
const STAT_MAX_SUBREQUESTS = 20;
// Workers KV get() 支持的最小边缘缓存 TTL 为 30 秒。
const KV_SHORT_CACHE_TTL = 30;
const LOGIN_RATE_LIMIT = 10;
const LOGIN_RATE_WINDOW_MS = 60_000;
const LOGIN_RATE_TTL_SECONDS = 120;
const MAX_LOCAL_BUCKETS = 1024;
// Workers Free 每次请求只有 10ms CPU；128 KiB 经实测 Base64 编码约 6ms，留出响应处理余量。
const MAX_NODES_BYTES = 128 * 1024;
// URL 编码会把每个 UTF-8 字节最多扩展为 3 个 ASCII 字节，余量留给表单字段。
const MAX_BODY_BYTES = MAX_NODES_BYTES * 3 + 64 * 1024;
const MIN_ADMIN_PASSWORD_LENGTH = 8;
const MIN_SUB_TOKEN_LENGTH = 16;

const textEncoder = new TextEncoder();
// 仅在单 isolate 内存保存纯数值/布尔缓存，严禁跨请求共享含 I/O 的 Promise。
const localRateBuckets = new Map();
const localFailBuckets = new Map();
let subscriptionCache = null;
let subscriptionCacheVersion = 0;
let configMarkerKnown = false;

class HttpError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.headers = headers;
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

      const routes = resolveRoutes(env);
      if (path === routes.sub) {
        if (req.method !== 'GET') return methodNotAllowed('GET');
        return await handleSub(req, env, ctx, url);
      }
      if (path === routes.admin) {
        if (!['GET', 'POST'].includes(req.method)) return methodNotAllowed('GET, POST');
        return await handleAdmin(req, env, url, routes);
      }
      if (path === routes.logout) {
        if (req.method !== 'POST') return methodNotAllowed('POST');
        return await handleLogout(req, env, url, routes);
      }
      return textResponse('Not Found', 404);
    } catch (err) {
      if (err instanceof HttpError) {
        return textResponse(err.message, err.status, err.headers);
      }
      logError('unhandled_request_error', {
        path,
        method: req.method,
        name: err?.name || 'Error',
        message: err?.message || String(err),
      });
      return textResponse('Internal Server Error', 500);
    }
  },
};

function logError(event, detail = {}) {
  console.error(JSON.stringify({ level: 'error', event, ...detail }));
}

function normalizeRoutePath(value, fallback) {
  if (typeof value !== 'string' || !value.trim()) return fallback;
  const trimmed = value.trim();
  if (!/^\/[a-zA-Z0-9._~/-]{1,64}$/.test(trimmed) || trimmed === '/' || trimmed.endsWith('/') || trimmed.includes('//') || trimmed.split('/').includes('..')) {
    throw new HttpError(500, 'Server misconfigured: invalid custom route path');
  }
  return trimmed;
}

function resolveRoutes(env) {
  const sub = normalizeRoutePath(env.SUB_PATH, '/sub');
  const admin = normalizeRoutePath(env.ADMIN_PATH, '/admin');
  const logout = admin === '/admin' ? '/logout' : `${admin}/logout`;
  if (sub === admin || sub === logout) {
    throw new HttpError(500, 'Server misconfigured: SUB_PATH and ADMIN_PATH must be different');
  }
  return { sub, admin, logout };
}

function validateEnv(env) {
  if (
    !env ||
    !env.NODE_KV ||
    typeof env.NODE_KV.get !== 'function' ||
    typeof env.NODE_KV.put !== 'function' ||
    typeof env.NODE_KV.delete !== 'function' ||
    typeof env.NODE_KV.list !== 'function'
  ) {
    throw new HttpError(500, 'Server misconfigured: missing NODE_KV binding');
  }
  if (typeof env.ADMIN_TOKEN !== 'string' || env.ADMIN_TOKEN.length < MIN_ADMIN_PASSWORD_LENGTH) {
    throw new HttpError(500, `Server misconfigured: ADMIN_TOKEN must be at least ${MIN_ADMIN_PASSWORD_LENGTH} characters`);
  }
  if (typeof env.SUB_TOKEN !== 'string' || env.SUB_TOKEN.length < MIN_SUB_TOKEN_LENGTH) {
    throw new HttpError(500, `Server misconfigured: SUB_TOKEN must be at least ${MIN_SUB_TOKEN_LENGTH} characters`);
  }
  if (env.ADMIN_TOKEN === env.SUB_TOKEN) {
    throw new HttpError(500, 'Server misconfigured: ADMIN_TOKEN and SUB_TOKEN must be different');
  }
}

function isSecureConnection(url) {
  if (url.protocol === 'https:') return true;
  return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

function isKvRateLimitError(err) {
  return Boolean(err && typeof err.message === 'string' && /\b429\b|Too Many Requests/i.test(err.message));
}

function pruneBucketMap(map) {
  if (map.size >= MAX_LOCAL_BUCKETS) {
    const oldestKey = map.keys().next().value;
    if (oldestKey !== undefined) map.delete(oldestKey);
  }
}

function methodNotAllowed(allow) {
  return textResponse('Method Not Allowed', 405, { Allow: allow });
}

// -------------------------
// 订阅
// -------------------------
async function handleSub(req, env, ctx, url) {
  const token = url.searchParams.get('token') || '';
  if (!(await safeEqual(token, env.SUB_TOKEN))) throw new HttpError(404, 'Not Found');

  let body = readCachedSubscription();
  if (body === null) {
    const cacheVersion = subscriptionCacheVersion;
    const config = await getConfig(env);
    if (!configMarkerKnown) {
      const markerTask = ensureConfigInitialized(env).catch((err) => {
        logError('config_marker_migration_failed', { message: err?.message || String(err) });
      });
      if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(markerTask);
      else await markerTask;
    }

    body = encodeBase64Utf8(normalizeNodesForSub(config.nodes || ''));
    if (cacheVersion === subscriptionCacheVersion) cacheSubscription(body);
  }

  return new Response(body, {
    status: 200,
    headers: {
      ...baseHeaders(),
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': String(SUB_UPDATE_TIME),
    },
  });
}

function readCachedSubscription() {
  if (!subscriptionCache || subscriptionCache.expiresAt <= Date.now()) {
    subscriptionCache = null;
    return null;
  }
  return subscriptionCache.body;
}

function cacheSubscription(body) {
  subscriptionCache = {
    body,
    expiresAt: Date.now() + SUB_CACHE_TTL_MS,
  };
}

function invalidateSubscriptionCache() {
  subscriptionCache = null;
  subscriptionCacheVersion += 1;
}

function normalizeNodesForStorage(value) {
  return value.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
}

function normalizeNodesForSub(value) {
  return normalizeNodesForStorage(value)
    .split('\n')
    .map((line) => line.replace(/^\uFEFF/, '').trim())
    .filter(Boolean)
    .join('\n');
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
async function handleAdmin(req, env, url, routes) {
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
      logError('load_stats_failed', { message: err?.message || String(err) });
    }
    return htmlResponse(renderAdmin({
      nodes: config.nodes,
      stats,
      token: env.SUB_TOKEN,
      origin: url.origin,
      subPath: routes.sub,
      logoutPath: routes.logout,
      csrf: session.csrf,
      nonce,
    }), { nonce });
  }

  const form = await parseForm(req);

  if (form.has('password')) {
    const ipHash = await sha256Hex(getClientIp(req));
    return handleLogin(form, env, ipHash, nonce, session, routes.admin);
  }

  if (!session) return redirect(routes.admin);

  await requireCsrf(form, session);
  const nodes = normalizeNodesForStorage(getStringField(form, 'nodes'));
  validateNodesSize(nodes);
  await saveConfig(env, nodes);
  return redirect(`${routes.admin}?saved=1`);
}

async function handleLogin(form, env, ipHash, nonce, existingSession, adminPath) {
  const password = getStringField(form, 'password');
  if (password.length > 512) throw new HttpError(400, 'Bad Request');

  const rate = await checkLoginRate(env, ipHash);
  if (!rate.allowed) {
    return htmlResponse(renderLogin('操作过于频繁，请稍后再试', nonce), {
      status: 429,
      nonce,
      extra: { 'Retry-After': String(rate.retryAfter || 60) },
    });
  }

  const localReservation = reserveLocalLoginSlot(ipHash);
  if (!localReservation.allowed) {
    return htmlResponse(renderLogin('尝试次数过多，请稍后再试', nonce), {
      status: 429,
      nonce,
      extra: { 'Retry-After': String(localReservation.retryAfter || LOGIN_FAIL_TTL_SECONDS) },
    });
  }

  const kvFailure = await readLoginFailure(env, ipHash);
  if (kvFailure.count >= LOGIN_FAIL_LIMIT) {
    syncLocalLoginFailure(ipHash, kvFailure.count, kvFailure.last);
    const retryAfter = Math.max(1, Math.ceil((kvFailure.last + LOGIN_FAIL_TIMEOUT - Date.now()) / 1000));
    return htmlResponse(renderLogin('尝试次数过多，请稍后再试', nonce), {
      status: 429,
      nonce,
      extra: { 'Retry-After': String(retryAfter) },
    });
  }

  const passwordValid = await safeEqual(password, env.ADMIN_TOKEN);
  if (!passwordValid) {
    const persisted = await recordLoginFailure(env, ipHash, Math.max(localReservation.count, kvFailure.count + 1));
    if (persisted.rateLimited) {
      return htmlResponse(renderLogin('操作过于频繁，请稍后再试', nonce), {
        status: 429,
        nonce,
        extra: { 'Retry-After': '1' },
      });
    }
    return htmlResponse(renderLogin('密码错误', nonce), { status: 401, nonce });
  }

  localFailBuckets.delete(ipHash);
  if (kvFailure.count > 0) {
    await clearLoginFailure(env, ipHash);
  }
  if (existingSession) {
    await deleteSession(env, existingSession.id);
  }
  const session = await createSession(env);
  return redirectWithCookie(adminPath, session.cookie);
}

async function handleLogout(req, env, url, routes) {
  assertSameOrigin(req, url);
  const cookies = parseCookies(req.headers.get('Cookie') || '');
  const hasCookie = Object.prototype.hasOwnProperty.call(cookies, SESSION_COOKIE_NAME);
  const session = await getSession(req, env);

  if (!session) {
    return hasCookie
      ? redirect(routes.admin, 303, { 'Set-Cookie': clearSessionCookie() })
      : redirect(routes.admin, 303);
  }

  const form = await parseForm(req);
  await requireCsrf(form, session);
  await deleteSession(env, session.id);

  return redirect(routes.admin, 303, { 'Set-Cookie': clearSessionCookie() });
}

async function createSession(env) {
  const id = crypto.randomUUID();
  const csrf = makeNonce();
  const credential = await sha256Hex(env.ADMIN_TOKEN);
  await env.NODE_KV.put(
    `session:${id}`,
    JSON.stringify({ csrf, created: Date.now(), credential }),
    { expirationTtl: SESSION_TTL }
  );

  return {
    id,
    csrf,
    cookie: sessionCookie(id),
  };
}

async function getSession(req, env) {
  const cookies = parseCookies(req.headers.get('Cookie') || '');
  const id = cookies[SESSION_COOKIE_NAME];
  if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/i.test(id)) return null;

  const raw = await env.NODE_KV.get(`session:${id}`);
  if (raw === null) return null;

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    await env.NODE_KV.delete(`session:${id}`);
    return null;
  }

  if (!data || typeof data.csrf !== 'string' || typeof data.created !== 'number' || typeof data.credential !== 'string') {
    await env.NODE_KV.delete(`session:${id}`);
    return null;
  }

  const credential = await sha256Hex(env.ADMIN_TOKEN);
  if (!(await safeEqual(data.credential, credential))) {
    await env.NODE_KV.delete(`session:${id}`);
    return null;
  }

  if (Date.now() - data.created > SESSION_TTL * 1000) {
    await env.NODE_KV.delete(`session:${id}`);
    return null;
  }

  return { id, csrf: data.csrf, created: data.created };
}

async function deleteSession(env, id) {
  await env.NODE_KV.delete(`session:${id}`);
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

function reserveLocalLoginSlot(key) {
  const now = Date.now();
  const existing = localFailBuckets.get(key);
  if (existing && now - existing.last <= LOGIN_FAIL_TIMEOUT) {
    if (existing.count >= LOGIN_FAIL_LIMIT) {
      return {
        allowed: false,
        count: existing.count,
        retryAfter: Math.max(1, Math.ceil((existing.last + LOGIN_FAIL_TIMEOUT - now) / 1000)),
      };
    }
    const next = { count: existing.count + 1, last: now };
    localFailBuckets.set(key, next);
    return { allowed: true, count: next.count };
  }

  pruneBucketMap(localFailBuckets);
  const next = { count: 1, last: now };
  localFailBuckets.set(key, next);
  return { allowed: true, count: 1 };
}

function syncLocalLoginFailure(key, count, last) {
  pruneBucketMap(localFailBuckets);
  localFailBuckets.set(key, { count, last });
}

async function recordLoginFailure(env, key, count) {
  const next = { count, last: Date.now() };
  try {
    await env.NODE_KV.put(`login:${key}`, JSON.stringify(next), {
      expirationTtl: LOGIN_FAIL_TTL_SECONDS,
    });
    return { rateLimited: false };
  } catch (err) {
    if (isKvRateLimitError(err)) {
      return { rateLimited: true };
    }
    throw err;
  }
}

async function readLoginFailure(env, key) {
  const raw = await env.NODE_KV.get(`login:${key}`, { cacheTtl: KV_SHORT_CACHE_TTL });
  if (raw === null) return { count: 0, last: 0 };

  try {
    const value = JSON.parse(raw);
    if (
      !value ||
      !Number.isInteger(value.count) ||
      value.count < 0 ||
      !Number.isFinite(value.last)
    ) {
      return { count: 0, last: 0 };
    }
    if (Date.now() - value.last > LOGIN_FAIL_TIMEOUT) return { count: 0, last: 0 };
    return { count: value.count, last: value.last };
  } catch {
    return { count: 0, last: 0 };
  }
}

async function clearLoginFailure(env, key) {
  await env.NODE_KV.delete(`login:${key}`);
}

async function checkLoginRate(env, key) {
  const now = Date.now();
  const windowId = Math.floor(now / LOGIN_RATE_WINDOW_MS);
  const windowEnd = (windowId + 1) * LOGIN_RATE_WINDOW_MS;
  const retryAfter = Math.max(1, Math.ceil((windowEnd - now) / 1000));

  const local = localRateBuckets.get(key);
  let localCount = 1;
  if (local && local.windowId === windowId) {
    if (local.count >= LOGIN_RATE_LIMIT) {
      return { allowed: false, retryAfter };
    }
    localCount = local.count + 1;
  } else {
    pruneBucketMap(localRateBuckets);
  }
  localRateBuckets.set(key, { windowId, count: localCount });

  const storageKey = `rate:${key}:${windowId}`;
  const current = Number.parseInt(
    (await env.NODE_KV.get(storageKey, { cacheTtl: KV_SHORT_CACHE_TTL })) || '0',
    10
  );
  const safeCurrent = Number.isFinite(current) && current > 0 ? current : 0;
  if (safeCurrent >= LOGIN_RATE_LIMIT) {
    localRateBuckets.set(key, { windowId, count: LOGIN_RATE_LIMIT });
    return { allowed: false, retryAfter };
  }

  const nextCount = Math.max(localCount, safeCurrent + 1);
  try {
    await env.NODE_KV.put(storageKey, String(nextCount), {
      expirationTtl: LOGIN_RATE_TTL_SECONDS,
    });
  } catch (err) {
    if (isKvRateLimitError(err)) {
      return { allowed: false, retryAfter: 1 };
    }
    throw err;
  }

  return { allowed: true, retryAfter };
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
    logError('config_missing'); throw new HttpError(500, 'Internal Server Error');
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    logError('config_invalid_json'); throw new HttpError(500, 'Internal Server Error');
  }

  if (!data || typeof data !== 'object' || typeof data.nodes !== 'string') {
    logError('config_invalid_schema'); throw new HttpError(500, 'Internal Server Error');
  }
  validateNodesSize(data.nodes);
  if (allowUninitialized) await ensureConfigInitialized(env);
  return { nodes: data.nodes };
}

async function saveConfig(env, nodes) {
  // 先写配置再写标记：首次保存时即使数据写入失败，也不会留下标记导致后台永久 500。
  try {
    await env.NODE_KV.put(CONFIG_KEY, JSON.stringify({ nodes }));
  } catch (err) {
    if (isKvRateLimitError(err)) throw new HttpError(429, 'Too Many Requests', { 'Retry-After': '1' });
    throw err;
  }
  invalidateSubscriptionCache();
  await markConfigInitialized(env);
  configMarkerKnown = true;
}

async function ensureConfigInitialized(env) {
  if (configMarkerKnown) return;
  if (!(await isConfigInitialized(env))) {
    await markConfigInitialized(env);
  }
  configMarkerKnown = true;
}

async function isConfigInitialized(env) {
  return (await env.NODE_KV.get(CONFIG_INITIALIZED_KEY)) === '1';
}

async function markConfigInitialized(env) {
  await env.NODE_KV.put(CONFIG_INITIALIZED_KEY, '1');
}

async function loadStats(env) {
  const result = {};
  let cursor;
  let subrequests = 0;

  while (subrequests < STAT_MAX_SUBREQUESTS) {
    subrequests += 1;
    const list = await env.NODE_KV.list({ prefix: 'stat:', cursor });
    const keys = list.keys.map((key) => key.name);
    cursor = list.cursor;

    for (let i = 0; i < keys.length && subrequests < STAT_MAX_SUBREQUESTS; i += STAT_BATCH_SIZE) {
      subrequests += 1;
      const values = await env.NODE_KV.get(keys.slice(i, i + STAT_BATCH_SIZE));
      for (const [key, value] of values) {
        const country = key.slice('stat:'.length);
        const count = Number.parseInt(value || '0', 10);
        if (country && Number.isFinite(count)) result[country] = count;
      }
    }

    if (list.list_complete === true || !cursor) break;
  }

  return result;
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
  const secFetchSite = req.headers.get('Sec-Fetch-Site');
  const normalizedSite = secFetchSite ? secFetchSite.trim().toLowerCase() : '';
  if (normalizedSite && normalizedSite !== 'same-origin') {
    logError('origin_check_failed', { reason: 'sec_fetch_site', secFetchSite: normalizedSite });
    throw new HttpError(403, 'Forbidden');
  }

  const rawOrigin = req.headers.get('Origin');
  let requestOrigin = rawOrigin && rawOrigin.toLowerCase() !== 'null' ? rawOrigin : '';
  if (!requestOrigin) {
    const referer = req.headers.get('Referer');
    if (referer) {
      try {
        requestOrigin = new URL(referer).origin;
      } catch {
        logError('origin_check_failed', { reason: 'invalid_referer' });
        throw new HttpError(403, 'Forbidden');
      }
    }
  }

  const allowedOrigins = new Set([url.origin.toLowerCase()]);
  const host = (req.headers.get('Host') || '').trim();
  if (host && /^(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::\d{1,5})?$/i.test(host)) {
    allowedOrigins.add(`${url.protocol}//${host}`.toLowerCase());
  }

  if (requestOrigin) {
    if (!allowedOrigins.has(requestOrigin.toLowerCase())) {
      logError('origin_check_failed', { reason: 'origin_mismatch', secFetchSite: normalizedSite || null });
      throw new HttpError(403, 'Forbidden');
    }
    return;
  }

  if (normalizedSite !== 'same-origin') {
    logError('origin_check_failed', { reason: 'missing_origin_headers', rawOrigin: rawOrigin || null });
    throw new HttpError(403, 'Forbidden');
  }
}

// -------------------------
// 页面渲染
// -------------------------
function renderLogin(msg = '', nonce) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Sign In</title>
<style nonce="${nonce}">${baseStyle()}</style>
</head>
<body class="login-page">
<main class="login-wrapper">
  <section class="card login-card">
    <div class="login-head">
      <div class="logo-badge" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <h1>ADMIN ACCESS</h1>
      <p class="subtitle">输入管理密钥以继续</p>
    </div>
    ${msg ? `<div class="alert error" role="alert">${escapeHTML(msg)}</div>` : ''}
    <form method="post" class="stack">
      <label class="field-label" for="passwordInput">访问密钥</label>
      <div class="input-group">
        <input id="passwordInput" type="password" name="password" placeholder="Enter Access Key" required autocomplete="current-password" autofocus>
        <button type="button" class="btn-ghost" id="togglePwd" aria-label="显示或隐藏密钥">显示</button>
      </div>
      <button type="submit" class="btn-primary">登录</button>
    </form>
  </section>
</main>
<script nonce="${nonce}">
(function(){
  const toggle = document.getElementById('togglePwd');
  const input = document.getElementById('passwordInput');
  if (toggle && input) {
    toggle.addEventListener('click', () => {
      const next = input.type === 'password' ? 'text' : 'password';
      input.type = next;
      toggle.textContent = next === 'text' ? '隐藏' : '显示';
    });
  }
})();
</script>
</body>
</html>`;
}

function renderAdmin({ nodes, stats, token, origin, subPath, logoutPath, csrf, nonce }) {
  const link = `${origin}${subPath}?token=${encodeURIComponent(token)}`;
  const totalRequests = Object.values(stats).reduce((sum, value) => sum + value, 0);
  const regionCount = Object.keys(stats).length;

  const rows = Object.entries(stats)
    .sort(([, a], [, b]) => b - a)
    .map(([country, count]) => `<tr><td>${escapeHTML(country)}</td><td>${Number(count)}</td></tr>`)
    .join('');

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Node Control</title>
<style nonce="${nonce}">${baseStyle()}</style>
</head>
<body>
<div class="toast" id="toast" role="status" aria-live="polite">配置已保存</div>

<main class="container">
  <header class="topbar">
    <div class="brand">
      <span class="brand-dot" aria-hidden="true"></span>
      <span>NODE CONTROL</span>
    </div>
    <form method="post" action="${escapeHTML(logoutPath)}" class="logout-form">
      <input type="hidden" name="csrf" value="${escapeHTML(csrf)}">
      <button class="btn-danger" type="submit" title="退出登录" aria-label="退出登录">退出登录</button>
    </form>
  </header>

  <section class="stats-grid" aria-label="历史统计概览">
    <div class="stat-card">
      <div class="stat-label">历史订阅请求</div>
      <div class="stat-value mono">${totalRequests}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">覆盖地区</div>
      <div class="stat-value mono">${regionCount}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">统计状态</div>
      <div class="stat-value stat-tag">只读 · 统计已停写</div>
    </div>
  </section>

  <section class="card">
    <div class="card-head">
      <div>
        <h2>订阅链接</h2>
        <p class="hint">默认隐藏凭证防肩窥，可直接一键复制</p>
      </div>
    </div>
    <div class="input-group">
      <input id="subLink" class="mono" type="password" value="${escapeHTML(link)}" readonly aria-label="订阅链接">
      <button class="btn-ghost" type="button" id="toggleSub">显示</button>
      <button class="btn-primary btn-compact" type="button" id="copyBtn">复制链接</button>
    </div>
  </section>

  <section class="card">
    <div class="card-head">
      <div>
        <h2>节点配置</h2>
        <p class="hint">每行一条节点链接，支持 Ctrl/Cmd + S 快速保存；输出时自动去除 BOM、空行与 CRLF</p>
      </div>
      <span class="badge" id="dirtyBadge">已同步</span>
    </div>
    <form method="post" id="nodesForm" class="stack">
      <input type="hidden" name="csrf" value="${escapeHTML(csrf)}">
      <textarea name="nodes" id="nodesInput" class="mono" spellcheck="false" placeholder="在此粘贴节点链接（每行一条）...">${escapeHTML(nodes)}</textarea>
      <div class="editor-footer">
        <div class="meta-text mono" id="nodesMeta">0 条节点 · 已用 0.0 / 128 KiB</div>
        <div class="progress-track" aria-hidden="true"><div class="progress-bar" id="sizeBar"></div></div>
      </div>
      <div class="form-actions">
        <button type="submit" id="saveBtn" class="btn-primary">
          <span class="btn-text">保存配置</span>
          <span class="btn-loader" id="saveLoader">保存中...</span>
        </button>
      </div>
    </form>
  </section>

  <section class="card">
    <div class="card-head">
      <div>
        <h2>历史订阅统计</h2>
        <p class="hint">仅展示历史只读记录，订阅拉取不写入 KV</p>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>地区</th><th>次数</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="2" class="empty-cell">NO DATA</td></tr>'}</tbody>
      </table>
    </div>
  </section>
</main>

<script nonce="${nonce}">
(function(){
  const toast = document.getElementById('toast');
  function showToast(text) {
    if (!toast) return;
    toast.textContent = text;
    toast.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => toast.classList.remove('show'), 2600);
  }

  const params = new URLSearchParams(window.location.search);
  if (params.get('saved') === '1') {
    showToast('配置已保存');
    history.replaceState({}, '', window.location.pathname);
  }

  const subLink = document.getElementById('subLink');
  const toggleSub = document.getElementById('toggleSub');
  if (toggleSub && subLink) {
    toggleSub.addEventListener('click', () => {
      const show = subLink.type === 'password';
      subLink.type = show ? 'text' : 'password';
      toggleSub.textContent = show ? '隐藏' : '显示';
    });
  }

  const copyBtn = document.getElementById('copyBtn');
  if (copyBtn && subLink) {
    copyBtn.addEventListener('click', async () => {
      const value = subLink.value;
      try {
        await navigator.clipboard.writeText(value);
        copyBtn.textContent = '已复制';
        showToast('订阅链接已复制');
        setTimeout(() => { copyBtn.textContent = '复制链接'; }, 1500);
      } catch {
        const prevType = subLink.type;
        subLink.type = 'text';
        subLink.select();
        try {
          document.execCommand('copy');
          copyBtn.textContent = '已复制';
          showToast('订阅链接已复制');
          setTimeout(() => { copyBtn.textContent = '复制链接'; }, 1500);
        } catch {
          showToast('复制失败，请手动复制');
        } finally {
          subLink.type = prevType;
        }
      }
    });
  }

  const MAX_BYTES = ${MAX_NODES_BYTES};
  const encoder = new TextEncoder();
  const nodesForm = document.getElementById('nodesForm');
  const nodesInput = document.getElementById('nodesInput');
  const nodesMeta = document.getElementById('nodesMeta');
  const sizeBar = document.getElementById('sizeBar');
  const dirtyBadge = document.getElementById('dirtyBadge');
  const saveBtn = document.getElementById('saveBtn');
  const saveLoader = document.getElementById('saveLoader');
  const initialValue = nodesInput ? nodesInput.value : '';

  function updateNodesMeta() {
    if (!nodesInput || !nodesMeta) return 0;
    const raw = nodesInput.value;
    const bytes = encoder.encode(raw).byteLength;
    const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
    const kib = (bytes / 1024).toFixed(1);
    const pct = Math.min(100, (bytes / MAX_BYTES) * 100);
    const exceeded = bytes > MAX_BYTES;

    nodesMeta.textContent = exceeded
      ? lines + ' 条节点 · 已用 ' + kib + ' / 128 KiB（超出上限，请精简后再保存）'
      : lines + ' 条节点 · 已用 ' + kib + ' / 128 KiB';
    nodesMeta.classList.toggle('is-error', exceeded);

    if (sizeBar) {
      sizeBar.style.width = pct.toFixed(1) + '%';
      sizeBar.classList.toggle('is-error', exceeded);
    }
    if (dirtyBadge) {
      const dirty = raw !== initialValue;
      dirtyBadge.textContent = dirty ? '未保存' : '已同步';
      dirtyBadge.classList.toggle('is-dirty', dirty);
    }
    return bytes;
  }

  if (nodesInput) {
    updateNodesMeta();
    nodesInput.addEventListener('input', updateNodesMeta);
  }

  if (nodesForm) {
    nodesForm.addEventListener('submit', (event) => {
      if (updateNodesMeta() > MAX_BYTES) {
        event.preventDefault();
        showToast('节点内容超出 128 KiB 上限');
        return;
      }
      if (saveBtn) saveBtn.disabled = true;
      if (saveLoader) saveLoader.classList.add('is-loading');
      const btnText = saveBtn && saveBtn.querySelector('.btn-text');
      if (btnText) btnText.style.display = 'none';
    });
  }

  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's' && nodesForm) {
      event.preventDefault();
      nodesForm.requestSubmit();
    }
  });

  window.addEventListener('pageshow', () => {
    if (saveBtn) {
      saveBtn.disabled = false;
      const btnText = saveBtn.querySelector('.btn-text');
      if (btnText) btnText.style.display = '';
    }
    if (saveLoader) saveLoader.classList.remove('is-loading');
  });
})();
</script>
</body>
</html>`;
}

function baseStyle() {
  return `
:root{
  --bg:#0b1120;
  --surface:#111827;
  --surface-alt:#0f172a;
  --border:rgba(148,163,184,0.16);
  --border-strong:rgba(56,189,248,0.45);
  --text:#e2e8f0;
  --muted:#94a3b8;
  --accent:#38bdf8;
  --accent-hover:#0ea5e9;
  --danger:#f87171;
  --danger-bg:rgba(248,113,113,0.12);
  --ok:#34d399;
  --ok-bg:rgba(52,211,153,0.14);
  --warn:#fbbf24;
  --warn-bg:rgba(251,191,36,0.14);
  --radius:12px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{
  min-height:100vh;
  background:radial-gradient(circle at top,#172554 0%,var(--bg) 52%);
  color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  line-height:1.5;
  padding:28px 16px 48px;
}
body.login-page{
  display:flex;
  align-items:center;
  justify-content:center;
  padding:24px 16px;
}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}
.container{width:100%;max-width:880px;margin:0 auto;display:flex;flex-direction:column;gap:20px}
.login-wrapper{width:100%;max-width:400px}
.card{
  background:rgba(17,24,39,0.88);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:22px;
  backdrop-filter:blur(12px);
  box-shadow:0 12px 32px rgba(2,6,23,0.45);
}
.login-card{padding:28px 24px}
.login-head{text-align:center;margin-bottom:22px}
.logo-badge{
  width:48px;height:48px;margin:0 auto 14px;
  border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  color:var(--accent);
  background:rgba(56,189,248,0.12);
  border:1px solid rgba(56,189,248,0.28);
}
h1{font-size:1.2rem;font-weight:700;letter-spacing:0.08em}
h2{font-size:1rem;font-weight:600;letter-spacing:0.02em}
.subtitle,.hint{font-size:0.84rem;color:var(--muted);margin-top:4px}
.topbar{
  display:flex;align-items:center;justify-content:space-between;
  gap:12px;padding:4px 2px;
}
.brand{
  display:flex;align-items:center;gap:10px;
  font-size:1.05rem;font-weight:700;letter-spacing:0.1em;
}
.brand-dot{
  width:10px;height:10px;border-radius:50%;
  background:var(--accent);
  box-shadow:0 0 12px var(--accent);
}
.stats-grid{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:14px;
}
.stat-card{
  background:rgba(17,24,39,0.82);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:16px 18px;
}
.stat-label{font-size:0.8rem;color:var(--muted)}
.stat-value{font-size:1.45rem;font-weight:700;margin-top:6px;color:var(--text)}
.stat-tag{font-size:0.95rem;font-weight:600;color:var(--accent);margin-top:10px}
.card-head{
  display:flex;align-items:flex-start;justify-content:space-between;
  gap:12px;margin-bottom:14px;
}
.badge{
  flex-shrink:0;
  font-size:0.75rem;font-weight:600;
  padding:4px 10px;border-radius:999px;
  color:var(--ok);background:var(--ok-bg);
}
.badge.is-dirty{color:var(--warn);background:var(--warn-bg)}
.stack{display:flex;flex-direction:column;gap:12px}
.field-label{font-size:0.82rem;color:var(--muted)}
.input-group{display:flex;gap:8px;align-items:stretch}
input[type="text"],input[type="password"],textarea{
  width:100%;
  background:var(--surface-alt);
  border:1px solid var(--border);
  border-radius:8px;
  color:var(--text);
  padding:11px 13px;
  font-size:0.9rem;
  outline:none;
  transition:border-color .18s,box-shadow .18s;
}
input:focus,textarea:focus{
  border-color:var(--border-strong);
  box-shadow:0 0 0 3px rgba(56,189,248,0.16);
}
.input-group input{flex:1;min-width:0}
textarea{
  min-height:240px;height:280px;resize:vertical;
  line-height:1.55;font-size:0.86rem;
}
.editor-footer{display:flex;flex-direction:column;gap:6px}
.meta-text{font-size:0.78rem;color:var(--muted);text-align:right}
.meta-text.is-error{color:var(--danger);font-weight:600}
.progress-track{
  width:100%;height:4px;border-radius:999px;
  background:rgba(148,163,184,0.16);overflow:hidden;
}
.progress-bar{
  height:100%;width:0%;border-radius:999px;
  background:var(--accent);transition:width .15s ease;
}
.progress-bar.is-error{background:var(--danger)}
button{
  border:none;border-radius:8px;
  padding:10px 16px;font-size:0.88rem;font-weight:600;
  cursor:pointer;white-space:nowrap;
  transition:background .18s,border-color .18s,opacity .18s;
}
button:disabled{opacity:0.6;cursor:not-allowed}
.btn-primary{background:var(--accent);color:#082f49}
.btn-primary:hover:not(:disabled){background:var(--accent-hover)}
.btn-compact{flex-shrink:0}
.btn-ghost{
  background:transparent;color:var(--text);
  border:1px solid var(--border);flex-shrink:0;
}
.btn-ghost:hover:not(:disabled){border-color:var(--border-strong);color:var(--accent)}
.btn-danger{
  background:var(--danger-bg);color:var(--danger);
  border:1px solid rgba(248,113,113,0.3);
  padding:8px 14px;font-size:0.84rem;
}
.btn-danger:hover{background:#ef4444;color:#fff;border-color:#ef4444}
.form-actions{display:flex;justify-content:flex-end}
.form-actions .btn-primary{min-width:140px}
.btn-loader{display:none}
.btn-loader.is-loading{display:inline}
.alert.error{
  background:var(--danger-bg);color:var(--danger);
  border:1px solid rgba(248,113,113,0.32);
  border-radius:8px;padding:10px 12px;
  font-size:0.85rem;text-align:center;margin-bottom:14px;
}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{
  padding:10px 12px;text-align:left;font-size:0.88rem;
  border-bottom:1px solid var(--border);
}
th:last-child,td:last-child{text-align:right}
th{color:var(--muted);font-weight:600;font-size:0.8rem}
tbody tr:hover{background:rgba(148,163,184,0.06)}
.empty-cell{text-align:center!important;color:var(--muted);padding:18px}
.toast{
  position:fixed;top:18px;left:50%;
  transform:translateX(-50%) translateY(-80px);
  background:#0f172a;color:var(--ok);
  border:1px solid rgba(52,211,153,0.35);
  border-radius:8px;padding:10px 20px;
  font-size:0.86rem;font-weight:600;
  box-shadow:0 12px 28px rgba(2,6,23,0.55);
  transition:transform .25s ease;z-index:999;pointer-events:none;
}
.toast.show{transform:translateX(-50%) translateY(0)}
@media (max-width:640px){
  body{padding:16px 12px 36px}
  .card{padding:16px}
  .stats-grid{grid-template-columns:1fr}
  .input-group{flex-wrap:wrap}
  .input-group input{flex:1 1 100%}
  .input-group button{flex:1}
  .form-actions .btn-primary{width:100%}
  textarea{min-height:200px;height:220px}
}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{transition:none!important;animation:none!important}
}
`;
}

// -------------------------
// 响应与通用工具
// -------------------------
function baseHeaders() {
  return {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
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
      'Referrer-Policy': 'same-origin',
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
  if (typeof crypto.subtle.timingSafeEqual === 'function') {
    return crypto.subtle.timingSafeEqual(left, right);
  }
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
