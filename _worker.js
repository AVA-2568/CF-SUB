/**
 * CF Worker - 生产级安全加固版（赛博朋克 UI）
 * KV：NODE_KV
 * 
 * 安全增强：
 *   ✅ HTTPS 强制跳转
 *   ✅ Session ID 替代密码 Cookie
 *   ✅ 完整 XSS 转义
 *   ✅ 错误处理 + 日志脱敏
 *   ✅ Cookie 解析容错
 *   ✅ Session 验证容错
 * 
 * 功能增强：
 *   ✅ 登出功能
 *   ✅ 保存反馈 Toast
 *   ✅ 一键复制按钮
 *   ✅ KV 分页加载统计
 */

const SUBUpdateTime = 6;
const ALLOW_UA = /(v2ray|sing-box|singbox|xray|nekobox|v2rayn|quantumult|loon|shadowrocket)/i;

const SESSION_COOKIE_NAME = 'admin_session';
const SESSION_TTL = 15 * 60;

const LOGIN_FAIL_LIMIT = 3;
const LOGIN_FAIL_TIMEOUT = 12 * 60 * 60 * 1000;

// 缓存层（缩短 TTL 避免多实例数据不一致）
const CACHE = new Map();
const CACHE_TTL = 5 * 1000;  // 5 秒

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    try {
      // 🔒 HTTPS 强制跳转
      if (!isSecureConnection(req)) {
        return Response.redirect(`https://${url.host}${path}${url.search}`, 301);
      }

      switch (path) {
        case '/sub':
          return handleSub(req, env);
        case '/admin':
          return handleAdmin(req, env, url);
        case '/logout':
          return handleLogout(req, env);
        default:
          return new Response('404', { status: 404 });
      }
    } catch (err) {
      console.error(`[${path}]`, { message: err.message, name: err.name });
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};

// 🔒 HTTPS 检查
function isSecureConnection(req) {
  const forwardedProto = req.headers.get('x-forwarded-proto');
  const ssl = req.headers.get('x-forwarded-ssl');
  return forwardedProto === 'https' || ssl === 'on';
}

// -------------------------
// 订阅
// -------------------------
async function handleSub(req, env) {
  try {
    const url = new URL(req.url);
    const token = url.searchParams.get('token');
    const ua = (req.headers.get('User-Agent') || '').toLowerCase();

    if (token !== env.SUB_TOKEN) return new Response('404', { status: 404 });
    if (!ALLOW_UA.test(ua)) return new Response('404', { status: 404 });

    const country = req.headers.get('CF-IPCountry') || 'N/A';
    const statKey = `stat:${country}`;

    try {
      const current = parseInt(await env.NODE_KV.get(statKey) || '0', 10);
      await env.NODE_KV.put(statKey, String(current + 1));
    } catch (err) {
      console.error('stat update failed', { message: err.message });
    }

    const data = await getData(env);
    
    // 🔒 安全的 Base64 编码
    try {
      const encoder = new TextEncoder();
      const bytes = encoder.encode(data.nodes || '');
      const body = btoa(String.fromCharCode(...bytes));

      return new Response(body, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Profile-Update-Interval': `${SUBUpdateTime}`,
        },
      });
    } catch (err) {
      console.error('Base64 encode failed', { message: err.message });
      return new Response('Encoding Error', { status: 500 });
    }
  } catch (err) {
    console.error('handleSub failed', { message: err.message, name: err.name });
    return new Response('Internal Server Error', { status: 500 });
  }
}

// -------------------------
// 后台
// -------------------------
async function handleAdmin(req, env, url) {
  try {
    const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
    const cookies = parseCookies(req.headers.get('Cookie') || '');
    const sessionId = cookies[SESSION_COOKIE_NAME];

    // 🔒 验证 Session（带空值检查）
    const isLogin = sessionId ? await validateSession(sessionId, env) : false;

    const data = await getData(env);
    data.login_fail ||= {};
    const fail = data.login_fail[ip] || { count: 0, last: 0 };
    const now = Date.now();

    // IP 锁定检查
    if (fail.count >= LOGIN_FAIL_LIMIT && now - fail.last < LOGIN_FAIL_TIMEOUT) {
      return html(renderLogin('你已被禁止访问，请 12 小时后再试'));
    }

    // POST 处理：登录 或 修改节点
    if (req.method === 'POST') {
      const form = await req.formData();
      const password = form.get('password');
      const nodes = form.get('nodes');

      // 登录请求（仅有密码字段）
      if (password && !nodes) {
        if (password === env.ADMIN_TOKEN) {
          delete data.login_fail[ip];
          await saveData(env, data);
          return createSessionAndRedirect(env, ip);
        }
        data.login_fail[ip] = { count: fail.count + 1, last: now };
        await saveData(env, data);
        return html(renderLogin('密码错误'));
      }

      // 修改节点请求（需已登录）
      if (!isLogin) return html(renderLogin());

      data.nodes = nodes || '';
      await saveData(env, data);
      return Response.redirect(`${url.origin}/admin?saved=1`, 302);
    }

    // GET 请求
    if (!isLogin) return html(renderLogin());

    const stats = await loadStats(env);
    return html(renderAdmin(data.nodes || '', stats, env.SUB_TOKEN, url));
  } catch (err) {
    console.error('handleAdmin failed', { message: err.message, name: err.name });
    return new Response('Internal Server Error', { status: 500 });
  }
}

// -------------------------
// 登出
// -------------------------
async function handleLogout(req, env) {
  try {
    const cookies = parseCookies(req.headers.get('Cookie') || '');
    const sessionId = cookies[SESSION_COOKIE_NAME];

    if (sessionId) {
      try {
        await env.NODE_KV.delete(`session:${sessionId}`);
      } catch (err) {
        console.error('session delete failed', { message: err.message });
      }
    }

    const clearCookie = `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=0`;

    return new Response('<script>window.location.href="/admin"</script>', {
      headers: [
        ['Set-Cookie', clearCookie],
        ['Content-Type', 'text/html; charset=utf-8'],
      ],
    });
  } catch (err) {
    console.error('handleLogout failed', { message: err.message, name: err.name });
    return new Response('Internal Server Error', { status: 500 });
  }
}

// -------------------------
// 🔒 Session 管理
// -------------------------
async function createSessionAndRedirect(env, ip) {
  try {
    const sessionId = crypto.randomUUID();
    const sessionData = JSON.stringify({ ip, created: Date.now() });

    await env.NODE_KV.put(`session:${sessionId}`, sessionData, {
      expirationTtl: SESSION_TTL,
    });

    const cookie = `${SESSION_COOKIE_NAME}=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=${SESSION_TTL}`;

    return new Response('<script>location="/admin"</script>', {
      headers: [
        ['Set-Cookie', cookie],
        ['Content-Type', 'text/html; charset=utf-8'],
      ],
    });
  } catch (err) {
    console.error('createSession failed', { message: err.message });
    return html(renderLogin('系统错误，请重试'));
  }
}

// 🔒 Session 验证（带空值检查）
async function validateSession(sessionId, env) {
  if (!sessionId || typeof sessionId !== 'string') return false;
  try {
    const raw = await env.NODE_KV.get(`session:${sessionId}`);
    return !!raw;
  } catch (err) {
    console.error('validateSession failed', { message: err.message });
    return false;
  }
}

// -------------------------
// KV 工具
// -------------------------
async function getData(env) {
  try {
    const cached = CACHE.get('data');
    if (cached && Date.now() - cached.time < CACHE_TTL) {
      return cached.data;
    }
    const raw = await env.NODE_KV.get('data');
    const data = raw ? JSON.parse(raw) : { nodes: '', login_fail: {} };
    CACHE.set('data', { data, time: Date.now() });
    return data;
  } catch (err) {
    console.error('getData failed', { message: err.message });
    return { nodes: '', login_fail: {} };
  }
}

async function saveData(env, data) {
  try {
    await env.NODE_KV.put('data', JSON.stringify(data));
    CACHE.delete('data');
  } catch (err) {
    console.error('saveData failed', { message: err.message });
    throw err;
  }
}

// 🔒 统计加载（支持分页，突破 1000 条限制）
async function loadStats(env) {
  try {
    const result = {};
    let cursor = undefined;
    
    do {
      const list = await env.NODE_KV.list({ prefix: 'stat:', cursor });
      cursor = list.cursor;
      
      const keys = list.keys.map(k => k.name);
      if (keys.length > 0) {
        const results = await env.NODE_KV.getMany(keys);
        for (const [key, value] of Object.entries(results)) {
          const country = key.replace('stat:', '');
          result[country] = parseInt(value || '0', 10);
        }
      }
    } while (cursor);
    
    return result;
  } catch (err) {
    console.error('loadStats failed', { message: err.message });
    return {};
  }
}

// -------------------------
// 页面渲染
// -------------------------
function renderLogin(msg = '') {
  return `
<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login</title>
<style>${baseStyle()}</style>
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

function renderAdmin(nodes, stats, token, url) {
  const link = `${url.protocol}//${url.host}/sub?token=${token}`;
  const totalUsers = Object.values(stats).reduce((a, b) => a + b, 0);
  const regionCount = Object.keys(stats).length;
  
  const rows = Object.entries(stats)
    .sort(([, a], [, b]) => b - a)
    .map(([c, n]) => `<tr><td>${escapeHTML(c)}</td><td>${n}</td></tr>`)
    .join('');

  return `
<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Node Admin</title>
<style>${baseStyle()}</style>
</head>
<body>

<div class="container">

  <!-- 保存成功反馈 -->
  <div class="toast success" id="toast">✔ 配置已保存</div>

  <div class="header-section">
    <div class="brand">
      <svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor">
        <path d="M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z"/>
      </svg>
      <span>NODE CONTROL</span>
    </div>
    <a href="/logout" class="logout-btn" title="登出">⏻</a>
  </div>

  <!-- 统计概览 -->
  <div class="stats-overview">
    <div class="stat-card">
      <div class="stat-icon">📊</div>
      <div class="stat-value">${totalUsers}</div>
      <div class="stat-label">总订阅用户</div>
    </div>
    <div class="stat-card">
      <div class="stat-icon">🌍</div>
      <div class="stat-value">${regionCount}</div>
      <div class="stat-label">覆盖地区</div>
    </div>
    <div class="stat-card">
      <div class="stat-icon">🕐</div>
      <div class="stat-value">实时</div>
      <div class="stat-label">数据状态</div>
    </div>
  </div>

  <div class="card">
    <h2>节点配置</h2>
    <form method="post">
      <textarea name="nodes" spellcheck="false" placeholder="在此粘贴节点配置...">${escapeHTML(nodes)}</textarea>
      <button type="submit" id="saveBtn">
        <span class="btn-text">SAVE CONFIG</span>
        <span class="btn-loader" style="display:none;">⏳</span>
      </button>
    </form>
  </div>

  <div class="card">
    <h2>订阅链接</h2>
    <div class="link-wrapper">
      <input value="${link}" readonly onclick="this.select()">
      <button class="copy-btn" type="button" onclick="copyLink('${escapeHtmlForJs(link)}')">COPY</button>
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

<script>
// Toast 反馈
(function(){
  const params = new URLSearchParams(window.location.search);
  if (params.get('saved') === '1') {
    const toast = document.getElementById('toast');
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
    history.replaceState({}, '', window.location.pathname);
  }
})();

// 复制功能
function copyLink(text) {
  navigator.clipboard.writeText(text).then(() => {
    const btn = event.target;
    const original = btn.textContent;
    btn.textContent = 'COPIED!';
    btn.style.background = '#00c853';
    setTimeout(() => {
      btn.textContent = original;
      btn.style.background = '';
    }, 1500);
  }).catch(err => {
    console.error('Copy failed:', err);
    alert('复制失败，请手动复制');
  });
}

// 按钮加载状态
document.querySelector('form').addEventListener('submit', function(e) {
  const btn = this.querySelector('#saveBtn');
  btn.disabled = true;
  btn.querySelector('.btn-text').style.display = 'none';
  btn.querySelector('.btn-loader').style.display = 'inline';
});
</script>

</body>
</html>`;
}

// -------------------------
// 样式
// -------------------------
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
.logout-btn{
  color:#ff4d6a;
  text-decoration:none;
  font-size:1.4rem;
  line-height:1;
  padding:8px 12px;
  border-radius:6px;
  transition:all .2s;
  background:rgba(255,77,106,0.1);
}
.logout-btn:hover{
  background:#ff4d6a;
  color:#fff;
  transform:scale(1.1);
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
@media (max-width:768px){
  body{padding:12px;align-items:flex-start;padding-top:20px}
  .card{padding:18px;border-radius:10px}
  textarea{height:200px;font-size:13px}
  button{padding:14px;font-size:14px}
  th,td{padding:10px 6px;font-size:13px}
  .logout-btn{font-size:1.2rem}
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
  .logout-btn{font-size:1.1rem}
  .stats-overview{grid-template-columns:1fr}
  .stat-card{padding:14px}
  .stat-icon{font-size:1.5rem}
  .stat-value{font-size:1.3rem}
  .stat-label{font-size:0.8rem}
  .link-wrapper{flex-direction:column}
  .copy-btn{width:100%;margin-left:0}
}
.btn-loader{display:inline-block;margin-left:8px}
`;
}

// -------------------------
// 工具函数
// -------------------------

// 🔒 修复后的 Cookie 解析（容错处理）
function parseCookies(str) {
  if (!str) return {};
  return Object.fromEntries(
    str.split(';').map(v => {
      const [key, ...valueParts] = v.trim().split('=');
      const value = valueParts.join('=');  // 处理值中包含=的情况
      try {
        return [decodeURIComponent(key), decodeURIComponent(value || '')];
      } catch (e) {
        return [key, value || ''];
      }
    }).filter(([k, v]) => k && v)  // 过滤空值
  );
}

// 🔒 完整 XSS 转义
function escapeHTML(s) {
  if (typeof s !== 'string') return '';
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// 🔒 JS 字符串转义
function escapeHtmlForJs(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
}

// 🔒 安全响应头
function html(body) {
  return new Response(body, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    },
  });
}
