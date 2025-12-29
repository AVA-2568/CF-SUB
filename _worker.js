/**
 * CF Worker - 稳定版（赛博朋克 UI）
 * KV：NODE_KV
 */

const SUBUpdateTime = 6;
const ALLOW_UA = /(v2ray|sing-box|singbox|Xray|nekobox|v2rayn|quantumult|loon|Shadowrocket)/i;

const ADMIN_COOKIE_NAME = 'admin_auth';
const ADMIN_COOKIE_MAX_AGE = 15 * 60;

const LOGIN_FAIL_LIMIT = 3;
const LOGIN_FAIL_TIMEOUT = 12 * 60 * 60 * 1000;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === '/sub') return handleSub(req, env);
    if (url.pathname === '/admin') return handleAdmin(req, env, url);
    return new Response('404', { status: 404 });
  }
};

// -------------------------
// 订阅
// -------------------------
async function handleSub(req, env) {
  const url = new URL(req.url);
  const token = url.searchParams.get('token');
  const ua = (req.headers.get('User-Agent') || '').toLowerCase();

  if (token !== env.SUB_TOKEN) return new Response('404', { status: 404 });
  if (!ALLOW_UA.test(ua)) return new Response('404', { status: 404 });

  const country = req.headers.get('CF-IPCountry') || 'N/A';
  const statKey = `stat:${country}`;

  const current = parseInt(await env.NODE_KV.get(statKey) || '0', 10);
  await env.NODE_KV.put(statKey, String(current + 1));

  const data = await getData(env);
  const body = btoa(unescape(encodeURIComponent(data.nodes || '')));

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': `${SUBUpdateTime}`,
    },
  });
}

// -------------------------
// 后台
// -------------------------
async function handleAdmin(req, env, url) {
  const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
  const cookies = parseCookies(req.headers.get('Cookie') || '');
  const isLogin = cookies[ADMIN_COOKIE_NAME] === env.ADMIN_TOKEN;

  const data = await getData(env);
  data.login_fail ||= {};
  const fail = data.login_fail[ip] || { count: 0, last: 0 };
  const now = Date.now();

  if (fail.count >= LOGIN_FAIL_LIMIT && now - fail.last < LOGIN_FAIL_TIMEOUT) {
    return html(renderLogin('你已被禁止访问，请 12 小时后再试'));
  }

  if (req.method === 'POST') {
    const form = await req.formData();
    const password = form.get('password');
    const nodes = form.get('nodes');

    if (password && !nodes) {
      if (password === env.ADMIN_TOKEN) {
        delete data.login_fail[ip];
        await saveData(env, data);
        return redirectLogin(env);
      }
      data.login_fail[ip] = { count: fail.count + 1, last: now };
      await saveData(env, data);
      return html(renderLogin('密码错误'));
    }

    if (!isLogin) return html(renderLogin());
    data.nodes = nodes || '';
    await saveData(env, data);
  }

  if (!isLogin) return html(renderLogin());

  const stats = await loadStats(env);
  return html(renderAdmin(data.nodes || '', stats, env.SUB_TOKEN, url));
}

// -------------------------
async function getData(env) {
  const raw = await env.NODE_KV.get('data');
  return raw ? JSON.parse(raw) : { nodes: '', login_fail: {} };
}

async function saveData(env, data) {
  await env.NODE_KV.put('data', JSON.stringify(data));
}

// -------------------------
async function loadStats(env) {
  const list = await env.NODE_KV.list({ prefix: 'stat:' });
  const result = {};
  for (const k of list.keys) {
    const country = k.name.replace('stat:', '');
    result[country] = parseInt(await env.NODE_KV.get(k.name) || '0', 10);
  }
  return result;
}

// -------------------------
// 页面（赛博朋克）
// -------------------------
function renderLogin(msg = '') {
  return `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Admin Login</title>
<style>${baseStyle()}</style>
</head>
<body>
<div class="card glow">
  <h1>ADMIN ACCESS</h1>
  ${msg ? `<div class="error">${msg}</div>` : ''}
  <form method="post">
    <input type="password" name="password" placeholder="Enter Access Key" required>
    <button>LOGIN</button>
  </form>
</div>
</body>
</html>`;
}

function renderAdmin(nodes, stats, token, url) {
  const link = `${url.protocol}//${url.host}/sub?token=${token}`;
  const rows = Object.entries(stats).map(
    ([c, n]) => `<tr><td>${c}</td><td>${n}</td></tr>`
  ).join('');

  return `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Node Admin</title>
<style>${baseStyle()}</style>
</head>
<body>

<div class="container">

  <div class="card glow">
    <h1>NODE CONTROL</h1>
    <form method="post">
      <textarea name="nodes" spellcheck="false">${escapeHTML(nodes)}</textarea>
      <button>SAVE CONFIG</button>
    </form>
  </div>

  <div class="card">
    <h2>SUBSCRIPTION LINK</h2>
    <input value="${link}" readonly onclick="this.select()">
  </div>

  <div class="card">
    <h2>SUBSCRIPTION STATS</h2>
    <table>
      <tr><th>REGION</th><th>COUNT</th></tr>
      ${rows || '<tr><td colspan="2">NO DATA</td></tr>'}
    </table>
  </div>

</div>

</body>
</html>`;
}

// -------------------------
function baseStyle() {
  return `
*{box-sizing:border-box}
body{
  margin:0;
  min-height:100vh;
  background:radial-gradient(circle at top,#1b1b3a,#050510);
  color:#00f6ff;
  font-family:Consolas,monospace;
  display:flex;
  align-items:center;
  justify-content:center;
}
.container{width:100%;max-width:960px;padding:20px}
.card{
  background:rgba(10,10,30,.85);
  border:1px solid #00f6ff55;
  border-radius:8px;
  padding:20px;
  margin-bottom:20px;
}
.glow{
  box-shadow:0 0 15px #00f6ff66;
}
h1,h2{
  margin-top:0;
  text-align:center;
  letter-spacing:2px;
}
textarea,input{
  width:100%;
  background:#050510;
  border:1px solid #00f6ff55;
  color:#00f6ff;
  padding:10px;
  border-radius:4px;
  margin-top:10px;
}
textarea{height:240px}
button{
  width:100%;
  margin-top:15px;
  padding:12px;
  background:#00f6ff;
  border:none;
  color:#050510;
  font-weight:bold;
  cursor:pointer;
}
button:hover{background:#00c4cc}
table{
  width:100%;
  border-collapse:collapse;
  margin-top:10px;
}
th,td{
  border:1px solid #00f6ff33;
  padding:8px;
  text-align:center;
}
.error{
  color:#ff4d4d;
  text-align:center;
  margin-bottom:10px;
}
`;
}

// -------------------------
function parseCookies(str) {
  return Object.fromEntries(str.split(';').map(v => v.trim().split('=')));
}
function escapeHTML(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function html(body) {
  return new Response(body, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
function redirectLogin(env) {
  return new Response('<script>location="/admin"</script>', {
    headers: [
      ['Set-Cookie', `${ADMIN_COOKIE_NAME}=${env.ADMIN_TOKEN}; HttpOnly; Path=/admin; Max-Age=${ADMIN_COOKIE_MAX_AGE}`],
      ['Content-Type', 'text/html'],
    ],
  });
}
