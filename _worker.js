/**
 * CF Worker - 单 KV 版本 - 赛博风格管理后台
 * KV 名称：NODE_KV
 */

const SUBUpdateTime = 6;
const ALLOW_UA = /(clash|sing-box|singbox|v2ray|nekobox|surge|quantumult|loon)/i;

const ADMIN_COOKIE_NAME = 'admin_auth';
const ADMIN_COOKIE_MAX_AGE = 30 * 60;

const LOGIN_FAIL_LIMIT = 5;
const LOGIN_FAIL_TIMEOUT = 12 * 60 * 60 * 1000; // 封禁 12 小时

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/sub') return handleSub(request, env);
    if (url.pathname === '/admin') return handleAdmin(request, env, url);
    return new Response('404', { status: 404 });
  }
};

// -------------------------
// /sub 客户端订阅
// -------------------------
async function handleSub(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();

  if (token !== env.SUB_TOKEN) return new Response('403', { status: 403 });
  if (!ALLOW_UA.test(ua)) return new Response('403', { status: 403 });

  const data = await getKV(env);

  const country = request.headers.get('CF-IPCountry') || 'N/A';
  data.logs = data.logs || {};
  data.logs[country] = (data.logs[country] || 0) + 1;

  await env.NODE_KV.put('data', JSON.stringify(data));

  return new Response(
    btoa(unescape(encodeURIComponent(data.nodes || ''))),
    {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Profile-Update-Interval': `${SUBUpdateTime}`,
      },
    }
  );
}

// -------------------------
// /admin 后台
// -------------------------
async function handleAdmin(request, env, url) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const isLogin = cookies[ADMIN_COOKIE_NAME] === env.ADMIN_TOKEN;

  const data = await getKV(env);
  data.login_fail = data.login_fail || {};
  const fail = data.login_fail[ip] || { count: 0, last: 0 };
  const now = Date.now();

  if (fail.count >= LOGIN_FAIL_LIMIT && now - fail.last < LOGIN_FAIL_TIMEOUT) {
    return html(renderLogin('你已被禁止访问，请稍后再试'));
  }

  if (request.method === 'POST') {
    const form = await request.formData();
    const password = form.get('password');
    const nodes = form.get('nodes');

    if (password && !nodes) {
      if (password === env.ADMIN_TOKEN) {
        delete data.login_fail[ip];
        await env.NODE_KV.put('data', JSON.stringify(data));

        return new Response('<script>location="/admin"</script>', {
          headers: [
            ['Set-Cookie', `${ADMIN_COOKIE_NAME}=${env.ADMIN_TOKEN}; HttpOnly; Path=/admin; Max-Age=${ADMIN_COOKIE_MAX_AGE}`],
            ['Content-Type', 'text/html'],
          ],
        });
      }

      data.login_fail[ip] = { count: fail.count + 1, last: now };
      await env.NODE_KV.put('data', JSON.stringify(data));
      return html(renderLogin('密码错误'));
    }

    if (!isLogin) return html(renderLogin());

    data.nodes = nodes || '';
    await env.NODE_KV.put('data', JSON.stringify(data));
  }

  if (!isLogin) return html(renderLogin());

  return html(renderAdmin(data.nodes || '', data.logs || {}, env.SUB_TOKEN, url));
}

// -------------------------
// KV 获取
// -------------------------
async function getKV(env) {
  const raw = await env.NODE_KV.get('data');
  return raw ? JSON.parse(raw) : { nodes: '', logs: {}, login_fail: {} };
}

// -------------------------
// 赛博风格登录页
// -------------------------
function renderLogin(msg = '') {
  return `
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Admin Login</title>
<style>
body {background:#0f0c29; color:#0ff; font-family:'Courier New', monospace; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;}
.container {background: rgba(0,0,0,0.6); padding:40px; border:1px solid #0ff; border-radius:10px; width:300px; text-align:center; box-shadow: 0 0 20px #0ff;}
input, button {width:100%; padding:10px; margin:10px 0; background:#111; color:#0ff; border:1px solid #0ff; border-radius:5px; font-family:'Courier New', monospace;}
button:hover {background:#0ff; color:#111; cursor:pointer;}
.error {color:#f00; font-weight:bold;}
h2 {margin-bottom:20px;}
</style>
</head>
<body>
<div class="container">
<h2>管理员登录</h2>
${msg ? `<p class="error">${escapeHTML(msg)}</p>` : ''}
<form method="post">
<input type="password" name="password" placeholder="输入密码" required>
<button type="submit">登录</button>
</form>
</div>
</body>
</html>`;
}

// -------------------------
// 赛博风格后台
// -------------------------
function renderAdmin(nodes, logs, token, url) {
  const link = `${url.protocol}//${url.host}/sub?token=${token}`;
  const rows = Object.entries(logs).map(
    ([c, n]) => `<tr><td>${c}</td><td>${n}</td></tr>`
  ).join('');

  return `
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Node Admin</title>
<style>
body {background:#0f0c29; color:#0ff; font-family:'Courier New', monospace; margin:0; padding:20px;}
h2,h3 {border-bottom:1px solid #0ff; padding-bottom:5px;}
textarea {width:100%; height:260px; background:#111; color:#0ff; border:1px solid #0ff; padding:10px; font-family:'Courier New', monospace; border-radius:5px;}
input.sub-link {width:100%; padding:10px; background:#111; color:#0ff; border:1px solid #0ff; border-radius:5px; margin-bottom:20px; cursor:text;}
table {width:100%; border-collapse:collapse; margin-top:10px;}
td, th {border:1px solid #0ff; padding:8px; text-align:center;}
th {background:#111;}
button {padding:10px 20px; margin-top:10px; background:#111; color:#0ff; border:1px solid #0ff; border-radius:5px;}
button:hover {background:#0ff; color:#111; cursor:pointer;}
form {margin-bottom:20px;}
</style>
</head>
<body>

<h2>节点管理</h2>
<form method="post">
<textarea name="nodes" spellcheck="false">${escapeHTML(nodes)}</textarea>
<button type="submit">保存节点</button>
</form>

<h3>当前订阅链接</h3>
<input class="sub-link" value="${link}" onclick="this.select()" readonly>

<h3>订阅拉取统计</h3>
<table>
<tr><th>国家</th><th>次数</th></tr>
${rows || '<tr><td colspan=2>暂无记录</td></tr>'}
</table>

</body>
</html>`;
}

// -------------------------
// 工具函数
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
