/**
 * CF Worker - 单 KV 版本
 * KV 名称：NODE_KV
 * 数据结构：
 * {
 *   "nodes": "...节点文本...",
 *   "logs": { "CN": 5, "US": 2, ... }
 * }
 */

const SUBUpdateTime = 6; // Clash 等客户端轮询间隔（分钟）
const ALLOW_UA = /(clash|sing-box|singbox|v2ray|nekobox|surge|quantumult|loon)/i;
const ADMIN_COOKIE_NAME = 'admin_auth';
const ADMIN_COOKIE_MAX_AGE = 10 * 60; // 10 分钟
const MAX_PASSWORD_LENGTH = 64;
const MAX_NODES_LENGTH = 10000; // 节点文本最大长度

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/sub') {
      return handleSub(request, env);
    }

    if (url.pathname === '/admin') {
      return handleAdmin(request, env, url);
    }

    return new Response('404 Not Found', { status: 404 });
  },
};

// -------------------------
// /sub 客户端订阅
// -------------------------
async function handleSub(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();

  if (!env.SUB_TOKEN || token !== env.SUB_TOKEN) {
    return new Response('403 Forbidden', { status: 403 });
  }

  if (!ALLOW_UA.test(ua)) {
    return new Response('UA Not Allowed', { status: 403 });
  }

  const data = await getKV(env);

  // 记录拉取次数（按国家）
  const country = request.headers.get('CF-IPCountry') || 'N/A';
  data.logs = data.logs || {};
  data.logs[country] = (data.logs[country] || 0) + 1;

  await env.NODE_KV.put('data', JSON.stringify(data));

  const base64 = btoa(unescape(encodeURIComponent(data.nodes || '')));

  return new Response(base64, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': `${SUBUpdateTime}`,
    },
  });
}

// -------------------------
// /admin 管理后台
// -------------------------
async function handleAdmin(request, env, url) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const isAuthenticated = cookies[ADMIN_COOKIE_NAME] === env.ADMIN_TOKEN;

  if (request.method === 'POST') {
    const form = await request.formData();
    const password = form.get('password')?.trim();
    const nodes = form.get('nodes')?.trim();

    // 登录流程
    if (password && !nodes) {
      if (password.length > MAX_PASSWORD_LENGTH) {
        return new Response(renderLogin('密码过长'), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      if (password === env.ADMIN_TOKEN) {
        return new Response('<script>location.href="/admin"</script>', {
          headers: [
            ['Set-Cookie', `${ADMIN_COOKIE_NAME}=${env.ADMIN_TOKEN}; Path=/admin; HttpOnly; Max-Age=${ADMIN_COOKIE_MAX_AGE}`],
            ['Content-Type', 'text/html; charset=utf-8'],
          ],
        });
      } else {
        return new Response(renderLogin('密码错误'), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
    }

    // 保存节点流程
    if (!isAuthenticated) {
      return new Response(renderLogin(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (!nodes || nodes.length > MAX_NODES_LENGTH) {
      return new Response('节点内容为空或过长', { status: 400 });
    }

    const data = await getKV(env);
    data.nodes = nodes;
    await env.NODE_KV.put('data', JSON.stringify(data));

    return new Response(renderAdmin(data.nodes || '', data.logs || {}, env.SUB_TOKEN, url), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  // GET 请求
  if (!isAuthenticated) {
    return new Response(renderLogin(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  const data = await getKV(env);
  return new Response(renderAdmin(data.nodes || '', data.logs || {}, env.SUB_TOKEN, url), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// -------------------------
// KV 操作封装
// -------------------------
async function getKV(env) {
  const raw = await env.NODE_KV.get('data');
  if (!raw) return { nodes: '', logs: {} };
  try {
    const parsed = JSON.parse(raw);
    parsed.logs = parsed.logs || {};
    return parsed;
  } catch {
    return { nodes: '', logs: {} };
  }
}

// -------------------------
// 管理页面 HTML
// -------------------------
function renderAdmin(nodes, logs, subToken, url) {
  const rows = Object.entries(logs).map(([country, count]) => `
<tr>
<td>${country}</td>
<td>${count}</td>
</tr>`).join('');

  // 构建订阅链接
  const subLink = `${url.protocol}//${url.host}/sub?token=${subToken}`;

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Node Admin</title>
<style>
body{background:#111;color:#eee;font-family:system-ui;padding:20px}
textarea{width:100%;height:260px;background:#000;color:#0f0}
table{width:100%;border-collapse:collapse;margin-top:20px;font-size:12px}
td,th{border:1px solid #333;padding:6px}
th{background:#222}
button{margin-top:8px;padding:8px 16px}
input.sub-link{width:100%;padding:6px;background:#222;color:#0f0;border:none;cursor:text}
</style>
</head>
<body>

<h2>节点管理</h2>
<form method="post">
<textarea name="nodes" spellcheck="false">${escapeHTML(nodes)}</textarea><br>
<button type="submit">保存</button>
</form>

<h2>当前订阅链接</h2>
<input class="sub-link" type="text" readonly value="${subLink}" onclick="this.select()">

<h2>订阅拉取记录（按国家统计）</h2>
<table>
<tr><th>国家</th><th>拉取次数</th></tr>
${rows || '<tr><td colspan="2">暂无记录</td></tr>'}
</table>

</body>
</html>`;
}

// -------------------------
// 登录页面 HTML
// -------------------------
function renderLogin(msg = '') {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Admin Login</title>
<style>
body{background:#111;color:#eee;font-family:system-ui;padding:20px}
input{width:200px;padding:6px;margin:8px 0}
button{padding:6px 12px}
.error{color:red}
</style>
</head>
<body>
<h2>管理员登录</h2>
${msg ? `<p class="error">${escapeHTML(msg)}</p>` : ''}
<form method="post">
密码：<input type="password" name="password" required><br>
<button type="submit">登录</button>
</form>
</body>
</html>`;
}

// -------------------------
// 工具函数
// -------------------------
function escapeHTML(str) {
  return str.replace(/&/g,'&amp;')
            .replace(/</g,'&lt;')
            .replace(/>/g,'&gt;');
}

function parseCookies(cookieHeader) {
  const cookies = {};
  cookieHeader.split(';').forEach(cookie => {
    const [key, value] = cookie.split('=').map(c => c.trim());
    if (key && value) cookies[key] = value;
  });
  return cookies;
}
