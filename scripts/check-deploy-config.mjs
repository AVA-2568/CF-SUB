import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const args = process.argv.slice(2);
const allowPlaceholder = args.includes('--allow-placeholder');
const configArg = args.find((arg) => !arg.startsWith('--'));
const configPath = resolve(process.cwd(), configArg || 'wrangler.toml');
const originalConfig = await readFile(configPath, 'utf8');
const config = allowPlaceholder
  ? originalConfig.replaceAll('REPLACE_WITH_KV_NAMESPACE_ID', '0123456789abcdef0123456789abcdef')
  : originalConfig;
const errors = [];

if (!/^main\s*=\s*"_worker\.js"$/m.test(config)) {
  errors.push('main 必须指向单文件入口 "_worker.js"');
}

if (!/^compatibility_date\s*=\s*"\d{4}-\d{2}-\d{2}"$/m.test(config)) {
  errors.push('缺少有效的 compatibility_date');
}

if (/REPLACE_WITH_[A-Z0-9_]+/.test(config)) {
  errors.push('wrangler.toml 仍包含 REPLACE_WITH_* 占位符');
}

const kvBlock = config.match(/\[\[kv_namespaces\]\][\s\S]*?(?=\n\[\[|\s*$)/)?.[0] || '';
const kvBinding = kvBlock.match(/^binding\s*=\s*"([^"]+)"$/m)?.[1];
const kvId = kvBlock.match(/^id\s*=\s*"([^"]+)"$/m)?.[1];
if (kvBinding !== 'NODE_KV') {
  errors.push('KV binding 必须为 NODE_KV');
}
if (!/^[0-9a-f]{32}$/i.test(kvId || '')) {
  errors.push('NODE_KV 的 namespace id 必须是 32 位十六进制字符串');
}

const doBlock = config.match(/\[\[durable_objects\.bindings\]\][\s\S]*?(?=\n\[\[|\s*$)/)?.[0] || '';
if (!/^name\s*=\s*"AUTH"$/m.test(doBlock)) {
  errors.push('Durable Object binding 必须命名为 AUTH');
}
if (!/^class_name\s*=\s*"AuthDurableObject"$/m.test(doBlock)) {
  errors.push('AUTH binding 必须指向 AuthDurableObject');
}
if (!/\[\[migrations\]\][\s\S]*?new_sqlite_classes\s*=\s*\[[^\]]*"AuthDurableObject"[^\]]*\]/.test(config)) {
  errors.push('缺少 AuthDurableObject 的 new_sqlite_classes 迁移');
}
if (/\[\[ratelimits\]\]/.test(config)) {
  errors.push('旧版 [[ratelimits]] 配置仍存在；登录限流已迁移到 Durable Object');
}

if (errors.length > 0) {
  console.error('部署配置检查失败：');
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log(allowPlaceholder ? '部署配置结构检查通过（CI 模式，允许 KV 占位符）。' : '部署配置检查通过。');
}
