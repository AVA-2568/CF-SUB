import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

function stripTomlComments(content) {
  return content
    .split(/\r?\n/)
    .map((line) => {
      let inDouble = false;
      let inSingle = false;
      let escaped = false;
      for (let i = 0; i < line.length; i += 1) {
        const ch = line[i];
        if (inDouble) {
          if (escaped) escaped = false;
          else if (ch === '\\') escaped = true;
          else if (ch === '"') inDouble = false;
        } else if (inSingle) {
          if (ch === "'") inSingle = false;
        } else if (ch === '"') {
          inDouble = true;
        } else if (ch === "'") {
          inSingle = true;
        } else if (ch === '#') {
          return line.slice(0, i);
        }
      }
      return line;
    })
    .join('\n');
}

const args = process.argv.slice(2);
const allowPlaceholder = args.includes('--allow-placeholder');
const configArg = args.find((arg) => !arg.startsWith('--'));
const configPath = resolve(process.cwd(), configArg || 'wrangler.toml');
const originalConfig = stripTomlComments(await readFile(configPath, 'utf8'));
const config = allowPlaceholder
  ? originalConfig.replaceAll('REPLACE_WITH_KV_NAMESPACE_ID', '0123456789abcdef0123456789abcdef')
  : originalConfig;
const errors = [];

if (!/^\s*main\s*=\s*"_worker\.js"\s*$/m.test(config)) {
  errors.push('main 必须指向单文件入口 "_worker.js"');
}

if (!/^\s*compatibility_date\s*=\s*"\d{4}-\d{2}-\d{2}"\s*$/m.test(config)) {
  errors.push('缺少有效的 compatibility_date');
}

if (/REPLACE_WITH_[A-Z0-9_]+/.test(config)) {
  errors.push('wrangler.toml 仍包含 REPLACE_WITH_* 占位符');
}

const kvBlocks = [...config.matchAll(/^\s*\[\[kv_namespaces\]\][\s\S]*?(?=\n\s*\[|$(?![\s\S]))/gm)].map((m) => m[0]);
const nodeKvBlock = kvBlocks.find((block) => /^\s*binding\s*=\s*"NODE_KV"\s*$/m.test(block));
const kvId = nodeKvBlock?.match(/^\s*id\s*=\s*"([^"]+)"\s*$/m)?.[1];
if (!nodeKvBlock) {
  errors.push('KV binding 必须包含 NODE_KV');
} else if (!/^[0-9a-f]{32}$/i.test(kvId || '')) {
  errors.push('NODE_KV 的 namespace id 必须是 32 位十六进制字符串');
}

if (/^\s*\[\[(?:durable_objects\.bindings|migrations)\]\]/m.test(config)) {
  errors.push('KV-only 版本不应再配置 Durable Objects');
}

if (errors.length > 0) {
  console.error('部署配置检查失败：');
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log(allowPlaceholder ? '部署配置结构检查通过（CI 模式，允许 KV 占位符）。' : '部署配置检查通过。');
}
