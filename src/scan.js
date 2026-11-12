// Scans a git repository's whole history for things that become public the
// moment the repository does. Read-only: it only runs git read commands.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const run = (cwd, args, input) =>
  execFileSync('git', args, { cwd, input, encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['pipe', 'pipe', 'pipe'] });

// Specific token formats first, the generic assignment rule last.
export const SECRET_RULES = [
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI API key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['Stripe live key', /\b[sr]k_live_[A-Za-z0-9]{16,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Private key', /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----/],
];
const ASSIGNMENT = /\b(?:api[_-]?key|secret|token|passw(?:or)?d|pwd)\b["']?\s*[:=]\s*["']([^"'\s]{12,})["']/i;
const PLACEHOLDER = /^(?:your|my|example|sample|changeme|change[_-]me|placeholder|dummy|test|fake|x+$|\*+$|<|\$\{|%)|example|xxxx/i;

const SENSITIVE_FILES = [
  [/^\.env(?:\.(?!example$|sample$|template$|dist$).+)?$/i, 'environment file, usually holds keys'],
  [/\.(?:pem|key|p12|pfx|jks|keystore|kdbx)$/i, 'key or certificate store'],
  [/^id_(?:rsa|dsa|ecdsa|ed25519)$/, 'SSH private key'],
  [/^(?:\.netrc|credentials(?:\.json)?|secrets?\.(?:json|ya?ml|toml))$/i, 'credentials file'],
  // The two below are often harmless, so they only warn.
  [/^(?:\.npmrc|\.pypirc)$/i, 'may hold a registry token'],
  [/\.(?:sqlite3?|db|sql|dump|bak)$/i, 'may hold real data (database or dump)'],
];

// Absolute home-directory paths leak the account name of whoever wrote the code.
const HOME_PATH = /(?:[A-Za-z]:[\\/]{1,2}Users[\\/]{1,2}|\/(?:Users|home)\/)([A-Za-z0-9._-]{2,})/g;
const GENERIC_USERS = new Set(['user', 'username', 'you', 'me', 'name', 'your-name', 'yourname', 'runner', 'runneradmin',
  'ubuntu', 'root', 'vscode', 'node', 'app', 'public', 'default', 'shared', 'admin', 'administrator', 'dev', 'git', 'www']);

const NOREPLY = /@users\.noreply\.github\.com$|^noreply@|\[bot\]@/i;

export const mask = v => (v.length <= 8 ? '****' : `${v.slice(0, 4)}…(${v.length} chars)`);

// Everything one added line can give away. Pure, so it is easy to test.
export function checkLine(line, terms = []) {
  const hits = [];
  for (const [label, re] of SECRET_RULES) {
    const m = re.exec(line);
    if (m) { hits.push({ type: 'secret', label, raw: m[0] }); break; }
  }
  if (!hits.length) {
    const m = ASSIGNMENT.exec(line);
    if (m && !PLACEHOLDER.test(m[1]) && /[A-Za-z]/.test(m[1]) && /\d/.test(m[1])) {
      hits.push({ type: 'secret', label: 'Hard-coded credential', raw: m[1] });
    }
  }
  for (const m of line.matchAll(HOME_PATH)) {
    if (!GENERIC_USERS.has(m[1].toLowerCase())) hits.push({ type: 'path', label: `Home directory of "${m[1]}"`, raw: m[0] });
  }
  const lower = line.toLowerCase();
  for (const t of terms) if (lower.includes(t)) hits.push({ type: 'term', label: `Your term "${t}"`, raw: t });
  return hits;
}

export function sensitiveFile(path) {
  const base = path.slice(path.lastIndexOf('/') + 1);
  for (const [re, why] of SENSITIVE_FILES) if (re.test(base)) return why;
  return null;
}

// One pass over `git log -p` for every branch and tag.
function walkHistory(cwd, terms, onProgress) {
  return new Promise((resolve, reject) => {
    const identities = new Map(), files = new Map(), found = new Map();
    let commits = 0, commit = '', file = '', stderr = '';
    const note = (hit, where) => {
      const key = `${hit.type}\0${hit.raw}`;
      const f = found.get(key);
      if (f) { f.count++; f.commit = commit; f.file = where; } // log runs newest first, so this ends on the oldest
      else found.set(key, { ...hit, count: 1, commit, file: where, newestCommit: commit });
    };
    const proc = spawn('git', ['log', '--all', '--no-color', '-p', '-U0', '--no-ext-diff', '--no-textconv',
      '--format=%x01%H%x02%an%x02%ae%x02%cn%x02%ce%x02%s'], { cwd });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('error', reject);
    const lines = createInterface({ input: proc.stdout, crlfDelay: Infinity });
    lines.on('line', line => {
      if (line[0] === '\x01') {
        const [hash, an, ae, cn, ce, subject = ''] = line.slice(1).split('\x02');
        commit = hash; file = '';
        if (++commits % 500 === 0) onProgress?.(commits);
        for (const [name, email] of [[an, ae], [cn, ce]]) {
          const id = identities.get(email) ?? { email, names: new Set(), commits: 0 };
          id.names.add(name); id.commits++; identities.set(email, id);
        }
        // shortcut: only the subject line of a commit message is checked for
        // your terms, add %b to the format if bodies matter.
        for (const hit of checkLine(subject, terms)) note(hit, '(commit message)');
      } else if (line.startsWith('diff --git ')) {
        const at = line.lastIndexOf(' b/');
        file = at < 0 ? '' : line.slice(at + 3);
        if (file) files.set(file, commit);
      } else if (line[0] === '+' && !line.startsWith('+++') && line.length < 4000) {
        for (const hit of checkLine(line, terms)) note(hit, file);
      }
    });
    proc.on('close', code => {
      if (code !== 0) return reject(new Error(stderr.trim().split('\n').pop() || `git log exited with ${code}`));
      resolve({ identities, files, found, commits });
    });
  });
}

function largeBlobs(cwd, minBytes) {
  const objects = run(cwd, ['rev-list', '--objects', '--all']);
  if (!objects.trim()) return [];
  const sized = run(cwd, ['cat-file', '--batch-check=%(objecttype) %(objectsize) %(rest)'], objects);
  const seen = new Map();
  for (const line of sized.split('\n')) {
    const m = /^blob (\d+) (.+)$/.exec(line);
    if (m && Number(m[1]) >= minBytes) seen.set(m[2], Math.max(Number(m[1]), seen.get(m[2]) ?? 0));
  }
  return [...seen].map(([path, bytes]) => ({ path, bytes })).sort((a, b) => b.bytes - a.bytes);
}

function inHead(cwd, literal) {
  try { run(cwd, ['grep', '-q', '-I', '-F', '-e', literal, 'HEAD']); return true; } catch { return false; }
}

export async function scan(cwd, { terms = [], minBlob = 5 * 1024 * 1024, onProgress } = {}) {
  try { run(cwd, ['rev-parse', '--git-dir']); } catch { throw new Error(`${cwd} is not a git repository.`); }
  let hasHead = true;
  try { run(cwd, ['rev-parse', '--verify', '-q', 'HEAD']); } catch { hasHead = false; }
  if (!hasHead) throw new Error('This repository has no commits yet.');

  const clean = terms.map(t => t.trim().toLowerCase()).filter(t => t.length >= 3);
  const { identities, files, found, commits } = await walkHistory(cwd, clean, onProgress);
  const headFiles = new Set(run(cwd, ['ls-tree', '-r', '--name-only', '-z', 'HEAD']).split('\0').filter(Boolean));
  const findings = [];
  const add = (severity, kind, title, detail, extra = {}) => findings.push({ severity, kind, title, detail, ...extra });

  for (const f of found.values()) {
    const current = inHead(cwd, f.raw);
    const where = `${f.file} · first seen in ${f.commit.slice(0, 8)} · ${f.count}×`;
    if (f.type === 'secret') add('blocker', 'secret', `${f.label}: ${mask(f.raw)}`, where, { inHead: current });
    else add('warn', f.type, f.type === 'path' ? `${f.label}: ${f.raw}` : f.label, where, { inHead: current });
  }
  for (const [path, commit] of files) {
    const why = sensitiveFile(path);
    if (why) add(why.startsWith('may ') ? 'warn' : 'blocker', 'file', path, `${why} · added in ${commit.slice(0, 8)}`, { inHead: headFiles.has(path) });
  }
  for (const id of [...identities.values()].sort((a, b) => b.commits - a.commits)) {
    if (!NOREPLY.test(id.email)) add('warn', 'identity', id.email, `${[...id.names].join(', ')} · ${id.commits} commit entries`, { inHead: true });
  }
  for (const b of largeBlobs(cwd, minBlob)) {
    add('warn', 'large', b.path, `${(b.bytes / 1048576).toFixed(1)} MB`, { inHead: headFiles.has(b.path) });
  }

  const has = re => [...headFiles].some(p => re.test(p));
  if (!has(/^(LICEN[CS]E|COPYING|UNLICENSE)(\.\w+)?$/i)) add('info', 'hygiene', 'No license file', 'Without a license nobody may legally use the code.');
  if (!has(/^README(\.\w+)?$/i)) add('info', 'hygiene', 'No README', 'Visitors will not know what this is.');
  const wf = join(cwd, '.github', 'workflows');
  if (existsSync(wf)) {
    for (const name of readdirSync(wf).filter(n => /\.ya?ml$/.test(n))) {
      if (/^\s*pull_request_target\s*:/m.test(readFileSync(join(wf, name), 'utf8'))) {
        add('warn', 'workflow', `.github/workflows/${name}`, 'uses pull_request_target, which runs with your secrets on code from strangers', { inHead: true });
      }
    }
  }

  const order = { blocker: 0, warn: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.kind.localeCompare(b.kind));
  return { commits, files: files.size, findings };
}

// Writes the tracked files of the current commit to a new folder, without any
// history. This is the usual fix for problems that exist only in old commits.
export function snapshot(cwd, dir) {
  if (existsSync(dir) && readdirSync(dir).length) throw new Error(`${dir} already exists and is not empty.`);
  // read-tree into a temporary index so the export matches HEAD exactly, even
  // with staged changes in the real index.
  const env = { ...process.env, GIT_INDEX_FILE: join(run(cwd, ['rev-parse', '--absolute-git-dir']).trim(), 'prepublic-index') };
  execFileSync('git', ['read-tree', 'HEAD'], { cwd, env });
  try {
    execFileSync('git', ['checkout-index', '-a', '-f', `--prefix=${dir.replace(/\\/g, '/').replace(/\/?$/, '/')}`], { cwd, env });
  } finally {
    rmSync(env.GIT_INDEX_FILE, { force: true });
  }
}
