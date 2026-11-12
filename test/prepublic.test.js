import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { render, summarize } from '../src/report.js';
import { checkLine, mask, scan, sensitiveFile, snapshot } from '../src/scan.js';

// Fake values in the right shape. Built from parts so this file itself stays clean.
const AWS = 'AKIA' + 'IOSFODNN7EXAMPL2';
const GH = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
const KEY_BLOCK = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----';
const PASSWORD = 'hunter2' + 'hunter2X9';
const HOME = '/home/' + 'jdoe42';

test('checkLine recognises key formats and masks nothing itself', () => {
  assert.deepEqual(checkLine(`key = "${AWS}"`).map(h => h.label), ['AWS access key']);
  assert.deepEqual(checkLine(`export GITHUB_TOKEN=${GH}`).map(h => h.label), ['GitHub token']);
  assert.equal(checkLine(KEY_BLOCK)[0].label, 'Private key');
  assert.equal(checkLine(`password: "${PASSWORD}"`)[0].label, 'Hard-coded credential');
});

test('checkLine ignores placeholders, env lookups and short values', () => {
  for (const ok of [
    'api_key = "your-api-key-here1"', 'token: "${{ secrets.TOKEN }}"', 'password = "xxxxxxxxxxxxxxxx"',
    'secret = os.environ["SECRET_NAME_123"]', 'token = "abc123"', 'api_key: "example1234567890"', 'const tokens = 12',
  ]) assert.deepEqual(checkLine(ok), [], ok);
});

test('checkLine finds home paths but not generic ones, and your own terms', () => {
  assert.equal(checkLine('open("C:\\\\Users\\\\jdoe42\\\\notes.txt")')[0].label, 'Home directory of "jdoe42"');
  assert.equal(checkLine(`cd ${HOME}/project`)[0].label, 'Home directory of "jdoe42"');
  assert.equal(checkLine('cat /Users/' + 'maria.k/notes')[0].label, 'Home directory of "maria.k"');
  assert.deepEqual(checkLine('cd /home/runner/work && ls /Users/username/x'), []);
  assert.deepEqual(checkLine('Built for ACME Corp', ['acme corp']).map(h => h.type), ['term']);
});

test('sensitiveFile knows what should never be committed', () => {
  for (const bad of ['.env', 'config/.env.production', 'deploy/id_rsa', 'cert/server.pem', 'data/app.sqlite', 'secrets.yml', '.npmrc']) assert.ok(sensitiveFile(bad), bad);
  assert.ok(sensitiveFile('.npmrc').startsWith('may '), 'often harmless, so it only warns');
  for (const fine of ['.env.example', 'src/keys.js', 'README.md', 'environment.ts', 'db/schema.rb']) assert.equal(sensitiveFile(fine), null, fine);
});

test('mask never shows more than four characters', () => {
  assert.equal(mask(AWS), 'AKIA…(20 chars)');
  assert.equal(mask('short'), '****');
});

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'prepublic-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
  const commit = (msg, email = 'real.person@company.example') =>
    git('-c', 'user.name=Real Person', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', msg);
  const write = (path, text) => { mkdirSync(join(dir, path, '..'), { recursive: true }); writeFileSync(join(dir, path), text); git('add', '-A'); };
  git('init', '-q', '-b', 'main');
  return { dir, git, commit, write };
}

test('scan finds problems in old commits and says whether they are still in the files', async () => {
  const r = repo();
  try {
    r.write('config.js', `const key = "${AWS}";\n`);
    r.write('.env', 'DB=1\n');
    r.commit('initial');
    r.write('config.js', 'const key = process.env.KEY;\n');
    execFileSync('git', ['rm', '-q', '--cached', '.env'], { cwd: r.dir });
    rmSync(join(r.dir, '.env'));
    r.commit('remove the key');
    r.write('run.sh', `cd ${HOME}/app\n`);
    r.write('big.bin', Buffer.alloc(2 * 1024 * 1024, 7));
    r.commit('script for Project Falcon', '12345+someone@users.noreply.github.com');

    const result = await scan(r.dir, { terms: ['Project Falcon'], minBlob: 1024 * 1024 });
    const by = kind => result.findings.filter(f => f.kind === kind);
    assert.equal(result.commits, 3);
    assert.deepEqual(by('secret').map(f => [f.title, f.inHead, f.severity]), [['AWS access key: AKIA…(20 chars)', false, 'blocker']]);
    assert.deepEqual(by('file').map(f => [f.title, f.inHead]), [['.env', false]]);
    assert.deepEqual(by('path').map(f => f.inHead), [true]);
    assert.deepEqual(by('identity').map(f => f.title), ['real.person@company.example']); // the noreply address is fine
    assert.deepEqual(by('term').map(f => f.detail.startsWith('(commit message)')), [true]);
    assert.deepEqual(by('large').map(f => f.title), ['big.bin']);
    assert.deepEqual(by('hygiene').map(f => f.title), ['No license file', 'No README']);
    assert.ok(!JSON.stringify(result).includes(AWS), 'the full secret must not appear in the result');

    const text = render(result);
    assert.ok(text.includes('[only in history]') && text.includes('[still in current files]'));
    assert.ok(!text.includes(AWS));
    // History only: the key, the .env file and the term in a commit message. Current: the path and the big file.
    assert.deepEqual(summarize(result), { blockers: 2, warnings: 4, notes: 2, historyOnly: 3, current: 2 });

    // The fresh copy has the current files and no history.
    const out = join(r.dir, '..', `${r.dir.split(/[\\/]/).pop()}-copy`);
    try {
      snapshot(r.dir, out);
      assert.ok(existsSync(join(out, 'run.sh')) && existsSync(join(out, 'config.js')));
      assert.ok(!existsSync(join(out, '.env')) && !existsSync(join(out, '.git')));
      assert.equal(readFileSync(join(out, 'config.js'), 'utf8').includes(AWS), false);
      assert.throws(() => snapshot(r.dir, out), /not empty/);
      assert.equal(r.git('status', '--porcelain').toString(), '', 'the real index must be untouched');
    } finally { rmSync(out, { recursive: true, force: true }); }
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});

test('scan reports a clean repository as clean and rejects non-repositories', async () => {
  const r = repo();
  try {
    r.write('README.md', '# Hi\n');
    r.write('LICENSE', 'MIT\n');
    r.commit('initial', '1+me@users.noreply.github.com');
    const result = await scan(r.dir);
    assert.deepEqual(result.findings, []);
    assert.ok(render(result).includes('Nothing found'));
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
  const plain = mkdtempSync(join(tmpdir(), 'prepublic-plain-'));
  try { await assert.rejects(scan(plain), /not a git repository/); } finally { rmSync(plain, { recursive: true, force: true }); }
});
