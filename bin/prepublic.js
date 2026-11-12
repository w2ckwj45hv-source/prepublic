#!/usr/bin/env node
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { render, summarize } from '../src/report.js';
import { scan, snapshot } from '../src/scan.js';

const HELP = `prepublic - check a git repository before you make it public

Usage:  prepublic [path] [options]

Scans every commit on every branch and tag for secrets, sensitive files,
commit email addresses, home directory paths, large files and your own terms.
It only reads. Nothing is changed, uploaded or sent anywhere.

  -t, --term <text>      also look for this text, e.g. your name, employer or
                         a client's name (repeatable, case-insensitive)
      --min-size <MB>    report files at least this large (default 5)
      --snapshot <dir>   write the current files to a new folder without history
      --json             machine-readable output
  -h, --help             show this help

Exit code: 0 clean, 1 warnings or blockers found, 2 error.`;

async function main() {
  const { values: o, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      term: { type: 'string', short: 't', multiple: true },
      'min-size': { type: 'string' },
      snapshot: { type: 'string' },
      json: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (o.help) { console.log(HELP); return 0; }
  if (positionals.length > 1) throw new Error('Give one repository path at most.');
  const cwd = resolve(positionals[0] ?? '.');
  const mb = o['min-size'] === undefined ? 5 : Number(o['min-size']);
  if (!(mb > 0)) throw new Error('--min-size needs a positive number.');

  // Progress only on a real terminal, so piped output stays clean.
  const tty = process.stderr.isTTY && !o.json;
  const onProgress = tty ? n => process.stderr.write(`\r${n} commits ...`) : undefined;
  const result = await scan(cwd, { terms: o.term ?? [], minBlob: mb * 1024 * 1024, onProgress });
  if (tty) process.stderr.write('\r                    \r');

  if (o.json) console.log(JSON.stringify({ ...result, summary: summarize(result) }, null, 2));
  else console.log(render(result));

  if (o.snapshot) {
    const dir = resolve(o.snapshot);
    snapshot(cwd, dir);
    const left = result.findings.filter(f => f.inHead && f.kind !== 'identity' && f.severity !== 'info');
    console.error(`\nFresh copy without history written to ${dir}`);
    if (left.length) console.error(`Findings in the current files (${left.length}) are in the copy too. Fix them there before publishing.`);
    console.error('Next: cd into it, run "git init", set your noreply email, commit, then run prepublic again on the copy.');
  }
  const s = summarize(result);
  return s.blockers + s.warnings ? 1 : 0;
}

main().then(code => { process.exitCode = code; }, e => { console.error(`prepublic: ${e.message}`); process.exitCode = 2; });
