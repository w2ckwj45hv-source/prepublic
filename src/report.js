// Turns scan findings into the text report.
const SECTIONS = [
  ['secret', 'Secrets', 'Treat every one as leaked: revoke it and create a new one. Removing it from the files is not enough.'],
  ['file', 'Sensitive files', 'These were committed at some point. A deleted file is still in the history.'],
  ['identity', 'Email addresses in commits', 'Every commit carries these, and they become public with the history. GitHub offers a noreply address for this.'],
  ['path', 'Home directory paths', 'They reveal the account name of whoever wrote the code.'],
  ['term', 'Your own terms', 'Text you asked to look for.'],
  ['large', 'Large files', 'Data dumps and binaries make the repository heavy and are often not meant to be shared.'],
  ['workflow', 'Risky workflows', 'Check these before strangers can open pull requests.'],
  ['hygiene', 'Before visitors arrive', ''],
];
const MARK = { blocker: 'BLOCKER', warn: 'warning', info: 'note' };
const MAX_IDENTITIES = 10;

export function summarize(result) {
  const count = s => result.findings.filter(f => f.severity === s).length;
  const historyOnly = result.findings.filter(f => f.inHead === false && f.severity !== 'info').length;
  const current = result.findings.filter(f => f.inHead === true && f.kind !== 'identity' && f.severity !== 'info').length;
  return { blockers: count('blocker'), warnings: count('warn'), notes: count('info'), historyOnly, current };
}

export function render(result) {
  const s = summarize(result), out = [];
  const n = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
  out.push(`Scanned ${n(result.commits, 'commit')} and ${n(result.files, 'file path')} across all branches and tags.`, '');
  if (!result.findings.length) {
    out.push('Nothing found. That is not proof: the secret rules cover common key formats only.');
    return out.join('\n');
  }
  for (const [kind, title, why] of SECTIONS) {
    const items = result.findings.filter(f => f.kind === kind);
    if (!items.length) continue;
    out.push(`${title} (${items.length})`);
    if (why) out.push(`  ${why}`);
    // A repository with many contributors would otherwise bury everything else.
    const shown = kind === 'identity' ? items.slice(0, MAX_IDENTITIES) : items;
    for (const f of shown) {
      const where = f.inHead === undefined || kind === 'identity' ? '' : f.inHead ? '  [still in current files]' : '  [only in history]';
      out.push(`  ${MARK[f.severity].padEnd(8)} ${f.title}${where}`, `           ${f.detail}`);
    }
    if (shown.length < items.length) out.push(`  ... and ${items.length - shown.length} more (use --json for all)`);
    out.push('');
  }
  out.push(`${n(s.blockers, 'blocker')}, ${n(s.warnings, 'warning')}, ${n(s.notes, 'note')}.`);
  if (s.blockers + s.warnings) {
    out.push('', 'What to do:');
    const one = c => c === 1;
    if (s.historyOnly) out.push(`  - ${n(s.historyOnly, 'finding')} ${one(s.historyOnly) ? 'exists' : 'exist'} only in old commits. Publishing a fresh copy without history removes ${one(s.historyOnly) ? 'it' : 'them'}:  prepublic --snapshot <new-folder>`);
    if (s.current) out.push(`  - ${n(s.current, 'finding')} ${one(s.current) ? 'is' : 'are'} in the current files. Edit or remove ${one(s.current) ? 'it' : 'those'} first, then commit.`);
    if (result.findings.some(f => f.kind === 'identity')) out.push('  - A fresh copy also drops the old commit emails. Set a noreply address before the first commit in it.');
    if (result.findings.some(f => f.kind === 'secret')) out.push('  - Revoke every secret listed above, whether or not you publish the history.');
  }
  return out.join('\n');
}
