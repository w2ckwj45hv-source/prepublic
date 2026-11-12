# prepublic

Check a git repository before you make it public.

Flipping a repository from private to public publishes more than the files you
can see. It publishes every old commit, every file you ever deleted and the
email address on each commit. prepublic reads the whole history and tells you
what is in there.

```bash
node bin/prepublic.js path/to/repo
```

```
Scanned 18 commits and 68 file paths across all branches and tags.

Secrets (1)
  Treat every one as leaked: revoke it and create a new one. Removing it from the files is not enough.
  BLOCKER  AWS access key: AKIA…(20 chars)  [only in history]
           config.js · first seen in 2b05535b · 1×

Sensitive files (1)
  These were committed at some point. A deleted file is still in the history.
  warning  data/app.db  [still in current files]
           may hold real data (database or dump) · added in 2b05535b

Email addresses in commits (1)
  Every commit carries these, and they become public with the history. GitHub offers a noreply address for this.
  warning  jane@her-employer.example
           Jane Doe · 8 commit entries

1 blocker, 2 warnings, 0 notes.

What to do:
  - 1 finding exists only in old commits. Publishing a fresh copy without history removes it:  prepublic --snapshot <new-folder>
  - 1 finding is in the current files. Edit or remove it first, then commit.
```

## What it checks

| Check | Why it matters |
|---|---|
| **Secrets** in every added line of every commit | Keys for AWS, GitHub, Anthropic, OpenAI, Slack, Stripe and Google, private key blocks, and hard-coded passwords and tokens |
| **Sensitive files** ever committed | `.env`, key and certificate files, SSH keys, credential files, databases and dumps, even if deleted later |
| **Email addresses** on commits | Every author and committer address that is not a noreply address |
| **Home directory paths** | `C:\Users\name\…` and `/home/name/…` reveal your account name |
| **Your own terms** (`--term`) | Your name, your employer, a client, a project code name |
| **Large files** | Data dumps and binaries that were never meant to be shared |
| **`pull_request_target` workflows** | They run with your secrets on code from strangers |
| **License and README** | Missing ones are noted |

For every finding it says whether it is **still in the current files** or
**only in history**. That decides the fix: current files you edit, history you
either rewrite or leave behind.

## It only reads

prepublic runs read-only git commands on your local clone. It changes nothing,
uploads nothing and has no dependencies. Secrets are masked in all output,
including `--json`.

## Usage

Not on npm yet. Clone this repository and run it with Node 20 or newer:

```bash
git clone https://github.com/w2ckwj45hv-source/prepublic
node prepublic/bin/prepublic.js path/to/repo --term "Jane Doe" --term "ACME"
```

| Option | Meaning |
|---|---|
| `-t, --term <text>` | Also look for this text. Repeatable, case-insensitive. |
| `--min-size <MB>` | Report files at least this large. Default 5. |
| `--snapshot <dir>` | Write the files of the current commit to a new folder without history |
| `--json` | Machine-readable output |

The exit code is 0 when nothing was found, 1 when there are warnings or
blockers and 2 on an error, so it can gate a script.

## The fresh-copy route

Most problems sit in old commits. If you do not need the commit log in public,
the simplest fix is to publish a copy that starts at commit one:

```bash
node bin/prepublic.js my-repo --snapshot my-repo-public
cd my-repo-public
git init
git config user.email "ID+name@users.noreply.github.com"
git add -A && git commit -m "Initial public release"
node ../prepublic/bin/prepublic.js .
```

The last line checks the copy again. Anything it still reports is in the
current files and needs editing.

To keep the history instead, rewrite it with
[git filter-repo](https://github.com/newren/git-filter-repo). That is outside
the scope of this tool.

## Limits

- The secret rules cover common key formats and obvious assignments. A clean
  report is not proof. For a deeper secret scan, also run
  [gitleaks](https://github.com/gitleaks/gitleaks).
- Only the subject line of commit messages is searched for your terms.
- Binary files are not searched for text.
- It does not look at issues, pull requests, wikis or releases, which also
  become public.
- It cannot know which of your words are private. Use `--term` for names.

## Development

```bash
npm test
```

The tests build small throwaway repositories with planted problems.

## License

MIT
