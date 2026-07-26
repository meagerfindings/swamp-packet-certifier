# @mgreten/packet-certifier

`@mgreten/packet-certifier` creates durable, structured evidence that a bounded
implementation packet changed only approved files in a Git worktree. It resolves
and records the base commit, handles tracked and untracked filenames safely,
rejects symlink escapes and binary changes, tracks symlink retargeting, enforces
file and line budgets, protects ignored runtime trees with before/after hashes,
and can evaluate a deterministic `git diff --check`-compatible policy internally
without persisting source text. It is designed for attended agent workflows that
need stronger evidence than a process exit code or an agent's self-report.

This extension is a certification boundary, not an OS sandbox or an atomic
filesystem snapshot. Stop implementation processes and watchers before
certification. Use a fail-closed sandbox for unattended or untrusted execution.

## Installation

```bash
swamp extension pull @mgreten/packet-certifier
```

## Setup

Create one persistent model in the repository whose worktrees will be certified.
The default policy permits no application-owned ignored files. Explicitly allow
every ignored runtime path the implementation may coexist with; allowed contents
are still hashed and must remain unchanged between snapshot and certification.
Swamp-owned `.swamp/` state is excluded because each method invocation
necessarily writes there.

```bash
swamp model create @mgreten/packet-certifier packet-certifier
```

Add other generated ignored paths only when they are necessary for your
toolchain. Prefixes must be repository-relative and end in `/`.

```yaml
globalArguments:
  allowedIgnoredPaths:
    - .tool/package.json
  allowedIgnoredPathPrefixes:
    - .tool/cache/
  excludedIgnoredPathPrefixes:
    - .tool/node_modules/
```

`excludedIgnoredPathPrefixes` is a deliberately weaker escape hatch for large,
reproducible runtime trees that cannot fit within the bounded inventory.
Excluded prefixes are pruned before ignored-file and final-tree enumeration, so
their contents are neither inspected nor hashed. Each prefix must identify a
Git-ignored, untracked directory with no symlink in its path, spelled exactly as
it appears on disk. Because pruning compares bytes while the filesystem may
resolve case and Unicode form, a prefix that differs from the real directory's
name is rejected rather than silently excluding nothing. Prefixes must not
overlap one another. The exact exclusion policy is bound into the pre-invocation
snapshot and recorded in certification evidence; changing it between snapshot
and certification fails closed. Prefer `allowedIgnoredPathPrefixes` whenever the
tree fits the limits.

An excluded prefix is the only supported way to carry an ignored tree Git
refuses to enumerate, such as a directory holding nested repositories or agent
worktrees. Git reports each of those as one opaque entry, so their contents can
be pruned but never inspected. Those entries do not count toward the packet path
limit, so an excluded tree may hold more nested repositories than a packet may
change files. An unenumerable ignored directory outside every excluded prefix is
rejected rather than skipped.

## Usage

First snapshot ignored runtime state immediately before invoking the
implementation agent. The returned resource name is a deterministic digest of
the packet and invocation IDs; retain the returned data handle if you want to
inspect it directly:

```bash
swamp model method run packet-certifier snapshotIgnoredState \
  --input cwd=/absolute/path/to/worktree \
  --input packetId=packet-001 \
  --input invocationId=invocation-001 \
  --input baseRef=origin/main
```

After the implementation process has exited, certify with the same packet and
invocation IDs. The model reads and validates its own immutable pre-invocation
snapshot; callers cannot supply or replace snapshot hashes:

```bash
swamp model method run packet-certifier certify \
  --input cwd=/absolute/path/to/worktree \
  --input packetId=packet-001 \
  --input invocationId=invocation-001 \
  --input allowedPaths='["src/widget.ts","src/widget_test.ts"]' \
  --input maxChangedFiles=2 \
  --input maxChangedLines=160 \
  --input checks='[{"name":"diff whitespace","executable":"git","args":["diff","--check"]}]'
```

Read the persisted report using the data handle returned by `certify`, or list
the model's data to discover its digest-scoped name:

```bash
swamp data list packet-certifier
```

## Global Arguments

| Argument                      | Type       | Default | Purpose                                                                                                                                                   |
| ----------------------------- | ---------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowedIgnoredPaths`         | `string[]` | `[]`    | Exact ignored files permitted to exist. Sensitive ignored files not listed here fail certification.                                                       |
| `allowedIgnoredPathPrefixes`  | `string[]` | `[]`    | Ignored path prefixes permitted to exist. Their contents are hashed before and after implementation.                                                      |
| `excludedIgnoredPathPrefixes` | `string[]` | `[]`    | Large ignored runtime prefixes intentionally outside content inspection and hashing. Exclusions are validated, snapshot-bound, and disclosed in evidence. |

The ignored-state policy is instance-scoped by design, so that no caller can
widen what a packet may touch. Swamp injects a model's global arguments into
every method call, so these three names also appear in each method's inputs and
are accepted there; values passed per call are ignored in favour of the model
definition. Certify a repository with a different runtime layout by creating a
second model instance rather than by overriding a policy at the call site.

## Method: `snapshotIgnoredState`

Captures a SHA-256 hash over every ignored file's repository-relative path,
POSIX permission mode, and content. All symlinks and non-regular files are
rejected.

| Argument       | Type     | Required | Description                                                                        |
| -------------- | -------- | -------- | ---------------------------------------------------------------------------------- |
| `cwd`          | `string` | yes      | Absolute path to the canonical Git worktree root. Nested directories are rejected. |
| `packetId`     | `string` | yes      | Stable ID matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.                              |
| `invocationId` | `string` | yes      | Invocation ID using the same restricted format.                                    |
| `baseRef`      | `string` | no       | Git ref resolved to an immutable commit before invocation; defaults to `HEAD`.     |

The method writes an immutable packet/invocation-scoped resource with
`hashVersion`, IDs, resolved base commit, Git object format, `stateHash`,
`fileCount`, `excludedIgnoredPathPrefixes`, pseudonymous `rootBinding`, and
`capturedAt`; it does not persist the absolute root or raw base-ref name.
`rootBinding` is deterministic and may be guessable for common paths, so treat
it as pseudonymous rather than secret.

## Method: `certify`

| Argument          | Type        | Required | Default | Description                                                                                                                                                                                                                                     |
| ----------------- | ----------- | -------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cwd`             | `string`    | yes      | —       | Canonical Git worktree root.                                                                                                                                                                                                                    |
| `packetId`        | `string`    | yes      | —       | Stable identifier for the approved implementation packet; must match the snapshot.                                                                                                                                                              |
| `invocationId`    | `string`    | yes      | —       | Invocation identifier; must match the snapshot.                                                                                                                                                                                                 |
| `allowedPaths`    | `string[]`  | yes      | —       | Exact repository-relative paths the packet may change.                                                                                                                                                                                          |
| `maxChangedFiles` | `number`    | no       | `3`     | Maximum changed tracked and untracked files, up to 20.                                                                                                                                                                                          |
| `maxChangedLines` | `number`    | no       | `120`   | Maximum total added plus removed lines, up to 2,000.                                                                                                                                                                                            |
| `checks`          | check array | no       | `[]`    | At most one `git diff --check`-compatible declaration; conservatively evaluates every line in final changed files for trailing whitespace, space-before-tab indentation, blank lines at EOF, and conflict markers without trusting Git's index. |

The packet-scoped report records the resolved base object ID, packet and
invocation IDs, changed paths and counts, policy violations, ignored-state
comparison, deterministic check result, worktree-state hash, effective policy
(including excluded ignored prefixes), and final `passed` decision. It does not
retain the raw base ref, absolute root, command stderr, source bytes, or check
output.

## How It Works

The model resolves and stores the base commit and object format during the
pre-invocation snapshot. During certification it verifies reachable objects with
`git fsck`, enumerates the immutable base tree with Git plumbing, walks final
files directly with Deno, and compares bytes and permission modes without
trusting Git's worktree diff, index flags, stat cache, attributes, or moving
refs. Fatal UTF-8 decoding makes invalid UTF-8 paths fail closed. Hashes use the
versioned `packet-certifier-v7` canonical encoding with an unsigned 64-bit
length before every field.

Content comparison is confined to a candidate set so that a large repository can
be certified without reading it. The base tree supplies each blob's
authoritative size and mode, so a deletion, a resize, or a mode change is
decided without opening a file; paths Git itself reports as modified are unioned
in, but only to widen the set, never to clear a path, because the index and
`.gitattributes` are writable by the invocation under certification. Candidates
are read, verified against their base object ID, and compared byte for byte.
Every remaining tracked path is proved identical by re-deriving its blob object
ID with `git hash-object --no-filters`, which consults no index and no stat
cache and cannot be fed substituted content through a clean filter; that closes
the equal-size, equal-mode rewrite an `--assume-unchanged` entry would otherwise
hide. The aggregate byte limit therefore bounds candidate content rather than
the whole repository. Text line accounting removes common prefix and suffix
lines and conservatively counts the remaining changed region; separated edits
may therefore be over-counted but never under-counted. The optional whitespace
check is implemented internally over changed final files; its declaration
retains `git diff --check` compatibility but does not execute that command. Git
runs with a minimal environment and lazy fetching disabled;
partial-clone/promisor configuration, replacement refs, and executable content
filters are rejected, while fsmonitor/hooks/external diff/text
conversion/global/system configuration are disabled. Special files, nested
repositories, gitlinks, unsupported base objects, unmerged entries, and staged
state are rejected.

A tracked symlink is compared rather than refused, because a repository that
merely contains one is not an attack. A symlink's content is the target path
read with `readLink`, so an unchanged symlink certifies while an added, removed,
or retargeted one is reported as a change; nothing is ever read through the
link, and a symlink is never descended into or hashed as file content. The entry
kind is part of the hashed representation, so a regular file and a symlink whose
bytes coincide cannot be conflated. Ignored-state protection continues to refuse
symlinks outright. Tracked file permissions are normalized to Git's
executable-bit-only `100644`/`100755` model; ignored-file evidence continues to
hash all POSIX permission bits.

Each file is limited to 10 MiB, aggregate inspected state to 50 MiB, Git output
to 4 MiB, packet/ignored inventories to 1,000 paths, repository inventories to
10,000 paths, and commands to 30 seconds. Repository inventory limits are
separate from the number of paths a packet may change. Disallowed ignored paths
are reported before their contents are read. The published targets are Apple
Silicon macOS and x86-64 Linux with Git 2.37+ and Deno; Windows is not currently
supported or claimed.

Ignored files require a separate policy because Git does not retain their
previous content. The snapshot method hashes the bounded application-owned
ignored state before implementation. Certification hashes it twice afterward,
requires both hashes to agree, compares them with the snapshot, and rejects
ignored paths outside the configured policy. Allowed ignored trees are therefore
permitted to exist but not silently mutate. Explicitly excluded ignored prefixes
are outside both ignored-state hashing and final-tree inspection; they are
intended only for reproducible runtime dependencies and are named in both
snapshot and report evidence. Files under `.swamp/` are also outside this
comparison because Swamp writes model outputs and evidence there during both
methods; protect that operational directory with normal host permissions and
Swamp's own data controls.

## Security Boundaries

- Run only after the implementation process and its children have exited.
- Do not treat `passed: true` as a substitute for sandboxing, tests, code
  review, or human approval.
- Record certification evidence immediately; later filesystem mutations are
  outside the report.
- Keep `allowedIgnoredPaths` and `allowedIgnoredPathPrefixes` narrow. Broad
  prefixes increase the amount of runtime state that must be hashed and
  reviewed.
- Use `excludedIgnoredPathPrefixes` only for large reproducible runtime trees.
  Their contents are outside certification, so never exclude source,
  configuration, credentials, manifests, or other application-owned state.
- Treat `.swamp/` as trusted certification infrastructure. Its contents are
  excluded from worktree and ignored-state comparisons so that Swamp can persist
  method outputs.
- Persisted reports omit command output to reduce the chance of retaining source
  code or secrets.
- Evidence uses a 30-day lifetime with 20-item garbage collection. This is
  operational evidence, not permanent audit retention; export it into an
  appropriate audit system if longer retention is required.

## License

MIT — see LICENSE.txt for details.
