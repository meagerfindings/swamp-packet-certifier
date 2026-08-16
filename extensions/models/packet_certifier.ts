/**
 * Fail-closed certification of bounded Git worktree changes.
 *
 * @module packet-certifier
 */
import { z } from "npm:zod@4.4.3";

const HASH_VERSION = "packet-certifier-v9";
const SHA256 = /^[0-9a-f]{64}$/;
// The packet limit: how many files one approved packet may change, and how many
// ignored files this model will hash. It is a policy ceiling on the size of a
// unit of reviewable work, so it does not move when the repository grows.
const MAX_PATHS = 1_000;
// The repository limit: how many paths may exist in the base tree, the index, or
// the worktree. It bounds retained path strings and per-entry syscalls, not
// content bytes — non-candidate content is never read into this process (it is
// hashed inside Git by `verifyUnchanged`), and candidate content stays bounded
// by MAX_FILE_BYTES and MAX_TOTAL_BYTES. At 100k paths of ~100 bytes each the
// inventories cost single-digit MiB of strings, which real monoliths need: an
// 18k-file Rails application already presents 22k filesystem entries.
const MAX_REPOSITORY_PATHS = 100_000;
// Raised from 10/50 MiB during the 2026-08-08 CompanyCam incident: candidate
// content on a live monorepo (large generated fixtures, checked-in binary
// assets) exceeded the old caps even though only a handful of files were
// actual packet candidates. The cap remains a fail-closed ceiling, not a
// removal — MAX_COMMAND_BYTES and the per-candidate read path are unchanged.
const MAX_FILE_BYTES = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_COMMAND_BYTES = 4 * 1024 * 1024;
// Raised from 30s alongside the byte ceilings above: a 60 MiB+ Git command
// (hash-object/cat-file batches, ls-tree over 22k paths) on a cold FS cache
// can outrun a 30s abort on real CompanyCam-scale monorepos. This governs the
// AbortController deadline for every `command()` invocation below, including
// the one that carries `core.commitGraph=false`.
const COMMAND_TIMEOUT_MS = 60_000;
const MAX_TOTAL_LINE_DIFF_STEPS = 20_000_000;
const IGNORED_SCOPE = "application-owned-v1";

const IdString = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
const ShortString = z.string().min(1).max(256);
const PathString = z.string().min(1).max(1_024);
const HashString = z.string().regex(SHA256);
const BinaryClaimSchema = z.object({
  path: PathString,
  sha256: HashString,
}).strict();
const Count = z.number().int().nonnegative();
const SnapshotBindingSchema = z.object({
  hashVersion: z.literal(HASH_VERSION),
  packetId: IdString,
  invocationId: IdString,
  resolvedBaseSha: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
  objectFormat: z.enum(["sha1", "sha256"]),
  rootBinding: HashString,
  fileCount: Count.max(MAX_PATHS),
  stateHash: HashString,
  ignoredScope: z.literal(IGNORED_SCOPE).optional(),
  excludedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS),
  mayVaryIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS).default([]),
}).strict();

const IgnoredSnapshotSchema = SnapshotBindingSchema.extend({
  allowedBinaryFiles: z.array(BinaryClaimSchema).max(20),
  capturedAt: z.string().datetime(),
}).strict();

const ReportSchema = z.object({
  hashVersion: z.literal(HASH_VERSION),
  packetId: IdString,
  invocationId: IdString,
  snapshotInvocationId: IdString.optional(),
  rootBinding: HashString,
  worktreeStateHash: HashString,
  ignoredState: z.object({
    expected: SnapshotBindingSchema,
    current: SnapshotBindingSchema,
    changed: z.boolean(),
    stable: z.boolean(),
  }).strict(),
  changedFiles: z.array(
    z.object({
      path: PathString,
      added: Count,
      removed: Count,
      binary: z.boolean(),
      untracked: z.boolean().optional(),
    }).strict(),
  ).max(MAX_PATHS),
  counts: z.object({
    totalFiles: Count,
    totalAdded: Count,
    totalRemoved: Count,
    untrackedCount: Count,
  }).strict(),
  pathViolations: z.array(PathString).max(MAX_PATHS),
  ignoredPathViolations: z.array(PathString).max(MAX_PATHS),
  budgetViolations: z.object({
    maxChangedFiles: z.boolean(),
    maxChangedLines: z.boolean(),
    binaryFiles: z.array(PathString).max(MAX_PATHS),
    binaryClaimViolations: z.array(PathString).max(MAX_PATHS),
  }).strict(),
  checkResults: z.array(
    z.object({
      name: ShortString,
      executable: z.literal("git"),
      exitCode: z.number().int(),
      passed: z.boolean(),
      durationMs: Count,
      outputOmitted: z.literal(true),
    }).strict(),
  ).max(1),
  resolvedBaseSha: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
  effectivePolicy: z.object({
    allowedPaths: z.array(PathString).min(1).max(MAX_PATHS),
    maxChangedFiles: z.number().int().min(1).max(25),
    maxChangedLines: z.number().int().min(1).max(2_000),
    checks: z.array(
      z.object({
        name: ShortString,
        executable: z.literal("git"),
        args: z.tuple([z.literal("diff"), z.literal("--check")]),
      }).strict(),
    ).max(1),
    allowBinary: z.literal(false),
    allowedBinaryFiles: z.array(BinaryClaimSchema).max(20),
    allowedIgnoredPaths: z.array(PathString).max(MAX_PATHS),
    allowedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS),
    excludedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS),
    mayVaryIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS),
  }).strict(),
  passed: z.boolean(),
  checkedAt: z.string().datetime(),
}).strict();

const GlobalArgsSchema = z.object({
  // Permitted to exist AND content-pinned: any content/mode/kind mutation of
  // a path matching one of these still trips `changed`. This is how an
  // operator lists ignored secrets (`.env`, `*.key`, `vertex-ai-sa.json`,
  // `tmp/local_secret.txt`, `vaults/local_encryption/`) that must stay
  // byte-identical across an attended invocation.
  allowedIgnoredPaths: z.array(PathString).max(MAX_PATHS).default([]),
  allowedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS).default([]),
  excludedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS).default([]),
  // Permitted to exist AND permitted to vary: a path matching one of these
  // prefixes is never folded into `stateHash`, so its content, appearance, or
  // disappearance cannot fail certification. For volatile, policy-approved
  // build byproducts (e.g. `log/`, `tmp/cache/`) that legitimately change
  // during the invocation being certified but carry no secret content worth
  // pinning. Distinct from `excludedIgnoredPathPrefixes`: excluded prefixes
  // are pruned at the Git listing layer and validated to exist on disk and
  // contain no tracked paths; a may-vary prefix carries neither requirement —
  // it may be empty, may not exist yet, and may coexist with a tracked
  // `.gitkeep` under the same directory (the tracked file is still covered by
  // the ordinary tracked-diff check; only the *ignored* files beneath a
  // may-vary prefix are exempt from `stateHash`).
  mayVaryIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS).default([]),
}).strict();

type ModelContext = {
  repoDir?: string;
  globalArgs?: z.infer<typeof GlobalArgsSchema>;
  writeResource: (
    spec: string,
    name: string,
    payload: unknown,
  ) => unknown | Promise<unknown>;
  readResource: (
    instanceName: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
};
type Change = {
  path: string;
  added: number;
  removed: number;
  binary: boolean;
  untracked?: boolean;
};
/**
 * What kind of thing occupies a path.
 *
 * Only these two kinds are certifiable. Everything else — FIFOs, sockets,
 * devices, gitlinks — is refused, so this type cannot silently widen.
 */
type EntryKind = "file" | "symlink";

function validateRepoPath(path: string): void {
  if (
    !path || path.length > 1_024 || path.startsWith("/") || path.includes("\0")
  ) {
    throw new Error("invalid repository-relative path");
  }
  if (
    path.split("/").some((part) => part === "." || part === ".." || part === "")
  ) {
    throw new Error("path contains a reserved or empty segment");
  }
}

function frame(parts: Uint8Array[]): Uint8Array {
  let size = 0;
  for (const part of parts) size += 8 + part.length;
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setBigUint64(offset, BigInt(part.length), false);
    offset += 8;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", data.slice().buffer),
  );
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function gitBlobObjectId(
  bytes: Uint8Array,
  format: "sha1" | "sha256",
): Promise<string> {
  const header = new TextEncoder().encode(`blob ${bytes.length}\0`);
  const object = new Uint8Array(header.length + bytes.length);
  object.set(header);
  object.set(bytes, header.length);
  const algorithm = format === "sha1" ? "SHA-1" : "SHA-256";
  const digest = new Uint8Array(await crypto.subtle.digest(algorithm, object));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function canonicalHash(parts: Uint8Array[]): Promise<string> {
  return await sha256(
    frame([new TextEncoder().encode(HASH_VERSION), ...parts]),
  );
}

async function evidenceName(
  kind: "ignored" | "report",
  packetId: string,
  invocationId: string,
): Promise<string> {
  const digest = await canonicalHash([
    new TextEncoder().encode(packetId),
    new TextEncoder().encode(invocationId),
  ]);
  return `${kind}-${digest}`;
}

async function command(
  cwd: string,
  label: string,
  args: string[],
  acceptedCodes: number[] = [0],
  literalPathspecs = true,
  stdin?: Uint8Array,
): Promise<Deno.CommandOutput> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), COMMAND_TIMEOUT_MS);
  try {
    if (stdin && stdin.length > MAX_COMMAND_BYTES) {
      throw new Error(`${label} exceeded input limit`);
    }
    const process = new Deno.Command("git", {
      args: [
        "-c",
        "core.quotePath=false",
        "-c",
        "diff.external=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        // Disabled during the 2026-08-08 incident: a stale or mid-write
        // commit-graph file on a large, actively-developed repository can
        // make ordinary rev-walk/log-adjacent Git commands (used internally
        // by ls-tree/diff plumbing) stall or read corrupt cached ancestry
        // data. Certification only ever needs exact object/tree state, which
        // core.commitGraph=false forces Git to derive without the cache.
        "core.commitGraph=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fileMode=true",
        "-c",
        "diff.ignoreSubmodules=none",
        "--no-replace-objects",
        ...args,
      ],
      cwd,
      env: {
        PATH: Deno.env.get("PATH") ?? "/usr/bin:/bin",
        TMPDIR: Deno.env.get("TMPDIR") ?? "/tmp",
        LANG: Deno.env.get("LANG") ?? "C.UTF-8",
        GIT_EXTERNAL_DIFF: "",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        ...(literalPathspecs ? { GIT_LITERAL_PATHSPECS: "1" } : {}),
        GIT_NO_REPLACE_OBJECTS: "1",
        GIT_NO_LAZY_FETCH: "1",
      },
      clearEnv: true,
      stdin: stdin ? "piped" : "null",
      stdout: "piped",
      stderr: "piped",
      signal: controller.signal,
    });
    let output: Deno.CommandOutput;
    if (stdin) {
      const child = process.spawn();
      const writer = child.stdin.getWriter();
      // Git may exit before draining a large path list — a broken pipe here is
      // not a certification failure, the exit code below is what decides.
      const written = writer.write(stdin)
        .then(() => writer.close())
        .catch(() => {});
      // The write must not be awaited before the output is collected. Git streams
      // one line of output per input line, so on a large repository it blocks
      // writing stdout long before it has drained stdin; awaiting the write first
      // deadlocks both pipes until the abort timer fires. Collecting concurrently
      // keeps stdout draining while stdin fills.
      [output] = await Promise.all([child.output(), written]);
    } else {
      output = await process.output();
    }
    if (
      output.stdout.length > MAX_COMMAND_BYTES ||
      output.stderr.length > MAX_COMMAND_BYTES
    ) {
      throw new Error(`${label} exceeded output limit`);
    }
    if (!acceptedCodes.includes(output.code)) {
      throw new Error(`${label} failed (exit ${output.code})`);
    }
    return output;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(label)) throw error;
    throw new Error(`${label} failed`);
  } finally {
    clearTimeout(timer);
  }
}

async function rejectExecutableFilters(cwd: string): Promise<void> {
  const output = await command(cwd, "git config filters", [
    "config",
    "--includes",
    "--get-regexp",
    "^filter\\..*\\.(clean|process)$",
  ], [0, 1]);
  if (output.stdout.length) {
    throw new Error("repository clean/process filters are not certifiable");
  }
}

async function rejectLazyFetchConfiguration(cwd: string): Promise<void> {
  const output = await command(cwd, "git config partial clone", [
    "config",
    "--includes",
    "--get-regexp",
    "^(extensions\\.partialClone|remote\\..*\\.(promisor|partialCloneFilter))$",
  ], [0, 1]);
  if (output.stdout.length) {
    throw new Error(
      "partial-clone and promisor repositories are not certifiable",
    );
  }
}

async function objectFormat(cwd: string): Promise<"sha1" | "sha256"> {
  const output = await command(cwd, "git object format", [
    "rev-parse",
    "--show-object-format",
  ]);
  const format = new TextDecoder().decode(output.stdout).trim();
  if (format !== "sha1" && format !== "sha256") {
    throw new Error("unsupported Git object format");
  }
  return format;
}

async function canonicalRepoRoot(requestedCwd: string): Promise<string> {
  const cwd = await Deno.realPath(requestedCwd);
  const output = await command(cwd, "git rev-parse", [
    "rev-parse",
    "--show-toplevel",
  ]);
  const root = await Deno.realPath(
    new TextDecoder("utf-8", { fatal: true }).decode(output.stdout).trim(),
  );
  if (cwd !== root) {
    throw new Error("cwd must be the canonical repository root");
  }
  return root;
}

async function rootBinding(cwd: string): Promise<string> {
  return await canonicalHash([new TextEncoder().encode(cwd)]);
}

/**
 * Split NUL-delimited Git output. `limit` bounds the entries returned; callers
 * that discard entries before retaining them pass the wider repository ceiling
 * and enforce the packet limit on what survives.
 */
function splitZ(data: Uint8Array, limit: number = MAX_PATHS): string[] {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
  const fields = text.split("\0");
  if (fields.pop() !== "") {
    throw new Error("malformed NUL-delimited Git output");
  }
  if (fields.length > limit) {
    throw new Error("inventory exceeds path limit");
  }
  return fields;
}

async function inspectRegular(
  cwd: string,
  path: string,
): Promise<{ bytes: Uint8Array; mode: number }> {
  const stat = await Deno.lstat(`${cwd}/${path}`);
  if (!stat.isFile || stat.isSymlink) {
    throw new Error(`refusing non-regular file: ${path}`);
  }
  if (stat.size > MAX_FILE_BYTES) {
    throw new Error(`file exceeds byte limit: ${path}`);
  }
  return {
    bytes: await Deno.readFile(`${cwd}/${path}`),
    mode: (stat.mode ?? 0) & 0o777,
  };
}

/**
 * Read a symlink's target as bytes, without following it.
 *
 * `readLink` returns the stored target string and performs no traversal, so an
 * absolute or `../`-bearing target is only ever compared as data. This is the
 * sole way symlink state enters the model: `inspectRegular` still refuses
 * symlinks, so no content is read *through* one, and nothing here resolves the
 * target or touches whatever it points at. A target that escapes the worktree is
 * therefore reportable without being reachable.
 *
 * The target is bounded because a symlink's `lstat` size is its target length,
 * which every filesystem caps far below MAX_FILE_BYTES; the check is kept so
 * this cannot become an unbounded read if that ever stops being true.
 */
async function readSymlinkTarget(
  cwd: string,
  path: string,
): Promise<Uint8Array> {
  const stat = await Deno.lstat(`${cwd}/${path}`);
  if (!stat.isSymlink) {
    throw new Error(`expected a symlink: ${path}`);
  }
  if (stat.size > MAX_FILE_BYTES) {
    throw new Error(`symlink target exceeds byte limit: ${path}`);
  }
  return new TextEncoder().encode(await Deno.readLink(`${cwd}/${path}`));
}

/**
 * Inspect whichever certifiable kind occupies a path.
 *
 * Callers that hash or compare worktree state go through this so a regular file
 * and a symlink are never handled by the same branch by accident. The returned
 * `mode` is meaningful only for files: Git stores no permission bits for a
 * symlink, so it is reported as 0 and excluded from comparison.
 */
async function inspectEntry(
  cwd: string,
  path: string,
  kind: EntryKind,
): Promise<{ bytes: Uint8Array; mode: number }> {
  if (kind === "symlink") {
    return { bytes: await readSymlinkTarget(cwd, path), mode: 0 };
  }
  return await inspectRegular(cwd, path);
}

/**
 * Report whether any tracked path matches a pathspec.
 *
 * The question is existence, so the inventory is bounded by the repository
 * ceiling rather than the packet limit. Using the packet limit here would turn a
 * monolith that tracks more than MAX_PATHS files under the queried prefix into a
 * misleading "inventory exceeds path limit" instead of the specific violation the
 * caller is testing for — a scale property must not be reported as a policy one.
 */
async function tracksAnyPath(
  cwd: string,
  label: string,
  pathspec: string,
): Promise<boolean> {
  const output = await command(cwd, label, [
    "ls-files",
    "-z",
    "--",
    pathspec,
  ]);
  return splitZ(output.stdout, MAX_REPOSITORY_PATHS).length > 0;
}

/**
 * Enumerate paths without validating them, for callers that discard entries
 * before retaining them. Such a caller must apply `validateRepoPath` to every
 * path it keeps and bound the retained set itself.
 */
async function listRaw(
  cwd: string,
  args: string[],
  label: string,
  literalPathspecs: boolean,
  limit: number,
): Promise<string[]> {
  return splitZ(
    (await command(cwd, label, args, [0], literalPathspecs)).stdout,
    limit,
  );
}

async function topLevelPathspecs(
  cwd: string,
  excludeRuntimeSwamp: boolean,
): Promise<string[]> {
  const paths: string[] = [];
  for await (const entry of Deno.readDir(cwd)) {
    if (
      entry.name === ".git" ||
      (excludeRuntimeSwamp && entry.name === ".swamp" && entry.isDirectory)
    ) continue;
    validateRepoPath(entry.name);
    paths.push(entry.name);
    // How many entries sit at a repository's root is a property of the repository,
    // not of the packet under review, so this is bounded by the repository
    // ceiling. These become pathspecs on one Git invocation, which the command
    // input limit bounds independently.
    if (paths.length > MAX_REPOSITORY_PATHS) {
      throw new Error("top-level inventory exceeds path limit");
    }
  }
  return paths;
}

async function listIgnoredPaths(
  cwd: string,
  excludeRuntimeSwamp: boolean,
  excludedPrefixes: string[],
): Promise<string[]> {
  const pathspecs = await topLevelPathspecs(cwd, excludeRuntimeSwamp);
  if (!pathspecs.length) return [];
  // Exclusion is applied twice, deliberately. The :(exclude) pathspec prunes
  // the common case cheaply, inside Git. It is not sufficient on its own: Git
  // reports an ignored directory it will not descend into — notably a nested
  // repository — as one opaque entry with a trailing slash, and no pathspec
  // excluding a path inside that directory matches it. Those entries reach the
  // filter below, so both layers are required.
  //
  // The raw list is therefore bounded by the repository ceiling rather than the
  // packet limit: one entry per unenumerable directory can survive the
  // pathspec, and capping the raw list would fail a legitimately excluded tree
  // of many nested repositories. MAX_PATHS is enforced on the retained set.
  const raw = await listRaw(
    cwd,
    [
      "ls-files",
      "--others",
      "--ignored",
      "--exclude-standard",
      "-z",
      "--",
      ...pathspecs.map((path) => `:(literal)${path}`),
      ...excludedPrefixes.map((prefix) =>
        `:(exclude,literal)${prefix.slice(0, -1)}`
      ),
    ],
    "git ls-files ignored",
    false,
    MAX_REPOSITORY_PATHS,
  );
  const paths: string[] = [];
  for (const path of raw) {
    if (excludedPrefixes.some((prefix) => path.startsWith(prefix))) continue;
    // A trailing slash marks a directory Git declined to enumerate. Only an
    // excluded prefix may legitimately hide such a tree; anything else is
    // unbounded state this model must not silently ignore.
    if (path.endsWith("/")) {
      throw new Error(`refusing unenumerable ignored directory: ${path}`);
    }
    validateRepoPath(path);
    paths.push(path);
    if (paths.length > MAX_PATHS) {
      throw new Error("inventory exceeds path limit");
    }
  }
  return paths;
}

async function excludesRuntimeSwamp(
  cwd: string,
  context: ModelContext,
): Promise<boolean> {
  if (!context.repoDir || await canonicalRepoRoot(context.repoDir) !== cwd) {
    return false;
  }
  try {
    const stat = await Deno.lstat(`${cwd}/.swamp`);
    if (!stat.isDirectory || stat.isSymlink) {
      throw new Error("repository .swamp path must be a regular directory");
    }
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
  if (await tracksAnyPath(cwd, "git ls-files .swamp", ".swamp")) {
    throw new Error(
      "tracked .swamp paths cannot be certification infrastructure",
    );
  }
  const ignored = await command(
    cwd,
    "git check-ignore .swamp",
    ["check-ignore", "-q", "--", ".swamp"],
    [0, 1],
    false,
  );
  if (ignored.code !== 0) {
    throw new Error("repository .swamp directory must be ignored by Git");
  }
  return true;
}

async function validateExcludedIgnoredPrefixes(
  cwd: string,
  prefixes: string[],
): Promise<void> {
  for (const prefix of prefixes) {
    const root = prefix.slice(0, -1);
    const segments = root.split("/");
    for (let i = 1; i <= segments.length; i++) {
      const ancestor = segments.slice(0, i).join("/");
      try {
        const stat = await Deno.lstat(`${cwd}/${ancestor}`);
        if (stat.isSymlink) {
          throw new Error(
            `excluded ignored prefix crosses symlink: ${ancestor}`,
          );
        }
        if (i === segments.length && !stat.isDirectory) {
          throw new Error(
            `excluded ignored prefix is not a directory: ${root}`,
          );
        }
      } catch (error) {
        if (error instanceof Deno.errors.NotFound) {
          throw new Error(`excluded ignored prefix does not exist: ${root}`);
        }
        throw error;
      }
      // lstat resolves case-insensitively on APFS/HFS+ and normalizes Unicode,
      // so a prefix that differs from the real directory's bytes would pass
      // every check above and then silently exclude nothing. Pruning compares
      // bytes, so require the declared spelling to be the on-disk spelling.
      const parent = segments.slice(0, i - 1).join("/");
      const name = segments[i - 1];
      let found = false;
      for await (const entry of Deno.readDir(`${cwd}/${parent}`)) {
        if (entry.name === name) {
          found = true;
          break;
        }
      }
      if (!found) {
        throw new Error(
          `excluded ignored prefix does not match the on-disk name: ${ancestor}`,
        );
      }
    }
    if (
      await tracksAnyPath(
        cwd,
        "git ls-files excluded ignored prefix",
        root,
      )
    ) {
      throw new Error(
        `excluded ignored prefix contains tracked paths: ${root}`,
      );
    }
    const ignored = await command(
      cwd,
      "git check-ignore excluded prefix",
      ["check-ignore", "-q", "--no-index", "--", root],
      [0, 1],
      false,
    );
    if (ignored.code !== 0) {
      throw new Error(`excluded ignored prefix is not ignored by Git: ${root}`);
    }
  }
}

/**
 * Whether an ignored path is permitted to exist at all — allow-listed
 * (content-pinned) or may-vary (content-exempt). Both are "not a policy
 * violation"; `ignoredMayVary` distinguishes which of the two once that
 * question matters (whether the path's content is folded into `stateHash`).
 */
function ignoredAllowed(
  path: string,
  exact: Set<string>,
  prefixes: string[],
): boolean {
  return exact.has(path) || prefixes.some((prefix) => path.startsWith(prefix));
}

/**
 * Whether an ignored path falls under a may-vary prefix: permitted to exist
 * AND permitted to change content, because it is exempt from `stateHash`
 * entirely (see `ignoredSnapshot`'s `paths` argument — callers filter these
 * out before hashing, they never reach this function's caller-side use as a
 * hash-population filter). Kept separate from `ignoredAllowed` so a strict
 * allow-listed secret and a may-vary log/cache path are never conflated.
 */
function ignoredMayVary(path: string, mayVaryPrefixes: string[]): boolean {
  return mayVaryPrefixes.some((prefix) => path.startsWith(prefix));
}

/**
 * Fold ignored-path state into `stateHash`.
 *
 * `paths` is the ALREADY-FILTERED population the caller wants bound into the
 * comparable snapshot: it must exclude any may-vary path before calling this,
 * so a may-vary path's content (or its appearance/disappearance) never enters
 * `stateHash` and can never fail the `changed`/`stable` comparison. An
 * allow-listed path is NOT filtered out here — it stays content-pinned, which
 * is the point of the allow-list category (e.g. secrets: `.env`, `*.key`,
 * `vertex-ai-sa.json`) as distinct from the may-vary category (e.g. an
 * `rspec` run legitimately writing to a may-vary `log/test.log` mid-build).
 */
async function ignoredSnapshot(
  cwd: string,
  paths: string[],
  excludedPrefixes: string[],
  mayVaryPrefixes: string[],
  packetId: string,
  invocationId: string,
  resolvedBaseSha: string,
  format: "sha1" | "sha256",
): Promise<z.infer<typeof SnapshotBindingSchema>> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (const path of paths.toSorted()) {
    // An ignored path may be a symlink; its target is compared as data and never
    // followed. The kind joins the frame for the same anti-collision reason as in
    // worktreeHash, so retargeting an ignored symlink moves this digest.
    const kind = await entryKind(`${cwd}/${path}`);
    if (!kind) throw new Error(`ignored path vanished during capture: ${path}`);
    const { bytes, mode } = await inspectEntry(cwd, path, kind);
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) {
      throw new Error("ignored state exceeds aggregate byte limit");
    }
    parts.push(
      new TextEncoder().encode(path),
      new TextEncoder().encode(kind),
      new TextEncoder().encode(mode.toString(8)),
      bytes,
    );
  }
  return {
    hashVersion: HASH_VERSION,
    packetId,
    invocationId,
    resolvedBaseSha,
    objectFormat: format,
    rootBinding: await rootBinding(cwd),
    fileCount: paths.length,
    stateHash: await canonicalHash(parts),
    ignoredScope: IGNORED_SCOPE,
    excludedIgnoredPathPrefixes: excludedPrefixes,
    mayVaryIgnoredPathPrefixes: mayVaryPrefixes,
  };
}

async function resolveBase(cwd: string, baseRef: string): Promise<string> {
  const output = await command(cwd, "git rev-parse base", [
    "rev-parse",
    "--verify",
    `${baseRef}^{commit}`,
  ]);
  const sha = new TextDecoder().decode(output.stdout).trim();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(sha)) {
    throw new Error("git rev-parse base returned malformed object ID");
  }
  return sha;
}

async function requireUnstagedOnly(cwd: string): Promise<void> {
  const output = await command(cwd, "git diff cached", [
    "diff",
    "--cached",
    "--quiet",
    "--no-ext-diff",
    "--no-textconv",
    "--",
  ], [0, 1]);
  if (output.code === 1) {
    throw new Error(
      "index differs from HEAD; staged changes are not certifiable",
    );
  }
}

async function preflightIndex(cwd: string): Promise<void> {
  const output = await command(cwd, "git ls-files stage", [
    "ls-files",
    "--stage",
    "-z",
  ]);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(output.stdout);
  const records = text.split("\0");
  if (records.pop() !== "" || records.length > MAX_REPOSITORY_PATHS) {
    throw new Error("malformed or oversized index inventory");
  }
  for (const record of records) {
    const match = /^([0-7]{6}) ([0-9a-f]+) ([0-3])\t([\s\S]+)$/.exec(record);
    if (!match) throw new Error("malformed index entry");
    validateRepoPath(match[4]);
    if (match[3] !== "0") {
      throw new Error("unmerged index entries are not certifiable");
    }
    // A gitlink is a second repository's history, whose content this model
    // cannot inventory at all, so it stays refused. An indexed symlink is not
    // refused: a pre-existing tracked symlink is ordinary repository content,
    // and `collectChanges` compares its target against the base rather than
    // following it. `requireUnstagedOnly` still rejects a dirty index, so the
    // packet cannot have staged a symlink change past this point.
    if (match[1] === "160000") {
      throw new Error(`refusing indexed gitlink: ${match[4]}`);
    }
    if (
      match[1] !== "100644" && match[1] !== "100755" && match[1] !== "120000"
    ) {
      throw new Error(`refusing unsupported index entry mode: ${match[4]}`);
    }
  }
}

function countLines(bytes: Uint8Array): number {
  let count = 0;
  for (const byte of bytes) if (byte === 10) count++;
  return bytes.length && bytes.at(-1) !== 10 ? count + 1 : count;
}

type BaseEntry = {
  path: string;
  oid: string;
  mode: number;
  size: number;
  kind: EntryKind;
};
type FinalEntry = {
  path: string;
  mode: number;
  size: number;
  kind: EntryKind;
};

/**
 * Inventory the base tree, including each blob's authoritative size.
 *
 * `-l` reports the size recorded in the base tree's own blob objects, so it is
 * as immutable as the commit itself and costs no content read. That is what
 * makes it safe to compare against `lstat`: unlike the index, the stat cache,
 * or a worktree diff, nothing a certified invocation can write reaches it.
 */
async function baseTree(cwd: string, base: string): Promise<BaseEntry[]> {
  const output = await command(cwd, "git ls-tree base", [
    "ls-tree",
    "-r",
    "-l",
    "-z",
    "--full-tree",
    base,
  ]);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(output.stdout);
  const records = text.split("\0");
  if (records.pop() !== "" || records.length > MAX_REPOSITORY_PATHS) {
    throw new Error("malformed or oversized base-tree inventory");
  }
  return records.map((record) => {
    // `-l` right-pads the size column to align it, hence the loose spacing.
    // Mode 120000 is a symlink, whose blob content is its target path. It is
    // admitted so that a repository merely containing tracked symlinks stays
    // certifiable; a *change* to one is caught by comparing that blob against
    // `Deno.readLink`. A gitlink has mode 160000 and type "commit" rather than
    // "blob", so it cannot match here.
    const match =
      /^(100644|100755|120000) blob ([0-9a-f]+) +([0-9]+)\t([\s\S]+)$/
        .exec(record);
    if (!match) throw new Error("base tree contains unsupported object type");
    validateRepoPath(match[4]);
    const symlink = match[1] === "120000";
    return {
      path: match[4],
      oid: match[2],
      // Git records no permission bits for a symlink, so there is nothing to
      // compare; 0 keeps it out of the file-mode comparison entirely.
      mode: symlink ? 0 : match[1] === "100755" ? 0o755 : 0o644,
      size: Number(match[3]),
      kind: symlink ? "symlink" as const : "file" as const,
    };
  });
}

async function finalTree(
  cwd: string,
  excludeRuntimeSwamp: boolean,
  excludedPrefixes: string[],
): Promise<FinalEntry[]> {
  const pending = [cwd];
  const excludedRoots = new Set(
    excludedPrefixes.map((prefix) => prefix.slice(0, -1)),
  );
  let count = 0;
  const files: FinalEntry[] = [];
  while (pending.length) {
    const directory = pending.pop()!;
    for await (const entry of Deno.readDir(directory)) {
      if (directory === cwd && entry.name === ".git") continue;
      if (
        excludeRuntimeSwamp && directory === cwd && entry.name === ".swamp" &&
        entry.isDirectory
      ) continue;
      const path = `${directory}/${entry.name}`;
      const relative = path.slice(cwd.length + 1);
      if (excludedRoots.has(relative)) {
        if (!entry.isDirectory || entry.isSymlink) {
          throw new Error(
            `excluded ignored prefix is not a directory: ${relative}`,
          );
        }
        continue;
      }
      count++;
      if (count > MAX_REPOSITORY_PATHS) {
        throw new Error("filesystem inventory exceeds entry limit");
      }
      if (entry.name === ".git") {
        throw new Error(
          `refusing nested repository: ${relative}`,
        );
      }
      // `readDir` reports a symlink as neither file nor directory even when it
      // points at one, so this branch cannot enqueue a symlinked directory and
      // the walk can never leave the worktree. The `.git` rejection above runs
      // first, so a symlink named .git is still refused as a nested repository.
      if (entry.isDirectory && !entry.isSymlink) pending.push(path);
      else if (entry.isSymlink) {
        validateRepoPath(relative);
        // Recorded, not read. collectChanges compares the target against the
        // base blob; a symlink absent from the base surfaces as an addition.
        // `size` is left at 0 rather than the target length because nothing may
        // draw a conclusion from it: `collectChanges` treats every symlink as a
        // candidate and decides on the target bytes alone, so a stat-derived
        // size here would be an unused value that looks comparable.
        files.push({ path: relative, mode: 0, size: 0, kind: "symlink" });
      } else if (!entry.isFile) {
        throw new Error(
          `refusing non-regular file: ${relative}`,
        );
      } else {
        validateRepoPath(relative);
        const stat = await Deno.lstat(path);
        files.push({
          path: relative,
          mode: (stat.mode ?? 0) & 0o777,
          size: stat.size,
          kind: "file",
        });
      }
    }
  }
  if (files.length > MAX_REPOSITORY_PATHS) {
    throw new Error("final tree exceeds path limit");
  }
  return files;
}

function textLines(bytes: Uint8Array): string[] {
  if (!bytes.length) return [];
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const lines = text.split("\n");
  if (text.endsWith("\n")) lines.pop();
  return lines.map((line, index) =>
    index < lines.length - 1 || text.endsWith("\n") ? `${line}\n` : line
  );
}

function spendLineDiffStep(budget: { remaining: number }): void {
  if (--budget.remaining < 0) {
    throw new Error("line diff exceeds computation limit");
  }
}

function lineDelta(
  base: Uint8Array,
  final: Uint8Array,
  budget: { remaining: number },
): { added: number; removed: number } {
  const before = textLines(base);
  const after = textLines(final);
  const frontier = new Map<number, number>([[1, 0]]);

  // Myers' shortest-edit-path algorithm counts only inserted and removed
  // lines. Unlike trimming one common prefix and suffix, it does not charge
  // every unchanged line between two small, separated hunks to the packet.
  for (let distance = 0; distance <= before.length + after.length; distance++) {
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      spendLineDiffStep(budget);
      const down = frontier.get(diagonal + 1) ?? -1;
      const right = frontier.get(diagonal - 1) ?? -1;
      let x = diagonal === -distance ||
          (diagonal !== distance && right < down)
        ? down
        : right + 1;
      let y = x - diagonal;
      while (
        x < before.length && y < after.length && x >= 0 && y >= 0 &&
        before[x] === after[y]
      ) {
        spendLineDiffStep(budget);
        x++;
        y++;
      }
      frontier.set(diagonal, x);
      if (x >= before.length && y >= after.length) {
        const delta = after.length - before.length;
        return {
          added: (distance + delta) / 2,
          removed: (distance - delta) / 2,
        };
      }
    }
  }
  throw new Error("line diff did not converge");
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length &&
    left.every((byte, i) => byte === right[i]);
}

function gitMode(mode: number): number {
  return mode & 0o111 ? 0o755 : 0o644;
}

/**
 * Union the paths Git itself reports as modified against the base.
 *
 * Purely additive. Git's answer depends on the index, the stat cache, and
 * `.gitattributes` — all writable by the invocation being certified — so it can
 * never be trusted to *clear* a path. It is consulted only to widen the
 * candidate set, which costs nothing if it lies by omission.
 */
async function gitReportedChanges(
  cwd: string,
  base: string,
): Promise<Set<string>> {
  const reported = new Set<string>();
  for (
    const args of [
      [
        "diff",
        "--name-only",
        "-z",
        "--no-ext-diff",
        "--no-textconv",
        base,
        "--",
      ],
      ["diff", "--cached", "--name-only", "-z", "--no-ext-diff", base, "--"],
      ["ls-files", "--others", "--exclude-standard", "-z"],
    ]
  ) {
    const paths = await listRaw(
      cwd,
      args,
      "git reported changes",
      true,
      MAX_REPOSITORY_PATHS,
    );
    for (const path of paths) reported.add(path);
  }
  return reported;
}

/**
 * Prove that tracked files excluded from the candidate set are byte-identical
 * to the base, without their content ever entering this process.
 *
 * Size and mode equality alone would leave one hole: an equal-length, equal-mode
 * rewrite that Git also declines to report, which `--assume-unchanged` makes
 * reachable. `hash-object` closes it by re-deriving each blob's object ID from
 * worktree bytes. It reads no index and honours no stat cache, and `--no-filters`
 * stops `.gitattributes` from feeding it substituted content, so a forged match
 * would require a preimage attack on the repository's own hash. Hashing happens
 * inside Git across a single subprocess, which is why this can cover a
 * 190 MiB tree without approaching MAX_TOTAL_BYTES.
 *
 * `--stdin-paths` is strictly line-oriented with no NUL-delimited mode, so a
 * newline-bearing path cannot be expressed to it. Those are returned to the
 * caller for byte comparison rather than skipped.
 *
 * Batches are bounded by the command input limit rather than sent as one write,
 * because a repository at the path ceiling can describe more path bytes than a
 * single invocation accepts.
 *
 * Symlinks are deliberately never handed to `hash-object`, which follows them
 * and would hash the *pointed-at* content — the one read that must never happen.
 * They are returned to the caller for target comparison instead.
 */
async function verifyUnchanged(
  cwd: string,
  entries: BaseEntry[],
  format: "sha1" | "sha256",
): Promise<BaseEntry[]> {
  const hashable = entries.filter((entry) =>
    entry.kind === "file" && !entry.path.includes("\n")
  );
  const shape = format === "sha1" ? /^[0-9a-f]{40}$/ : /^[0-9a-f]{64}$/;
  const encoder = new TextEncoder();
  let batch: BaseEntry[] = [];
  let batchBytes = 0;
  const flush = async (): Promise<void> => {
    if (!batch.length) return;
    const output = await command(
      cwd,
      "git hash-object unchanged",
      ["hash-object", "--no-filters", "--stdin-paths"],
      [0],
      true,
      encoder.encode(batch.map((entry) => `${entry.path}\n`).join("")),
    );
    const oids = new TextDecoder("utf-8", { fatal: true })
      .decode(output.stdout).split("\n").filter((line) => line.length);
    if (oids.length !== batch.length) {
      throw new Error(
        "unchanged tracked inventory failed object-ID accounting",
      );
    }
    for (const [index, entry] of batch.entries()) {
      if (!shape.test(oids[index])) {
        throw new Error(
          "git hash-object unchanged returned malformed object ID",
        );
      }
      if (oids[index] !== entry.oid) {
        throw new Error(
          `tracked file differs from base without a detectable change: ${entry.path}`,
        );
      }
    }
    batch = [];
    batchBytes = 0;
  };
  for (const entry of hashable) {
    const size = encoder.encode(`${entry.path}\n`).length;
    if (batchBytes + size > MAX_COMMAND_BYTES) await flush();
    batch.push(entry);
    batchBytes += size;
  }
  await flush();
  return entries.filter((entry) =>
    entry.kind === "symlink" || entry.path.includes("\n")
  );
}

async function collectChanges(
  cwd: string,
  baseSha: string,
  base: BaseEntry[],
  final: FinalEntry[],
  ignored: Set<string>,
  format: "sha1" | "sha256",
): Promise<Change[]> {
  const changes: Change[] = [];
  const lineDiffBudget = { remaining: MAX_TOTAL_LINE_DIFF_STEPS };
  const finalByPath = new Map(final.map((entry) => [entry.path, entry]));
  const basePaths = new Set(base.map((entry) => entry.path));
  const reported = await gitReportedChanges(cwd, baseSha);
  const candidates: BaseEntry[] = [];
  const unchanged: BaseEntry[] = [];
  for (const entry of base) {
    const current = finalByPath.get(entry.path);
    // A deletion, a resize, a mode flip, or a change of entry kind is decided
    // entirely from the base tree and an lstat, so no candidate can hide behind
    // Git's bookkeeping. A symlink is always a candidate: its recorded size is
    // not its target length, so only comparing the target itself can clear it.
    if (
      !current || current.kind !== entry.kind || entry.kind === "symlink" ||
      current.size !== entry.size ||
      gitMode(current.mode) !== entry.mode || reported.has(entry.path)
    ) {
      candidates.push(entry);
    } else {
      unchanged.push(entry);
    }
  }
  candidates.push(...await verifyUnchanged(cwd, unchanged, format));
  let totalBytes = 0;
  for (const entry of candidates) {
    const current = finalByPath.get(entry.path);
    const baseBytes = (await command(cwd, "git cat-file base blob", [
      "cat-file",
      "blob",
      entry.oid,
    ])).stdout;
    if (await gitBlobObjectId(baseBytes, format) !== entry.oid) {
      throw new Error(`base blob failed object-ID verification: ${entry.path}`);
    }
    const finalFile = current
      ? await inspectEntry(cwd, entry.path, current.kind)
      : { bytes: new Uint8Array(), mode: 0 };
    totalBytes += baseBytes.length + finalFile.bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("tracked state exceeds aggregate byte limit");
    }
    // A base symlink whose target still matches is unchanged. Requiring the kind
    // to match as well means replacing a symlink with a file whose bytes happen
    // to equal the old target is a change, not a silent match.
    if (
      current && current.kind === entry.kind &&
      equalBytes(baseBytes, finalFile.bytes) &&
      (entry.kind === "symlink" || entry.mode === gitMode(finalFile.mode))
    ) {
      continue;
    }
    const binary = baseBytes.includes(0) || finalFile.bytes.includes(0);
    const delta = binary
      ? { added: 0, removed: 0 }
      : lineDelta(baseBytes, finalFile.bytes, lineDiffBudget);
    changes.push({ path: entry.path, ...delta, binary });
  }
  for (const entry of final) {
    if (basePaths.has(entry.path) || ignored.has(entry.path)) continue;
    const { bytes } = await inspectEntry(cwd, entry.path, entry.kind);
    totalBytes += bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("changed state exceeds aggregate byte limit");
    }
    const binary = bytes.includes(0);
    changes.push({
      path: entry.path,
      // A newly added symlink counts as one added line: its target. Reporting it
      // as a change is the point — an added symlink is how a packet would try to
      // introduce a path that resolves outside the worktree.
      added: binary ? 0 : entry.kind === "symlink" ? 1 : countLines(bytes),
      removed: 0,
      binary,
      untracked: true,
    });
  }
  return changes;
}

/**
 * Classify what currently occupies a path, or null if nothing does.
 *
 * `lstat` never follows the final component, so a symlink is reported as a
 * symlink rather than as whatever it points at. Callers that hold only a
 * `Change` use this to pick the right reader after the fact.
 */
async function entryKind(path: string): Promise<EntryKind | null> {
  let stat: Deno.FileInfo;
  try {
    stat = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return null;
    throw error;
  }
  if (stat.isSymlink) return "symlink";
  if (stat.isFile) return "file";
  throw new Error(`refusing non-regular file: ${path}`);
}

async function passesWhitespaceCheck(
  cwd: string,
  changes: Change[],
): Promise<boolean> {
  for (const change of changes) {
    const kind = await entryKind(`${cwd}/${change.path}`);
    // A symlink target is a path, not reviewable text; whitespace rules would be
    // meaningless against it and reading it as content is not permitted anyway.
    if (change.binary || kind !== "file") continue;
    const { bytes } = await inspectRegular(cwd, change.path);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const lines = text.split("\n");
    if (
      lines.some((line) =>
        /[ \t]+$/.test(line.endsWith("\r") ? line.slice(0, -1) : line) ||
        /^[ \t]* \t/.test(line) ||
        /^(<<<<<<<|\|\|\|\|\|\|\||=======|>>>>>>>)(?:[ \t]|\r?$)/.test(line)
      ) || /\n[ \t\r]*\n$/.test(text)
    ) return false;
  }
  return true;
}

/**
 * Bind the certified worktree state to a single digest.
 *
 * Each entry contributes its kind alongside its path, mode, and bytes. The kind
 * is load-bearing, not decorative: without it a regular file containing
 * `../../etc/passwd` and a symlink pointing at `../../etc/passwd` would frame
 * identically and produce the same digest, so one could be swapped for the other
 * under an unchanged hash. Adding it is what required HASH_VERSION v7.
 */
type WorktreeEvidence = {
  stateHash: string;
  binaryDigests: Map<string, string | null>;
};

async function captureWorktreeEvidence(
  cwd: string,
  base: string,
  changes: Change[],
): Promise<WorktreeEvidence> {
  const parts: Uint8Array[] = [];
  const binaryDigests = new Map<string, string | null>();
  let total = 0;
  for (
    const change of changes.toSorted((a, b) => a.path.localeCompare(b.path))
  ) {
    const kind = await entryKind(`${cwd}/${change.path}`);
    const inspected = kind
      ? await inspectEntry(cwd, change.path, kind)
      : { bytes: new Uint8Array(), mode: 0 };
    const { bytes, mode } = inspected;
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) {
      throw new Error(
        "worktree state exceeds aggregate byte limit",
      );
    }
    if (change.binary || bytes.includes(0)) {
      binaryDigests.set(
        change.path,
        kind === "file" ? await sha256(bytes) : null,
      );
    }
    parts.push(
      new TextEncoder().encode(change.path),
      new TextEncoder().encode(kind ?? "absent"),
      new TextEncoder().encode(mode.toString(8)),
      bytes,
    );
  }
  parts.push(new TextEncoder().encode(base));
  return {
    stateHash: await canonicalHash(parts),
    binaryDigests,
  };
}

/**
 * Resolve the ignored-state policy from the model definition.
 *
 * The policy is deliberately instance-scoped, never per-invocation: a caller
 * must not be able to widen what a packet may touch. The three policy fields
 * appear in both method argument schemas only because Swamp injects a model's
 * global arguments into every method call and those schemas are strict; values
 * passed per call are accepted and ignored in favour of the definition.
 */
function ignoredPolicy(
  context: ModelContext,
): {
  exact: Set<string>;
  prefixes: string[];
  excludedPrefixes: string[];
  mayVaryPrefixes: string[];
} {
  const exact = context.globalArgs?.allowedIgnoredPaths ?? [];
  const prefixes = context.globalArgs?.allowedIgnoredPathPrefixes ?? [];
  const excludedPrefixes = context.globalArgs?.excludedIgnoredPathPrefixes ??
    [];
  const mayVaryPrefixes = context.globalArgs?.mayVaryIgnoredPathPrefixes ?? [];
  for (const path of exact) validateRepoPath(path);
  for (const prefix of [...prefixes, ...excludedPrefixes, ...mayVaryPrefixes]) {
    if (!prefix.endsWith("/")) {
      throw new Error("ignored path prefix must end with /");
    }
    validateRepoPath(prefix.slice(0, -1));
  }
  if (excludedPrefixes.some((prefix) => prefix.startsWith(":"))) {
    throw new Error("excluded ignored path prefix cannot start with colon");
  }
  if (new Set(excludedPrefixes).size !== excludedPrefixes.length) {
    throw new Error("excluded ignored path prefixes must be unique");
  }
  if (new Set(mayVaryPrefixes).size !== mayVaryPrefixes.length) {
    throw new Error("may-vary ignored path prefixes must be unique");
  }
  for (const prefix of excludedPrefixes) {
    if (
      excludedPrefixes.some((other) =>
        other !== prefix && prefix.startsWith(other)
      )
    ) {
      throw new Error(
        `excluded ignored path prefix is already covered: ${prefix}`,
      );
    }
  }
  for (const excluded of excludedPrefixes) {
    if (
      [...exact].some((path) => path.startsWith(excluded)) ||
      prefixes.some((prefix) =>
        excluded.startsWith(prefix) || prefix.startsWith(excluded)
      )
    ) {
      throw new Error("allowed and excluded ignored path policies overlap");
    }
  }
  // A may-vary prefix may overlap an excluded prefix (excluded wins:
  // listIgnoredPaths prunes those paths before any policy category ever sees
  // them, so nothing under an excluded prefix reaches the may-vary check).
  // But a may-vary prefix must NOT overlap an allow-listed exact path or
  // prefix: may-vary exempts a path from stateHash, so an overlap would
  // silently un-pin a path the operator content-pinned on purpose (e.g. a
  // secret at config/secrets/.env exempted by a may-vary config/ prefix).
  // Content-pinning and content-exemption are contradictory intents for the
  // same path; forbid the overlap so exempting a pinned path is an explicit,
  // deliberate policy edit rather than an accident. (Redundant may-vary
  // bookkeeping — one may-vary prefix covering another — is also rejected.)
  for (const prefix of mayVaryPrefixes) {
    if (
      [...exact].some((path) => path.startsWith(prefix)) ||
      prefixes.some((allowed) =>
        prefix.startsWith(allowed) || allowed.startsWith(prefix)
      )
    ) {
      throw new Error(
        "allowed and may-vary ignored path policies overlap: a content-pinned " +
          `path cannot also be may-vary (${prefix})`,
      );
    }
    if (
      mayVaryPrefixes.some((other) =>
        other !== prefix && prefix.startsWith(other)
      )
    ) {
      throw new Error(
        `may-vary ignored path prefix is already covered: ${prefix}`,
      );
    }
  }
  return {
    exact: new Set(exact),
    prefixes,
    excludedPrefixes: excludedPrefixes.toSorted(),
    mayVaryPrefixes: mayVaryPrefixes.toSorted(),
  };
}

/** Swamp model definition. */
export const model = {
  type: "@mgreten/packet-certifier",
  version: "2026.08.16.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [{
    toVersion: "2026.07.24.3",
    description: "Add explicit excluded ignored path prefixes",
    upgradeAttributes: (old: Record<string, unknown>) => ({
      ...old,
      excludedIgnoredPathPrefixes: [],
    }),
  }, {
    toVersion: "2026.07.24.4",
    description: "Separate repository and packet inventory ceilings",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.07.24.5",
    description: "Normalize tracked permissions to Git file modes",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.07.25.1",
    description: "Prune excluded ignored trees holding nested repositories",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.07.25.2",
    description:
      "Compare only candidate tracked paths to certify large repositories",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.07.25.3",
    // Entry kind joined the hashed representation, so v6 digests are not
    // comparable to v7 ones and stored evidence cannot be carried across.
    description:
      "Certify pre-existing tracked symlinks and raise the repository ceiling",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.07.26.1",
    description: "Count minimal line edits across separated hunks",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.07.27.1",
    description:
      "Allow certification of an effective fallback invocation against the original pre-agent ignored-state snapshot",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.08.02.1",
    description:
      "Bind explicitly claimed binary SHA-256 digests into pre-invocation snapshots",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.08.08.1",
    description:
      "Raise candidate byte ceilings, extend the Git command timeout, and disable the commit-graph cache for CompanyCam-scale repositories",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }, {
    toVersion: "2026.08.14.1",
    description:
      "Add may-vary ignored-path category (stateHash-exempt) so volatile build byproducts (logs, caches) can change without failing certification, while allow-listed paths stay content-pinned",
    upgradeAttributes: (old: Record<string, unknown>) => ({
      ...old,
      mayVaryIgnoredPathPrefixes: [],
    }),
  }, {
    toVersion: "2026.08.16.1",
    description: "Raise the maximum packet file budget from 20 to 25",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }],
  resources: {
    ignoredSnapshot: {
      description: "Pre-invocation ignored-state evidence",
      schema: IgnoredSnapshotSchema,
      lifetime: "30d" as const,
      garbageCollection: 20,
    },
    certification: {
      description: "Packet certification evidence",
      schema: ReportSchema,
      lifetime: "30d" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    snapshotIgnoredState: {
      description:
        "Capture ignored state before an attended implementation invocation.",
      arguments: z.object({
        ...GlobalArgsSchema.shape,
        cwd: z.string().min(1).max(4_096),
        packetId: IdString,
        invocationId: IdString,
        baseRef: z.string().min(1).max(256).default("HEAD"),
        allowedBinaryFiles: z.array(BinaryClaimSchema).max(20).default([]),
      }).strict(),
      execute: async (
        args: Record<string, unknown>,
        context: ModelContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const cwd = await canonicalRepoRoot(args.cwd as string);
        const packetId = args.packetId as string;
        const invocationId = args.invocationId as string;
        const name = await evidenceName("ignored", packetId, invocationId);
        if (await context.readResource(name)) {
          throw new Error(
            "ignored-state snapshot already exists for invocation",
          );
        }
        await rejectExecutableFilters(cwd);
        await rejectLazyFetchConfiguration(cwd);
        const excludeRuntimeSwamp = await excludesRuntimeSwamp(cwd, context);
        const resolvedBaseSha = await resolveBase(cwd, args.baseRef as string);
        const format = await objectFormat(cwd);
        const policy = ignoredPolicy(context);
        const allowedBinaryFiles = (args.allowedBinaryFiles ?? []) as Array<
          z.infer<typeof BinaryClaimSchema>
        >;
        const claimedPaths = new Set<string>();
        for (const claim of allowedBinaryFiles) {
          validateRepoPath(claim.path);
          if (claimedPaths.has(claim.path)) {
            throw new Error(`duplicate binary claim: ${claim.path}`);
          }
          claimedPaths.add(claim.path);
        }
        await validateExcludedIgnoredPrefixes(cwd, policy.excludedPrefixes);
        const paths = await listIgnoredPaths(
          cwd,
          excludeRuntimeSwamp,
          policy.excludedPrefixes,
        );
        // Permitted to exist: allow-listed (content-pinned) OR may-vary
        // (content-exempt). Anything else is an unpermitted ignored path.
        const violation = paths.find((path) =>
          !ignoredAllowed(path, policy.exact, policy.prefixes) &&
          !ignoredMayVary(path, policy.mayVaryPrefixes)
        );
        if (violation) {
          throw new Error(
            `ignored path is not permitted by policy: ${violation}`,
          );
        }
        // May-vary paths are excluded from the population bound into
        // stateHash: they are permitted to change (or appear/disappear)
        // without affecting `changed`. Allow-listed paths remain in the
        // hashed population — they stay content-pinned.
        const hashedPaths = paths.filter((path) =>
          !ignoredMayVary(path, policy.mayVaryPrefixes)
        );
        const snapshot = IgnoredSnapshotSchema.parse({
          ...await ignoredSnapshot(
            cwd,
            hashedPaths,
            policy.excludedPrefixes,
            policy.mayVaryPrefixes,
            packetId,
            invocationId,
            resolvedBaseSha,
            format,
          ),
          allowedBinaryFiles,
          capturedAt: new Date().toISOString(),
        });
        return {
          dataHandles: [
            await context.writeResource(
              "ignoredSnapshot",
              name,
              snapshot,
            ),
          ],
        };
      },
    },
    certify: {
      description:
        "Certify an attended invocation's unstaged Git worktree changes.",
      arguments: z.object({
        ...GlobalArgsSchema.shape,
        cwd: z.string().min(1).max(4_096),
        packetId: IdString,
        invocationId: IdString,
        snapshotInvocationId: IdString.optional().describe(
          "Invocation identity of the original pre-agent ignored-state snapshot; defaults to invocationId",
        ),
        allowedPaths: z.array(PathString).min(1).max(MAX_PATHS),
        maxChangedFiles: z.number().int().min(1).max(25).default(3),
        maxChangedLines: z.number().int().min(1).max(2_000).default(120),
        checks: z.array(
          z.object({
            name: ShortString,
            executable: z.literal("git"),
            args: z.tuple([z.literal("diff"), z.literal("--check")]),
          }).strict(),
        ).max(1).default([]),
      }).strict(),
      execute: async (
        args: Record<string, unknown>,
        context: ModelContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const cwd = await canonicalRepoRoot(
          (args.cwd as string) || context.repoDir!,
        );
        const packetId = args.packetId as string;
        const invocationId = args.invocationId as string;
        const snapshotInvocationId =
          (args.snapshotInvocationId as string | undefined) ?? invocationId;
        const snapshotName = await evidenceName(
          "ignored",
          packetId,
          snapshotInvocationId,
        );
        const storedSnapshot = await context.readResource(snapshotName);
        if (!storedSnapshot) {
          throw new Error("pre-invocation ignored-state snapshot not found");
        }
        const parsedSnapshot = IgnoredSnapshotSchema.parse(storedSnapshot);
        if (
          parsedSnapshot.packetId !== packetId ||
          parsedSnapshot.invocationId !== snapshotInvocationId
        ) {
          throw new Error("pre-invocation snapshot identity mismatch");
        }
        if (!parsedSnapshot.ignoredScope) {
          throw new Error(
            "ignored-state snapshot predates application-owned scope; create a new invocation snapshot",
          );
        }
        const {
          capturedAt: _capturedAt,
          allowedBinaryFiles,
          ...expected
        } = parsedSnapshot;
        const allowedPaths = args.allowedPaths as string[];
        for (const path of allowedPaths) validateRepoPath(path);
        await rejectExecutableFilters(cwd);
        await rejectLazyFetchConfiguration(cwd);
        const excludeRuntimeSwamp = await excludesRuntimeSwamp(cwd, context);
        const policy = ignoredPolicy(context);
        if (
          JSON.stringify(expected.excludedIgnoredPathPrefixes) !==
            JSON.stringify(policy.excludedPrefixes)
        ) {
          throw new Error(
            "excluded ignored path policy differs from pre-invocation snapshot",
          );
        }
        // May-vary prefixes decide which ignored paths were excluded from the
        // snapshot's stateHash population; a policy change here would make
        // `expected` and `current` non-comparable in ways JSON equality alone
        // could not detect (e.g. a path becoming exempt would silently drop
        // out of `current` without `expected` changing to match).
        if (
          JSON.stringify(expected.mayVaryIgnoredPathPrefixes) !==
            JSON.stringify(policy.mayVaryPrefixes)
        ) {
          throw new Error(
            "may-vary ignored path policy differs from pre-invocation snapshot",
          );
        }
        await validateExcludedIgnoredPrefixes(cwd, policy.excludedPrefixes);
        const base = expected.resolvedBaseSha;
        await command(cwd, "git fsck base", [
          "fsck",
          "--strict",
          "--no-dangling",
          "--no-reflogs",
          base,
        ]);
        await preflightIndex(cwd);
        await requireUnstagedOnly(cwd);
        const baseEntries = await baseTree(cwd, base);
        const finalEntries = await finalTree(
          cwd,
          excludeRuntimeSwamp,
          policy.excludedPrefixes,
        );
        const ignoredPaths = await listIgnoredPaths(
          cwd,
          excludeRuntimeSwamp,
          policy.excludedPrefixes,
        );
        const changes = await collectChanges(
          cwd,
          base,
          baseEntries,
          finalEntries,
          new Set(ignoredPaths),
          expected.objectFormat,
        );
        // Permitted to exist: allow-listed (content-pinned) OR may-vary
        // (content-exempt); anything else is an unpermitted ignored path.
        // This is separate from, and unaffected by, the stateHash population
        // below — a may-vary path is never a violation, but it also never
        // reaches stateHash.
        const ignoredPathViolations = ignoredPaths.filter((path) =>
          !ignoredAllowed(path, policy.exact, policy.prefixes) &&
          !ignoredMayVary(path, policy.mayVaryPrefixes)
        );
        // May-vary paths are excluded from the hashed population, mirroring
        // snapshotIgnoredState: they may change or appear/disappear freely.
        const hashedPaths = ignoredPaths.filter((path) =>
          !ignoredMayVary(path, policy.mayVaryPrefixes)
        );
        // Do not read disallowed ignored files.
        const current = ignoredPathViolations.length
          ? {
            hashVersion: HASH_VERSION,
            packetId,
            invocationId: snapshotInvocationId,
            resolvedBaseSha: base,
            objectFormat: expected.objectFormat,
            rootBinding: await rootBinding(cwd),
            fileCount: hashedPaths.length,
            stateHash: await canonicalHash([]),
            ignoredScope: IGNORED_SCOPE,
            excludedIgnoredPathPrefixes: policy.excludedPrefixes,
            mayVaryIgnoredPathPrefixes: policy.mayVaryPrefixes,
          }
          : await ignoredSnapshot(
            cwd,
            hashedPaths,
            policy.excludedPrefixes,
            policy.mayVaryPrefixes,
            packetId,
            snapshotInvocationId,
            base,
            expected.objectFormat,
          );
        const second = ignoredPathViolations.length
          ? current
          : await ignoredSnapshot(
            cwd,
            hashedPaths,
            policy.excludedPrefixes,
            policy.mayVaryPrefixes,
            packetId,
            snapshotInvocationId,
            base,
            expected.objectFormat,
          );
        const stable = !ignoredPathViolations.length &&
          JSON.stringify(current) === JSON.stringify(second);
        const changed = JSON.stringify(expected) !== JSON.stringify(current);
        const allowed = new Set(allowedPaths);
        const pathViolations = changes.filter((change) =>
          !allowed.has(change.path)
        ).map((change) => change.path);
        const worktreeEvidence = await captureWorktreeEvidence(
          cwd,
          base,
          changes,
        );
        const binaryFiles = [...worktreeEvidence.binaryDigests.keys()];
        const binaryClaims = new Map(
          allowedBinaryFiles.map((claim) => [claim.path, claim.sha256]),
        );
        const changedBinaryPaths = new Set(binaryFiles);
        const binaryClaimViolations = allowedBinaryFiles
          .filter((claim) => !changedBinaryPaths.has(claim.path))
          .map((claim) => claim.path);
        for (const [path, digest] of worktreeEvidence.binaryDigests) {
          if (!digest || binaryClaims.get(path) !== digest) {
            binaryClaimViolations.push(path);
          }
        }
        binaryClaimViolations.sort();
        const totalAdded = changes.reduce(
          (sum, change) => sum + change.added,
          0,
        );
        const totalRemoved = changes.reduce(
          (sum, change) => sum + change.removed,
          0,
        );
        const checks = args.checks as Array<
          { name: string; executable: "git"; args: ["diff", "--check"] }
        >;
        const checkResults = [];
        for (const check of checks) {
          const started = Date.now();
          const checkPassed = await passesWhitespaceCheck(cwd, changes);
          checkResults.push({
            name: check.name,
            executable: "git" as const,
            exitCode: checkPassed ? 0 : 1,
            passed: checkPassed,
            durationMs: Date.now() - started,
            outputOmitted: true as const,
          });
        }
        const maxFiles = args.maxChangedFiles as number;
        const maxLines = args.maxChangedLines as number;
        const passed = !pathViolations.length &&
          !ignoredPathViolations.length && !changed && stable &&
          changes.length <= maxFiles && totalAdded + totalRemoved <= maxLines &&
          !binaryClaimViolations.length &&
          checkResults.every((result) => result.passed);
        const report = ReportSchema.parse({
          hashVersion: HASH_VERSION,
          packetId,
          invocationId,
          snapshotInvocationId,
          rootBinding: await rootBinding(cwd),
          worktreeStateHash: worktreeEvidence.stateHash,
          ignoredState: { expected, current, changed, stable },
          changedFiles: changes,
          counts: {
            totalFiles: changes.length,
            totalAdded,
            totalRemoved,
            untrackedCount: changes.filter((change) => change.untracked).length,
          },
          pathViolations,
          ignoredPathViolations,
          budgetViolations: {
            maxChangedFiles: changes.length > maxFiles,
            maxChangedLines: totalAdded + totalRemoved > maxLines,
            binaryFiles,
            binaryClaimViolations,
          },
          checkResults,
          resolvedBaseSha: base,
          effectivePolicy: {
            allowedPaths,
            maxChangedFiles: maxFiles,
            maxChangedLines: maxLines,
            checks,
            allowBinary: false as const,
            allowedBinaryFiles,
            allowedIgnoredPaths: [...policy.exact],
            allowedIgnoredPathPrefixes: policy.prefixes,
            excludedIgnoredPathPrefixes: policy.excludedPrefixes,
            mayVaryIgnoredPathPrefixes: policy.mayVaryPrefixes,
          },
          passed,
          checkedAt: new Date().toISOString(),
        });
        const reportName = await evidenceName("report", packetId, invocationId);
        return {
          dataHandles: [
            await context.writeResource(
              "certification",
              reportName,
              report,
            ),
          ],
        };
      },
    },
  },
};
