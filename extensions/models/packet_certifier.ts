/**
 * Fail-closed certification of bounded Git worktree changes.
 *
 * @module packet-certifier
 */
import { z } from "npm:zod@4.4.3";

const HASH_VERSION = "packet-certifier-v6";
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_PATHS = 1_000;
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
const MAX_COMMAND_BYTES = 4 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 30_000;
const IGNORED_SCOPE = "application-owned-v1";

const IdString = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
const ShortString = z.string().min(1).max(256);
const PathString = z.string().min(1).max(1_024);
const HashString = z.string().regex(SHA256);
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
}).strict();

const IgnoredSnapshotSchema = SnapshotBindingSchema.extend({
  capturedAt: z.string().datetime(),
}).strict();

const ReportSchema = z.object({
  hashVersion: z.literal(HASH_VERSION),
  packetId: IdString,
  invocationId: IdString,
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
    maxChangedFiles: z.number().int().min(1).max(20),
    maxChangedLines: z.number().int().min(1).max(2_000),
    checks: z.array(
      z.object({
        name: ShortString,
        executable: z.literal("git"),
        args: z.tuple([z.literal("diff"), z.literal("--check")]),
      }).strict(),
    ).max(1),
    allowBinary: z.literal(false),
    allowedIgnoredPaths: z.array(PathString).max(MAX_PATHS),
    allowedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS),
    excludedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS),
  }).strict(),
  passed: z.boolean(),
  checkedAt: z.string().datetime(),
}).strict();

const GlobalArgsSchema = z.object({
  allowedIgnoredPaths: z.array(PathString).max(MAX_PATHS).default([]),
  allowedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS).default([]),
  excludedIgnoredPathPrefixes: z.array(PathString).max(MAX_PATHS).default([]),
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
): Promise<Deno.CommandOutput> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), COMMAND_TIMEOUT_MS);
  try {
    const output = await new Deno.Command("git", {
      args: [
        "-c",
        "core.quotePath=false",
        "-c",
        "diff.external=",
        "-c",
        "core.fsmonitor=false",
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
      stdout: "piped",
      stderr: "piped",
      signal: controller.signal,
    }).output();
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

function decodeZ(data: Uint8Array): string[] {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
  const fields = text.split("\0");
  if (fields.pop() !== "") {
    throw new Error("malformed NUL-delimited Git output");
  }
  if (fields.length > MAX_PATHS) {
    throw new Error("inventory exceeds path limit");
  }
  for (const path of fields) validateRepoPath(path);
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

async function list(
  cwd: string,
  args: string[],
  label: string,
  literalPathspecs = true,
): Promise<string[]> {
  return decodeZ(
    (await command(cwd, label, args, [0], literalPathspecs)).stdout,
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
    if (paths.length > MAX_PATHS) {
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
  return await list(
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
  );
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
  if (
    (await list(cwd, ["ls-files", "-z", "--", ".swamp"], "git ls-files .swamp"))
      .length
  ) {
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
    }
    if (
      (await list(
        cwd,
        ["ls-files", "-z", "--", root],
        "git ls-files excluded ignored prefix",
      )).length
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

function ignoredAllowed(
  path: string,
  exact: Set<string>,
  prefixes: string[],
): boolean {
  return exact.has(path) || prefixes.some((prefix) => path.startsWith(prefix));
}

async function ignoredSnapshot(
  cwd: string,
  paths: string[],
  excludedPrefixes: string[],
  packetId: string,
  invocationId: string,
  resolvedBaseSha: string,
  format: "sha1" | "sha256",
): Promise<z.infer<typeof SnapshotBindingSchema>> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (const path of paths.toSorted()) {
    const { bytes, mode } = await inspectRegular(cwd, path);
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) {
      throw new Error("ignored state exceeds aggregate byte limit");
    }
    parts.push(
      new TextEncoder().encode(path),
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
  if (records.pop() !== "" || records.length > MAX_PATHS) {
    throw new Error("malformed or oversized index inventory");
  }
  for (const record of records) {
    const match = /^([0-7]{6}) ([0-9a-f]+) ([0-3])\t([\s\S]+)$/.exec(record);
    if (!match) throw new Error("malformed index entry");
    validateRepoPath(match[4]);
    if (match[3] !== "0") {
      throw new Error("unmerged index entries are not certifiable");
    }
    if (match[1] === "120000" || match[1] === "160000") {
      throw new Error(`refusing indexed symlink or gitlink: ${match[4]}`);
    }
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.lstat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}

function countLines(bytes: Uint8Array): number {
  let count = 0;
  for (const byte of bytes) if (byte === 10) count++;
  return bytes.length && bytes.at(-1) !== 10 ? count + 1 : count;
}

type BaseEntry = { path: string; oid: string; mode: number };
type FinalEntry = { path: string; mode: number };

async function baseTree(cwd: string, base: string): Promise<BaseEntry[]> {
  const output = await command(cwd, "git ls-tree base", [
    "ls-tree",
    "-r",
    "-z",
    "--full-tree",
    base,
  ]);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(output.stdout);
  const records = text.split("\0");
  if (records.pop() !== "" || records.length > MAX_PATHS) {
    throw new Error("malformed or oversized base-tree inventory");
  }
  return records.map((record) => {
    const match = /^(100644|100755) blob ([0-9a-f]+)\t([\s\S]+)$/.exec(record);
    if (!match) throw new Error("base tree contains unsupported object type");
    validateRepoPath(match[3]);
    return {
      path: match[3],
      oid: match[2],
      mode: match[1] === "100755" ? 0o755 : 0o644,
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
      if (count > MAX_PATHS * 10) {
        throw new Error("filesystem inventory exceeds entry limit");
      }
      if (entry.name === ".git") {
        throw new Error(
          `refusing nested repository: ${relative}`,
        );
      }
      if (entry.isDirectory) pending.push(path);
      else if (!entry.isFile) {
        throw new Error(
          `refusing non-regular file: ${relative}`,
        );
      } else {
        validateRepoPath(relative);
        const stat = await Deno.lstat(path);
        files.push({ path: relative, mode: (stat.mode ?? 0) & 0o777 });
      }
    }
  }
  if (files.length > MAX_PATHS) {
    throw new Error("final tree exceeds path limit");
  }
  return files;
}

function lineDelta(
  base: Uint8Array,
  final: Uint8Array,
): { added: number; removed: number } {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const before = decoder.decode(base).split("\n");
  const after = decoder.decode(final).split("\n");
  let prefix = 0;
  while (
    prefix < before.length && prefix < after.length &&
    before[prefix] === after[prefix]
  ) prefix++;
  let suffix = 0;
  while (
    suffix < before.length - prefix && suffix < after.length - prefix &&
    before[before.length - 1 - suffix] === after[after.length - 1 - suffix]
  ) suffix++;
  return {
    added: after.length - prefix - suffix,
    removed: before.length - prefix - suffix,
  };
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length &&
    left.every((byte, i) => byte === right[i]);
}

async function collectChanges(
  cwd: string,
  base: BaseEntry[],
  final: FinalEntry[],
  ignored: Set<string>,
  format: "sha1" | "sha256",
): Promise<Change[]> {
  const changes: Change[] = [];
  const finalByPath = new Map(final.map((entry) => [entry.path, entry]));
  const basePaths = new Set(base.map((entry) => entry.path));
  let totalBytes = 0;
  for (const entry of base) {
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
      ? await inspectRegular(cwd, entry.path)
      : { bytes: new Uint8Array(), mode: 0 };
    totalBytes += baseBytes.length + finalFile.bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("tracked state exceeds aggregate byte limit");
    }
    if (
      equalBytes(baseBytes, finalFile.bytes) && entry.mode === finalFile.mode
    ) {
      continue;
    }
    const binary = baseBytes.includes(0) || finalFile.bytes.includes(0);
    const delta = binary
      ? { added: 0, removed: 0 }
      : lineDelta(baseBytes, finalFile.bytes);
    changes.push({ path: entry.path, ...delta, binary });
  }
  for (const entry of final) {
    if (basePaths.has(entry.path) || ignored.has(entry.path)) continue;
    const { bytes } = await inspectRegular(cwd, entry.path);
    totalBytes += bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("changed state exceeds aggregate byte limit");
    }
    const binary = bytes.includes(0);
    changes.push({
      path: entry.path,
      added: binary ? 0 : countLines(bytes),
      removed: 0,
      binary,
      untracked: true,
    });
  }
  return changes;
}

async function passesWhitespaceCheck(
  cwd: string,
  changes: Change[],
): Promise<boolean> {
  for (const change of changes) {
    if (change.binary || !await exists(`${cwd}/${change.path}`)) continue;
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

async function worktreeHash(
  cwd: string,
  base: string,
  changes: Change[],
): Promise<string> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (
    const change of changes.toSorted((a, b) => a.path.localeCompare(b.path))
  ) {
    const inspected = await exists(`${cwd}/${change.path}`)
      ? await inspectRegular(cwd, change.path)
      : { bytes: new Uint8Array(), mode: 0 };
    const { bytes, mode } = inspected;
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) {
      throw new Error(
        "worktree state exceeds aggregate byte limit",
      );
    }
    parts.push(
      new TextEncoder().encode(change.path),
      new TextEncoder().encode(mode.toString(8)),
      bytes,
    );
  }
  parts.push(new TextEncoder().encode(base));
  return await canonicalHash(parts);
}

function ignoredPolicy(
  context: ModelContext,
): { exact: Set<string>; prefixes: string[]; excludedPrefixes: string[] } {
  const exact = context.globalArgs?.allowedIgnoredPaths ?? [];
  const prefixes = context.globalArgs?.allowedIgnoredPathPrefixes ?? [];
  const excludedPrefixes = context.globalArgs?.excludedIgnoredPathPrefixes ??
    [];
  for (const path of exact) validateRepoPath(path);
  for (const prefix of [...prefixes, ...excludedPrefixes]) {
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
  return {
    exact: new Set(exact),
    prefixes,
    excludedPrefixes: excludedPrefixes.toSorted(),
  };
}

/** Swamp model definition. */
export const model = {
  type: "@mgreten/packet-certifier",
  version: "2026.07.24.3",
  globalArguments: GlobalArgsSchema,
  upgrades: [{
    toVersion: "2026.07.24.3",
    description: "Add explicit excluded ignored path prefixes",
    upgradeAttributes: (old: Record<string, unknown>) => ({
      ...old,
      excludedIgnoredPathPrefixes: [],
    }),
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
        await validateExcludedIgnoredPrefixes(cwd, policy.excludedPrefixes);
        const paths = await listIgnoredPaths(
          cwd,
          excludeRuntimeSwamp,
          policy.excludedPrefixes,
        );
        const violation = paths.find((path) =>
          !ignoredAllowed(path, policy.exact, policy.prefixes)
        );
        if (violation) {
          throw new Error(
            `ignored path is not permitted by policy: ${violation}`,
          );
        }
        const snapshot = IgnoredSnapshotSchema.parse({
          ...await ignoredSnapshot(
            cwd,
            paths,
            policy.excludedPrefixes,
            packetId,
            invocationId,
            resolvedBaseSha,
            format,
          ),
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
        allowedPaths: z.array(PathString).min(1).max(MAX_PATHS),
        maxChangedFiles: z.number().int().min(1).max(20).default(3),
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
        const snapshotName = await evidenceName(
          "ignored",
          packetId,
          invocationId,
        );
        const storedSnapshot = await context.readResource(snapshotName);
        if (!storedSnapshot) {
          throw new Error("pre-invocation ignored-state snapshot not found");
        }
        const parsedSnapshot = IgnoredSnapshotSchema.parse(storedSnapshot);
        if (!parsedSnapshot.ignoredScope) {
          throw new Error(
            "ignored-state snapshot predates application-owned scope; create a new invocation snapshot",
          );
        }
        const { capturedAt: _capturedAt, ...expected } = parsedSnapshot;
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
          baseEntries,
          finalEntries,
          new Set(ignoredPaths),
          expected.objectFormat,
        );
        const ignoredPathViolations = ignoredPaths.filter((path) =>
          !ignoredAllowed(path, policy.exact, policy.prefixes)
        );
        // Do not read disallowed ignored files.
        const current = ignoredPathViolations.length
          ? {
            hashVersion: HASH_VERSION,
            packetId,
            invocationId,
            resolvedBaseSha: base,
            objectFormat: expected.objectFormat,
            rootBinding: await rootBinding(cwd),
            fileCount: ignoredPaths.length,
            stateHash: await canonicalHash([]),
            ignoredScope: IGNORED_SCOPE,
            excludedIgnoredPathPrefixes: policy.excludedPrefixes,
          }
          : await ignoredSnapshot(
            cwd,
            ignoredPaths,
            policy.excludedPrefixes,
            packetId,
            invocationId,
            base,
            expected.objectFormat,
          );
        const second = ignoredPathViolations.length
          ? current
          : await ignoredSnapshot(
            cwd,
            ignoredPaths,
            policy.excludedPrefixes,
            packetId,
            invocationId,
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
        const binaryFiles = changes.filter((change) => change.binary).map((
          change,
        ) => change.path);
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
          !binaryFiles.length && checkResults.every((result) => result.passed);
        const report = ReportSchema.parse({
          hashVersion: HASH_VERSION,
          packetId,
          invocationId,
          rootBinding: await rootBinding(cwd),
          worktreeStateHash: await worktreeHash(cwd, base, changes),
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
          },
          checkResults,
          resolvedBaseSha: base,
          effectivePolicy: {
            allowedPaths,
            maxChangedFiles: maxFiles,
            maxChangedLines: maxLines,
            checks,
            allowBinary: false as const,
            allowedIgnoredPaths: [...policy.exact],
            allowedIgnoredPathPrefixes: policy.prefixes,
            excludedIgnoredPathPrefixes: policy.excludedPrefixes,
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
