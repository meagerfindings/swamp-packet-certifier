import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.14";
import { model } from "./packet_certifier.ts";

type Snapshot = {
  hashVersion: "packet-certifier-v8";
  packetId: string;
  invocationId: string;
  resolvedBaseSha: string;
  objectFormat: "sha1" | "sha256";
  rootBinding: string;
  fileCount: number;
  stateHash: string;
  ignoredScope?: "application-owned-v1";
  excludedIgnoredPathPrefixes: string[];
  allowedBinaryFiles: Array<{ path: string; sha256: string }>;
  capturedAt: string;
};

type Report = {
  packetId: string;
  invocationId: string;
  snapshotInvocationId?: string;
  passed: boolean;
  ignoredState: {
    expected: Snapshot;
    current: Snapshot;
    changed: boolean;
    stable: boolean;
  };
  rootBinding: string;
  worktreeStateHash: string;
  changedFiles: Array<{
    path: string;
    added: number;
    removed: number;
    binary: boolean;
  }>;
  pathViolations: string[];
  ignoredPathViolations: string[];
  budgetViolations: {
    maxChangedLines: boolean;
    binaryFiles: string[];
    binaryClaimViolations: string[];
  };
  checkResults: Array<{ passed: boolean }>;
};

type Harness = {
  store: Map<string, Record<string, unknown>>;
  context: {
    repoDir?: string;
    globalArgs: {
      allowedIgnoredPaths: string[];
      allowedIgnoredPathPrefixes: string[];
      excludedIgnoredPathPrefixes: string[];
    };
    readResource: (name: string) => Promise<Record<string, unknown> | null>;
    writeResource: (
      spec: string,
      name: string,
      payload: unknown,
    ) => Promise<string>;
  };
};

function harness(globalArgs: {
  allowedIgnoredPaths?: string[];
  allowedIgnoredPathPrefixes?: string[];
  excludedIgnoredPathPrefixes?: string[];
} = {}): Harness {
  const store = new Map<string, Record<string, unknown>>();
  return {
    store,
    context: {
      globalArgs: {
        allowedIgnoredPaths: globalArgs.allowedIgnoredPaths ?? [],
        allowedIgnoredPathPrefixes: globalArgs.allowedIgnoredPathPrefixes ?? [],
        excludedIgnoredPathPrefixes: globalArgs.excludedIgnoredPathPrefixes ??
          [],
      },
      readResource: (name) => Promise.resolve(store.get(name) ?? null),
      writeResource: (_spec, name, payload) => {
        store.set(name, payload as Record<string, unknown>);
        return Promise.resolve(name);
      },
    },
  };
}

async function gitOutput(cwd: string, args: string[]): Promise<string> {
  const output = await new Deno.Command("git", {
    args,
    cwd,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!output.success) {
    throw new Error(new TextDecoder().decode(output.stderr));
  }
  return new TextDecoder().decode(output.stdout).trim();
}

async function createRepo(initial: Uint8Array | string = "initial\n") {
  const cwd = await Deno.makeTempDir();
  await gitOutput(cwd, ["init"]);
  if (typeof initial === "string") {
    await Deno.writeTextFile(`${cwd}/README.md`, initial);
  } else {
    await Deno.writeFile(`${cwd}/README.md`, initial);
  }
  await gitOutput(cwd, ["add", "README.md"]);
  await gitOutput(cwd, [
    "-c",
    "user.name=Packet Certifier Test",
    "-c",
    "user.email=packet-certifier@example.test",
    "commit",
    "-m",
    "initial",
  ]);
  return cwd;
}

async function snapshot(
  cwd: string,
  h: Harness,
  packetId = "packet-1",
  invocationId = "call-1",
  allowedBinaryFiles: Array<{ path: string; sha256: string }> = [],
): Promise<Snapshot> {
  h.context.repoDir ??= cwd;
  let value: Snapshot | undefined;
  const originalWrite = h.context.writeResource;
  h.context.writeResource = async (spec, name, payload) => {
    if (spec === "ignoredSnapshot") value = payload as Snapshot;
    return await originalWrite(spec, name, payload);
  };
  try {
    await model.methods.snapshotIgnoredState.execute(
      { cwd, packetId, invocationId, baseRef: "HEAD", allowedBinaryFiles },
      h.context,
    );
  } finally {
    h.context.writeResource = originalWrite;
  }
  if (!value) throw new Error("snapshot was not written");
  return value;
}

async function certify(
  cwd: string,
  h: Harness,
  allowedPaths: string[],
  options: {
    packetId?: string;
    invocationId?: string;
    snapshotInvocationId?: string;
    maxChangedFiles?: number;
    maxChangedLines?: number;
    checks?: Array<{
      name: string;
      executable: "git";
      args: ["diff", "--check"];
    }>;
  } = {},
): Promise<Report> {
  const packetId = options.packetId ?? "packet-1";
  const invocationId = options.invocationId ?? "call-1";
  const snapshotInvocationId = options.snapshotInvocationId ?? invocationId;
  if (
    ![...h.store.values()].some((value) =>
      value.packetId === packetId &&
      value.invocationId === snapshotInvocationId
    )
  ) {
    await snapshot(cwd, h, packetId, snapshotInvocationId);
  }
  let report: Report | undefined;
  const originalWrite = h.context.writeResource;
  h.context.writeResource = async (spec, name, payload) => {
    if (spec === "certification") report = payload as Report;
    return await originalWrite(spec, name, payload);
  };
  try {
    await model.methods.certify.execute({
      cwd,
      packetId,
      invocationId,
      snapshotInvocationId: options.snapshotInvocationId,
      allowedPaths,
      maxChangedFiles: options.maxChangedFiles ?? 3,
      maxChangedLines: options.maxChangedLines ?? 120,
      checks: options.checks ?? [],
    }, h.context);
  } finally {
    h.context.writeResource = originalWrite;
  }
  if (!report) throw new Error("certification was not written");
  return report;
}

Deno.test("certifies a fallback invocation against the original snapshot identity", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h, "packet-1", "initial-call");
    await Deno.writeTextFile(`${cwd}/README.md`, "fallback change\n");
    const report = await certify(cwd, h, ["README.md"], {
      invocationId: "fallback-call",
      snapshotInvocationId: "initial-call",
    });
    assertEquals(report.passed, true);
    assertEquals(report.invocationId, "fallback-call");
    assertEquals(report.snapshotInvocationId, "initial-call");
    assertEquals(report.ignoredState.expected.invocationId, "initial-call");
    assertEquals(report.ignoredState.current.invocationId, "initial-call");
    assertEquals(report.ignoredState.changed, false);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("certifies ordinary unstaged text without persisting absolute roots", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");
    const report = await certify(cwd, h, ["README.md"]);

    assertEquals(report.passed, true);
    assertEquals(
      (report as unknown as Record<string, unknown>).canonicalRoot,
      undefined,
    );
    assertEquals(report.rootBinding.length, 64);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("certifies a repository larger than the packet path ceiling", async () => {
  const cwd = await createRepo();
  try {
    await Deno.mkdir(`${cwd}/fixtures`);
    for (let i = 0; i <= 1_000; i++) {
      await Deno.writeTextFile(`${cwd}/fixtures/${i}`, "fixture\n");
    }
    await gitOutput(cwd, ["add", "fixtures"]);
    await gitOutput(cwd, [
      "-c",
      "user.name=Packet Certifier Test",
      "-c",
      "user.email=packet-certifier@example.test",
      "commit",
      "-m",
      "large repository",
    ]);
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");

    const report = await certify(cwd, h, ["README.md"]);

    assertEquals(report.passed, true);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("uses immutable extension-owned snapshots", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    const first = await snapshot(cwd, h);
    await assertRejects(
      () => snapshot(cwd, h),
      Error,
      "snapshot already exists",
    );
    assertEquals(first.packetId, "packet-1");

    await assertRejects(
      () =>
        model.methods.certify.execute({
          cwd,
          packetId: "different-packet",
          invocationId: "call-1",
          baseRef: "HEAD",
          allowedPaths: ["README.md"],
          maxChangedFiles: 3,
          maxChangedLines: 120,
          checks: [],
        }, h.context),
      Error,
      "snapshot not found",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("ID schema rejects lossy or ambiguous resource names", () => {
  const args = model.methods.snapshotIgnoredState.arguments;
  assertEquals(
    args.safeParse({
      cwd: "/tmp/repo",
      packetId: "a/b",
      invocationId: "call",
    }).success,
    false,
  );
  assertEquals(
    args.safeParse({
      cwd: "/tmp/repo",
      packetId: "x".repeat(65),
      invocationId: "call",
    }).success,
    false,
  );
});

Deno.test("method schemas accept Swamp-injected global arguments", () => {
  const globalArgs = {
    allowedIgnoredPaths: [],
    allowedIgnoredPathPrefixes: [".swamp/"],
    excludedIgnoredPathPrefixes: [".runtime/"],
  };

  assertEquals(
    model.methods.snapshotIgnoredState.arguments.safeParse({
      cwd: "/tmp/repo",
      packetId: "packet",
      invocationId: "call",
      ...globalArgs,
    }).success,
    true,
  );
  assertEquals(
    model.methods.certify.arguments.safeParse({
      cwd: "/tmp/repo",
      packetId: "packet",
      invocationId: "call",
      allowedPaths: ["README.md"],
      ...globalArgs,
    }).success,
    true,
  );
  assertEquals(
    model.methods.snapshotIgnoredState.arguments.safeParse({
      cwd: "/tmp/repo",
      packetId: "packet",
      invocationId: "call",
      baseReff: "origin/main",
      ...globalArgs,
    }).success,
    false,
  );
  assertEquals(
    model.methods.certify.arguments.safeParse({
      cwd: "/tmp/repo",
      packetId: "packet",
      invocationId: "call",
      allowedPaths: ["README.md"],
      cheks: [],
      ...globalArgs,
    }).success,
    false,
  );
});

Deno.test("excludes Swamp-owned runtime state from ignored-state protection", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, ".swamp/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore swamp runtime"]);
    await Deno.mkdir(`${cwd}/.swamp`);
    await Deno.writeTextFile(`${cwd}/.swamp/state`, "before\n");
    const h = harness();
    await snapshot(cwd, h);

    await Deno.writeTextFile(`${cwd}/.swamp/state`, "after\n");
    await Deno.writeTextFile(`${cwd}/.swamp/output`, "new\n");
    const report = await certify(cwd, h, ["README.md"]);

    assertEquals(report.passed, true);
    assertEquals(report.ignoredPathViolations, []);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("does not exempt .swamp in a different target repository", async () => {
  const cwd = await createRepo();
  const contextRepo = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, ".swamp/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore app swamp directory"]);
    await Deno.mkdir(`${cwd}/.swamp`);
    await Deno.writeTextFile(`${cwd}/.swamp/state`, "application state\n");
    const h = harness();
    h.context.repoDir = contextRepo;

    await assertRejects(
      () => snapshot(cwd, h),
      Error,
      "ignored path is not permitted by policy: .swamp/state",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
    await Deno.remove(contextRepo, { recursive: true });
  }
});

Deno.test("rejects legacy snapshots with incompatible ignored scope", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    const stored = [...h.store.values()].find((value) => value.capturedAt);
    if (!stored) throw new Error("snapshot was not stored");
    delete stored.ignoredScope;

    await assertRejects(
      () => certify(cwd, h, ["README.md"]),
      Error,
      "snapshot predates application-owned scope",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("detects ignored content and permission changes", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, ".runtime/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore runtime"]);
    await Deno.mkdir(`${cwd}/.runtime`);
    await Deno.writeTextFile(`${cwd}/.runtime/state`, "same\n", {
      mode: 0o600,
    });
    const h = harness({ allowedIgnoredPathPrefixes: [".runtime/"] });
    const before = await snapshot(cwd, h);
    await Deno.chmod(`${cwd}/.runtime/state`, 0o700);
    const report = await certify(cwd, h, ["README.md"]);

    assertEquals(report.passed, false);
    assertEquals(
      [...h.store.values()].find((value) => value.capturedAt)?.stateHash,
      before.stateHash,
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("fails closed on an unapproved large ignored tree", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, ".runtime/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore runtime"]);
    await Deno.mkdir(`${cwd}/.runtime`);
    for (let i = 0; i <= 1_000; i++) {
      await Deno.writeTextFile(`${cwd}/.runtime/${i}`, "generated\n");
    }

    await assertRejects(
      () => snapshot(cwd, harness()),
      Error,
      "inventory exceeds path limit",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("explicitly excludes a large ignored runtime tree while hashing protected ignored files", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(
      `${cwd}/.gitignore`,
      ".runtime/\n.protected/\n",
    );
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore runtime state"]);
    await Deno.mkdir(`${cwd}/.runtime`);
    await Deno.mkdir(`${cwd}/.protected`);
    await Deno.writeTextFile(`${cwd}/.protected/config`, "before\n", {
      mode: 0o600,
    });
    for (let i = 0; i <= 1_000; i++) {
      await Deno.writeTextFile(`${cwd}/.runtime/${i}`, "generated\n");
    }
    const h = harness({
      allowedIgnoredPaths: [".protected/config"],
      excludedIgnoredPathPrefixes: [".runtime/"],
    });
    const before = await snapshot(cwd, h);

    assertEquals(before.fileCount, 1);
    assertEquals(before.excludedIgnoredPathPrefixes, [".runtime/"]);
    assertEquals((await certify(cwd, h, ["README.md"])).passed, true);

    await Deno.writeTextFile(`${cwd}/.protected/config`, "after\n", {
      mode: 0o700,
    });
    assertEquals((await certify(cwd, h, ["README.md"])).passed, false);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("prunes excluded ignored prefixes containing nested repositories", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, ".worktrees/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore worktrees"]);
    // Agent worktrees are full nested checkouts. git ls-files reports each
    // one as a single opaque directory entry with a trailing slash, and
    // pathspec exclusion cannot match inside it.
    for (const name of ["agent-a", "agent-b"]) {
      const nested = `${cwd}/.worktrees/${name}`;
      await Deno.mkdir(nested, { recursive: true });
      await gitOutput(nested, ["init"]);
      await Deno.writeTextFile(`${nested}/nested.txt`, "nested\n");
    }
    const h = harness({ excludedIgnoredPathPrefixes: [".worktrees/"] });

    const before = await snapshot(cwd, h);
    assertEquals(before.fileCount, 0);
    assertEquals((await certify(cwd, h, ["README.md"])).passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("excludes more nested repositories than the packet path limit", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, ".worktrees/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore worktrees"]);
    // Each nested repository survives the :(exclude) pathspec as its own
    // opaque entry, so more than MAX_PATHS of them must still be prunable.
    // These have to be real repositories: Git reports neither an empty
    // directory nor a hand-made .git, so nothing would be pruned otherwise.
    await Deno.mkdir(`${cwd}/.worktrees`);
    for (let i = 0; i <= 1_000; i++) {
      await gitOutput(cwd, ["init", "-q", `.worktrees/agent-${i}`]);
    }
    const h = harness({ excludedIgnoredPathPrefixes: [".worktrees/"] });

    const before = await snapshot(cwd, h);
    assertEquals(before.fileCount, 0);
    assertEquals((await certify(cwd, h, ["README.md"])).passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("rejects an unenumerable ignored directory outside every exclusion", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, "vendored/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore vendored"]);
    const nested = `${cwd}/vendored/library`;
    await Deno.mkdir(nested, { recursive: true });
    await gitOutput(nested, ["init"]);

    await assertRejects(
      () => snapshot(cwd, harness()),
      Error,
      "refusing unenumerable ignored directory",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("definition policy wins over policy passed per call", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, "secret.env\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore secret"]);
    await Deno.writeTextFile(`${cwd}/secret.env`, "TOKEN=1\n");
    const h = harness();

    // A caller must not be able to widen the policy at the call site.
    await assertRejects(
      () =>
        model.methods.snapshotIgnoredState.execute({
          cwd,
          packetId: "packet-1",
          invocationId: "call-1",
          baseRef: "HEAD",
          allowedIgnoredPaths: ["secret.env"],
          allowedIgnoredPathPrefixes: [],
          excludedIgnoredPathPrefixes: [],
        }, h.context),
      Error,
      "ignored path is not permitted by policy: secret.env",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("rejects an excluded prefix that is not the on-disk spelling", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, "Cache/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore cache"]);
    await Deno.mkdir(`${cwd}/Cache`);
    await Deno.writeTextFile(`${cwd}/Cache/generated`, "generated\n");

    // A case-insensitive filesystem resolves "cache" to "Cache", so every
    // stat-based check would pass while byte-wise pruning matched nothing. A
    // case-sensitive filesystem rejects the incorrectly cased path earlier.
    let expectedMessage = "excluded ignored prefix does not exist";
    try {
      await Deno.lstat(`${cwd}/cache`);
      expectedMessage =
        "excluded ignored prefix does not match the on-disk name";
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    await assertRejects(
      () => snapshot(cwd, harness({ excludedIgnoredPathPrefixes: ["cache/"] })),
      Error,
      expectedMessage,
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("does not exclude a sibling sharing an excluded prefix name", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, "run/\nrun-evil/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore runtime"]);
    await Deno.mkdir(`${cwd}/run`);
    await Deno.writeTextFile(`${cwd}/run/generated`, "generated\n");
    await Deno.mkdir(`${cwd}/run-evil`);
    await Deno.writeTextFile(`${cwd}/run-evil/smuggled`, "smuggled\n");

    await assertRejects(
      () => snapshot(cwd, harness({ excludedIgnoredPathPrefixes: ["run/"] })),
      Error,
      "ignored path is not permitted by policy: run-evil/smuggled",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("binds excluded ignored prefixes to the invocation snapshot", async () => {
  const cwd = await createRepo();
  try {
    await Deno.writeTextFile(`${cwd}/.gitignore`, ".runtime/\n");
    await gitOutput(cwd, ["add", ".gitignore"]);
    await gitOutput(cwd, ["commit", "-m", "ignore runtime"]);
    await Deno.mkdir(`${cwd}/.runtime`);
    const h = harness({ excludedIgnoredPathPrefixes: [".runtime/"] });
    await snapshot(cwd, h);
    h.context.globalArgs.excludedIgnoredPathPrefixes = [];

    await assertRejects(
      () => certify(cwd, h, ["README.md"]),
      Error,
      "excluded ignored path policy differs",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test({
  name: "rejects symlinks at an excluded ignored prefix",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const cwd = await createRepo();
    const outside = await Deno.makeTempDir();
    try {
      await Deno.writeTextFile(`${cwd}/.gitignore`, ".runtime/\n");
      await gitOutput(cwd, ["add", ".gitignore"]);
      await gitOutput(cwd, ["commit", "-m", "ignore runtime"]);
      await Deno.symlink(outside, `${cwd}/.runtime`);

      await assertRejects(
        () =>
          snapshot(
            cwd,
            harness({ excludedIgnoredPathPrefixes: [".runtime/"] }),
          ),
        Error,
        "excluded ignored prefix crosses symlink",
      );
    } finally {
      await Deno.remove(cwd, { recursive: true });
      await Deno.remove(outside, { recursive: true });
    }
  },
});

Deno.test("rejects tracked Swamp state as certification infrastructure", async () => {
  const cwd = await createRepo();
  try {
    await Deno.mkdir(`${cwd}/.swamp`);
    await Deno.writeTextFile(`${cwd}/.swamp/state`, "tracked\n");
    await gitOutput(cwd, ["add", "-f", ".swamp/state"]);
    await gitOutput(cwd, ["commit", "-m", "track swamp state"]);
    const h = harness();
    h.context.repoDir = cwd;

    await assertRejects(
      () => snapshot(cwd, h),
      Error,
      "tracked .swamp paths",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("rejects staged and unmerged index state", async () => {
  const staged = await createRepo();
  try {
    const h = harness();
    await snapshot(staged, h);
    await Deno.writeTextFile(`${staged}/README.md`, "staged\n");
    await gitOutput(staged, ["add", "README.md"]);
    await assertRejects(
      () => certify(staged, h, ["README.md"]),
      Error,
      "staged changes are not certifiable",
    );
  } finally {
    await Deno.remove(staged, { recursive: true });
  }

  const unmerged = await createRepo();
  try {
    const h = harness();
    await snapshot(unmerged, h);
    const oid = await gitOutput(unmerged, ["rev-parse", "HEAD:README.md"]);
    const process = new Deno.Command("git", {
      args: ["update-index", "--index-info"],
      cwd: unmerged,
      stdin: "piped",
    }).spawn();
    const writer = process.stdin.getWriter();
    await writer.write(new TextEncoder().encode(
      `100644 ${oid} 1\tconflict\n100644 ${oid} 2\tconflict\n`,
    ));
    await writer.close();
    await process.output();
    await assertRejects(
      () => certify(unmerged, h, ["conflict"]),
      Error,
      "unmerged index entries",
    );
  } finally {
    await Deno.remove(unmerged, { recursive: true });
  }
});

Deno.test("neutralizes fsmonitor and rejects executable content filters", async () => {
  const cwd = await createRepo();
  try {
    const marker = `${cwd}/marker`;
    await Deno.writeTextFile(
      `${cwd}/evil.sh`,
      `#!/bin/sh\ntouch '${marker}'\ncat "$1" 2>/dev/null || true\n`,
      { mode: 0o755 },
    );
    await gitOutput(cwd, ["config", "core.fsmonitor", `${cwd}/evil.sh`]);
    const h = harness();
    await snapshot(cwd, h);
    await gitOutput(cwd, ["config", "filter.evil.clean", `${cwd}/evil.sh`]);
    await Deno.writeTextFile(
      `${cwd}/.gitattributes`,
      "README.md filter=evil\n",
    );
    await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");
    await assertRejects(
      () => certify(cwd, h, ["README.md", ".gitattributes", "evil.sh"]),
      Error,
      "clean/process filters",
    );

    assertEquals(await exists(marker), false);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("attributes cannot suppress internal text line accounting", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/.gitattributes`, "README.md -diff\n");
    await Deno.writeTextFile(`${cwd}/README.md`, "line\n".repeat(500));

    const report = await certify(cwd, h, ["README.md", ".gitattributes"]);
    assertEquals(report.passed, false);
    assertEquals(report.budgetViolations.maxChangedLines, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("binds the base before invocation even when HEAD moves", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    const before = await snapshot(cwd, h);
    await Deno.writeTextFile(
      `${cwd}/disallowed.txt`,
      "committed after snapshot\n",
    );
    await gitOutput(cwd, ["add", "disallowed.txt"]);
    await gitOutput(cwd, ["commit", "-m", "move head"]);
    const report = await certify(cwd, h, ["README.md"]);

    assertEquals(report.passed, false);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "disallowed.txt",
    ]);
    assertEquals(
      before.resolvedBaseSha === await gitOutput(cwd, ["rev-parse", "HEAD"]),
      false,
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("index flags cannot hide final tracked bytes", async () => {
  for (const flag of ["--assume-unchanged", "--skip-worktree"]) {
    const cwd = await createRepo();
    try {
      const h = harness();
      await snapshot(cwd, h);
      await gitOutput(cwd, ["update-index", flag, "README.md"]);
      await Deno.writeTextFile(`${cwd}/README.md`, `hidden by ${flag}  \n`);
      const report = await certify(cwd, h, ["different.txt"], {
        checks: [{
          name: "whitespace",
          executable: "git",
          args: ["diff", "--check"],
        }],
      });

      assertEquals(report.passed, false);
      assertEquals(report.checkResults[0].passed, false);
      assertEquals(report.changedFiles.map((change) => change.path), [
        "README.md",
      ]);
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  }
});

Deno.test("rejects partial-clone and promisor configuration", async () => {
  const cwd = await createRepo();
  try {
    await gitOutput(cwd, ["config", "remote.origin.promisor", "true"]);
    const h = harness();
    await assertRejects(
      () => snapshot(cwd, h),
      Error,
      "partial-clone and promisor repositories",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("verifies base blob bytes against their object IDs", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    const oid = await gitOutput(cwd, ["rev-parse", "HEAD:README.md"]);
    const forged = new TextEncoder().encode("blob 7\0forged\n");
    const compressed = await new Response(
      new Blob([forged]).stream().pipeThrough(new CompressionStream("deflate")),
    ).bytes();
    const objectPath = `${cwd}/.git/objects/${oid.slice(0, 2)}/${oid.slice(2)}`;
    await Deno.chmod(objectPath, 0o600);
    await Deno.writeFile(objectPath, compressed);
    await Deno.writeTextFile(`${cwd}/README.md`, "forged\n");

    await assertRejects(
      () => certify(cwd, h, ["README.md"]),
      Error,
      "git fsck base failed",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("replacement refs cannot substitute the bound base", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    const before = await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "replacement content\n");
    await gitOutput(cwd, ["add", "README.md"]);
    await gitOutput(cwd, ["commit", "-m", "replacement commit"]);
    const replacement = await gitOutput(cwd, ["rev-parse", "HEAD"]);
    await gitOutput(cwd, ["replace", before.resolvedBaseSha, replacement]);
    const report = await certify(cwd, h, ["different.txt"]);

    assertEquals(report.passed, false);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("certifies a binary only against its exact SHA-256 claim", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    const bytes = new Uint8Array([65, 0, 66]);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", bytes.slice().buffer),
    );
    const sha256 = [...digest].map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    await snapshot(cwd, h, "packet-1", "call-1", [
      { path: "asset.png", sha256 },
    ]);
    await Deno.writeFile(`${cwd}/asset.png`, bytes);

    const report = await certify(cwd, h, ["asset.png"]);

    assertEquals(report.passed, true);
    assertEquals(report.budgetViolations.binaryFiles, ["asset.png"]);
    assertEquals(report.budgetViolations.binaryClaimViolations, []);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("rejects an unclaimed binary beside a correctly claimed binary", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    const claimed = new Uint8Array([65, 0, 66]);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", claimed.slice().buffer),
    );
    const sha256 = [...digest].map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    await snapshot(cwd, h, "packet-1", "call-1", [
      { path: "claimed.png", sha256 },
    ]);
    await Deno.writeFile(`${cwd}/claimed.png`, claimed);
    await Deno.writeFile(`${cwd}/unclaimed.png`, new Uint8Array([67, 0, 68]));

    const report = await certify(cwd, h, ["claimed.png", "unclaimed.png"]);

    assertEquals(report.passed, false);
    assertEquals(report.budgetViolations.binaryClaimViolations, [
      "unclaimed.png",
    ]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("rejects duplicate binary claims before writing a snapshot", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await assertRejects(
      () =>
        snapshot(cwd, h, "packet-1", "call-1", [
          { path: "asset.png", sha256: "0".repeat(64) },
          { path: "asset.png", sha256: "1".repeat(64) },
        ]),
      Error,
      "duplicate binary claim",
    );
    assertEquals(h.store.size, 0);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("certify cannot replace snapshot-bound binary claims", () => {
  const parsed = model.methods.certify.arguments.safeParse({
    cwd: "/tmp/repo",
    packetId: "packet-1",
    invocationId: "call-1",
    allowedPaths: ["asset.png"],
    allowedBinaryFiles: [{ path: "asset.png", sha256: "0".repeat(64) }],
  });

  assertEquals(parsed.success, false);
});

Deno.test("rejects missing, incorrect, and unused binary claims", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h, "packet-1", "call-1", [
      { path: "asset.png", sha256: "0".repeat(64) },
      { path: "unused.png", sha256: "1".repeat(64) },
    ]);
    await Deno.writeFile(`${cwd}/asset.png`, new Uint8Array([65, 0, 66]));

    const report = await certify(cwd, h, ["asset.png"]);

    assertEquals(report.passed, false);
    assertEquals(report.budgetViolations.binaryClaimViolations, [
      "asset.png",
      "unused.png",
    ]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("rejects a binary base changed into clean text", async () => {
  const cwd = await createRepo(new Uint8Array([65, 0, 66]));
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/.gitattributes`, "README.md diff\n");
    await Deno.writeTextFile(`${cwd}/README.md`, "clean text\n");

    const report = await certify(cwd, h, ["README.md", ".gitattributes"]);
    assertEquals(report.passed, false);
    assertEquals(report.budgetViolations.binaryFiles, ["README.md"]);
    assertEquals(report.budgetViolations.binaryClaimViolations, ["README.md"]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("tracks executable-bit-only changes even when repo config disables them", async () => {
  const cwd = await createRepo();
  try {
    await gitOutput(cwd, ["config", "core.fileMode", "false"]);
    const h = harness();
    await snapshot(cwd, h);
    await Deno.chmod(`${cwd}/README.md`, 0o755);
    const report = await certify(cwd, h, ["README.md"]);

    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("ignores tracked permission bits Git does not store", async () => {
  const cwd = await createRepo();
  try {
    await Deno.chmod(`${cwd}/README.md`, 0o664);
    const h = harness();
    await snapshot(cwd, h);
    const report = await certify(cwd, h, ["README.md"]);

    assertEquals(report.changedFiles, []);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("rejects existing gitlinks and nested repositories", async () => {
  const gitlink = await createRepo();
  try {
    const h = harness();
    await snapshot(gitlink, h);
    const commit = await gitOutput(gitlink, ["rev-parse", "HEAD"]);
    await gitOutput(gitlink, [
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${commit},vendor`,
    ]);
    await assertRejects(
      () => certify(gitlink, h, ["vendor"]),
      Error,
      "indexed gitlink",
    );
  } finally {
    await Deno.remove(gitlink, { recursive: true });
  }

  const nested = await createRepo();
  try {
    await Deno.writeTextFile(`${nested}/.gitignore`, ".runtime/\n");
    await gitOutput(nested, ["add", ".gitignore"]);
    await gitOutput(nested, ["commit", "-m", "ignore runtime"]);
    await Deno.mkdir(`${nested}/.runtime`, { recursive: true });
    await Deno.writeTextFile(`${nested}/.runtime/state`, "value\n");
    const h = harness({ allowedIgnoredPathPrefixes: [".runtime/"] });
    await snapshot(nested, h);
    await Deno.mkdir(`${nested}/.runtime/nested`);
    await gitOutput(`${nested}/.runtime/nested`, ["init"]);
    await assertRejects(
      () => certify(nested, h, ["README.md"]),
      Error,
      "nested repository",
    );
  } finally {
    await Deno.remove(nested, { recursive: true });
  }
});

Deno.test("handles pathspec-magic filenames literally", async () => {
  const cwd = await createRepo();
  try {
    const path = ":(glob)*.txt";
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/${path}`, "literal\n");
    const report = await certify(cwd, h, [path]);
    assertEquals(report.changedFiles[0].path, path);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("enforces line budgets and omits deterministic-check output", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "one  \ntwo\nthree\n");
    const report = await certify(cwd, h, ["README.md"], {
      maxChangedLines: 2,
      checks: [{
        name: "whitespace",
        executable: "git",
        args: ["diff", "--check"],
      }],
    });

    assertEquals(report.passed, false);
    assertEquals(report.budgetViolations.maxChangedLines, true);
    assertEquals(report.checkResults[0].passed, false);
    assertEquals(
      "stdout" in
        (report.checkResults[0] as unknown as Record<string, unknown>),
      false,
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("implements default diff-check-compatible whitespace rules", async () => {
  const cases = [
    " \tindented\n",
    "content\n\n",
    "trailing  \r\n",
    "||||||| base\n",
  ];
  for (const content of cases) {
    const cwd = await createRepo();
    try {
      const h = harness();
      await snapshot(cwd, h);
      await Deno.writeTextFile(`${cwd}/README.md`, content);
      const report = await certify(cwd, h, ["README.md"], {
        checks: [{
          name: "whitespace",
          executable: "git",
          args: ["diff", "--check"],
        }],
      });

      assertEquals(report.checkResults[0].passed, false, content);
      assertEquals(report.passed, false, content);
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  }
});

Deno.test({
  name: "rejects an untracked FIFO",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const cwd = await createRepo();
    try {
      const h = harness();
      await snapshot(cwd, h);
      await new Deno.Command("mkfifo", { args: [`${cwd}/pipe`] }).output();
      await assertRejects(
        () => certify(cwd, h, ["pipe"]),
        Error,
        "non-regular file",
      );
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  },
});

Deno.test("detects a tracked edit that preserves the base byte length", async () => {
  const cwd = await createRepo("aaaaaa\n");
  try {
    const h = harness();
    await snapshot(cwd, h);
    // Same length and same mode, so neither the base size nor the base mode
    // distinguishes this file from an untouched one.
    await Deno.writeTextFile(`${cwd}/README.md`, "bbbbbb\n");
    assertEquals(
      (await Deno.lstat(`${cwd}/README.md`)).size,
      "aaaaaa\n".length,
    );

    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("detects a same-length edit Git itself declines to report", async () => {
  const cwd = await createRepo("aaaaaa\n");
  try {
    const h = harness();
    await snapshot(cwd, h);
    // --assume-unchanged makes Git report a clean worktree, so the diff union
    // contributes nothing. With size and mode also unchanged, only re-deriving
    // the blob object ID from worktree bytes can catch this.
    await gitOutput(cwd, ["update-index", "--assume-unchanged", "README.md"]);
    await Deno.writeTextFile(`${cwd}/README.md`, "bbbbbb\n");
    assertEquals(await gitOutput(cwd, ["diff", "--name-only", "HEAD"]), "");

    await assertRejects(
      () => certify(cwd, h, ["README.md"]),
      Error,
      "differs from base without a detectable change",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("detects a mode-only change on a tracked file", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.chmod(`${cwd}/README.md`, 0o755);

    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("detects a deleted tracked file", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.remove(`${cwd}/README.md`);

    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
    assertEquals(report.changedFiles[0].removed, 1);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("detects an untracked added file", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/added.txt`, "new file\n");

    const report = await certify(cwd, h, ["added.txt"]);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "added.txt",
    ]);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("certifies a repository whose tracked content exceeds the aggregate byte limit", async () => {
  const cwd = await createRepo();
  try {
    // 64 MiB of tracked content against a 50 MiB MAX_TOTAL_BYTES: reading every
    // tracked file would fail closed, so passing proves only candidates were read.
    await Deno.mkdir(`${cwd}/bulk`);
    const megabyte = new Uint8Array(1024 * 1024).fill(97);
    for (let i = 0; i < 64; i++) {
      await Deno.writeFile(`${cwd}/bulk/${i}.dat`, megabyte);
    }
    await gitOutput(cwd, ["add", "bulk"]);
    await gitOutput(cwd, [
      "-c",
      "user.name=Packet Certifier Test",
      "-c",
      "user.email=packet-certifier@example.test",
      "commit",
      "-m",
      "bulk tracked content",
    ]);
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");

    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.passed, true);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("certifies a repository whose tracked content exceeds the former aggregate byte limit but stays within the raised one", async () => {
  const cwd = await createRepo();
  try {
    // 64 MiB exceeded the old 50 MiB MAX_TOTAL_BYTES (see the test above,
    // which predates the 2026-08-08 incident raise to 256 MiB). Push past
    // that former ceiling into territory the raised limit must still admit,
    // proving the incident's byte-limit change actually took effect rather
    // than merely shifting the constant without widening the code path.
    await Deno.mkdir(`${cwd}/bulk`);
    const megabyte = new Uint8Array(1024 * 1024).fill(98);
    for (let i = 0; i < 200; i++) {
      await Deno.writeFile(`${cwd}/bulk/${i}.dat`, megabyte);
    }
    await gitOutput(cwd, ["add", "bulk"]);
    await gitOutput(cwd, [
      "-c",
      "user.name=Packet Certifier Test",
      "-c",
      "user.email=packet-certifier@example.test",
      "commit",
      "-m",
      "bulk tracked content beyond the former ceiling",
    ]);
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");

    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.passed, true);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("fails closed on a single candidate file exceeding the raised per-file byte limit", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    // 129 MiB exceeds the raised 128 MiB MAX_FILE_BYTES. The file must be a
    // candidate (its path is in allowedPaths) so the per-file check is what
    // trips, not the aggregate check.
    const chunk = new Uint8Array(1024 * 1024).fill(99);
    const handle = await Deno.open(`${cwd}/README.md`, {
      write: true,
      truncate: true,
    });
    for (let i = 0; i < 129; i++) {
      await handle.write(chunk);
    }
    handle.close();

    await assertRejects(
      () => certify(cwd, h, ["README.md"]),
      Error,
      "file exceeds byte limit",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("fails closed on aggregate candidate bytes exceeding the raised total byte limit", async () => {
  const cwd = await createRepo();
  try {
    const h = harness();
    await snapshot(cwd, h);
    await Deno.mkdir(`${cwd}/bulk`);
    const megabyte = new Uint8Array(1024 * 1024).fill(100);
    // Three untracked candidate files at 90 MiB each: none trips the 128 MiB
    // per-file limit individually, but their 270 MiB sum exceeds the raised
    // 256 MiB MAX_TOTAL_BYTES aggregate. Untracked (rather than tracked and
    // modified) so worktree bytes are read directly via inspectEntry, not
    // through a `git cat-file blob` call bounded by the separate 4 MiB
    // MAX_COMMAND_BYTES output cap.
    for (let i = 0; i < 3; i++) {
      const handle = await Deno.open(`${cwd}/bulk/${i}.dat`, {
        write: true,
        create: true,
      });
      for (let j = 0; j < 90; j++) {
        await handle.write(megabyte);
      }
      handle.close();
    }

    await assertRejects(
      () =>
        certify(cwd, h, ["bulk/0.dat", "bulk/1.dat", "bulk/2.dat"], {
          maxChangedFiles: 5,
        }),
      Error,
      "exceeds aggregate byte limit",
    );
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}

/** Commit a tracked symlink so it exists in the base tree as mode 120000. */
async function commitSymlink(
  cwd: string,
  target: string,
  name: string,
): Promise<void> {
  await Deno.symlink(target, `${cwd}/${name}`);
  await gitOutput(cwd, ["add", name]);
  await gitOutput(cwd, [
    "-c",
    "user.name=Packet Certifier Test",
    "-c",
    "user.email=packet-certifier@example.test",
    "commit",
    "-m",
    `track symlink ${name}`,
  ]);
  const mode = await gitOutput(cwd, ["ls-files", "--stage", "--", name]);
  if (!mode.startsWith("120000")) {
    throw new Error(`expected a tracked symlink, got: ${mode}`);
  }
}

Deno.test({
  name: "certifies an unchanged tracked symlink",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const cwd = await createRepo();
    try {
      await commitSymlink(cwd, "README.md", "link.md");
      const h = harness();
      await snapshot(cwd, h);
      await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");

      // The symlink is untouched, so it must not appear at all: a repository
      // that merely contains tracked symlinks stays certifiable.
      const report = await certify(cwd, h, ["README.md"]);
      assertEquals(report.changedFiles.map((change) => change.path), [
        "README.md",
      ]);
      assertEquals(report.passed, true);
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  },
});

Deno.test({
  name: "detects a retargeted tracked symlink",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const cwd = await createRepo();
    try {
      await Deno.writeTextFile(`${cwd}/other.txt`, "other\n");
      await gitOutput(cwd, ["add", "other.txt"]);
      await gitOutput(cwd, [
        "-c",
        "user.name=Packet Certifier Test",
        "-c",
        "user.email=packet-certifier@example.test",
        "commit",
        "-m",
        "add other",
      ]);
      await commitSymlink(cwd, "README.md", "link.md");
      const h = harness();
      await snapshot(cwd, h);
      // Silence Git so the diff union contributes nothing, and retarget between
      // two names of identical length so the stat size matches the base blob
      // size too. Only comparing the target bytes themselves can catch this.
      await gitOutput(cwd, ["update-index", "--assume-unchanged", "link.md"]);
      await Deno.remove(`${cwd}/link.md`);
      await Deno.symlink("other.txt", `${cwd}/link.md`);
      assertEquals("README.md".length, "other.txt".length);
      assertEquals(await gitOutput(cwd, ["diff", "--name-only", "HEAD"]), "");

      const report = await certify(cwd, h, ["README.md"]);
      assertEquals(report.changedFiles.map((change) => change.path), [
        "link.md",
      ]);
      assertEquals(report.pathViolations, ["link.md"]);
      assertEquals(report.passed, false);
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  },
});

Deno.test({
  name: "detects a newly added symlink",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const cwd = await createRepo();
    try {
      const h = harness();
      await snapshot(cwd, h);
      await Deno.symlink("README.md", `${cwd}/added-link`);

      const report = await certify(cwd, h, ["README.md"]);
      assertEquals(report.changedFiles.map((change) => change.path), [
        "added-link",
      ]);
      assertEquals(report.pathViolations, ["added-link"]);
      assertEquals(report.passed, false);
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  },
});

Deno.test({
  name: "reports a symlink escaping the worktree without reading through it",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const cwd = await createRepo();
    const outside = await Deno.makeTempDir();
    try {
      // 40 lines of content that must never be attributed to the symlink, and a
      // directory the walk must never descend into.
      const secret = `${outside}/secret.txt`;
      await Deno.writeTextFile(secret, "secret\n".repeat(40));
      await Deno.mkdir(`${outside}/tree`);
      await Deno.writeTextFile(`${outside}/tree/inside.txt`, "inside\n");
      const h = harness();
      await snapshot(cwd, h);
      await Deno.symlink(secret, `${cwd}/escape-file`);
      await Deno.symlink(`${outside}/tree`, `${cwd}/escape-dir`);

      const report = await certify(cwd, h, ["README.md"], {
        maxChangedFiles: 5,
      });
      const paths = report.changedFiles.map((change) => change.path).toSorted();
      assertEquals(paths, ["escape-dir", "escape-file"]);
      // One added line each: the target string. Reading through the symlink
      // would report the 40 lines behind it instead.
      for (const change of report.changedFiles) {
        assertEquals(change.added, 1, change.path);
      }
      // Descending the symlinked directory would surface this path.
      assertEquals(
        paths.some((path) => path.includes("inside.txt")),
        false,
      );
      assertEquals(report.passed, false);
    } finally {
      await Deno.remove(cwd, { recursive: true });
      await Deno.remove(outside, { recursive: true });
    }
  },
});

Deno.test("certifies a repository exceeding the former repository ceiling", async () => {
  const cwd = await createRepo();
  try {
    // The old MAX_REPOSITORY_PATHS was 10,000, and it bounded the index, the
    // base tree, and the filesystem walk. Commit more than that so every one of
    // those inventories is over the retired ceiling.
    await Deno.mkdir(`${cwd}/bulk`);
    for (let i = 0; i < 10_200; i++) {
      await Deno.writeTextFile(`${cwd}/bulk/${i}.txt`, "bulk\n");
    }
    await gitOutput(cwd, ["add", "bulk"]);
    await gitOutput(cwd, [
      "-c",
      "user.name=Packet Certifier Test",
      "-c",
      "user.email=packet-certifier@example.test",
      "commit",
      "-m",
      "bulk tracked paths",
    ]);
    assertEquals(
      (await gitOutput(cwd, ["ls-files"])).split("\n").length > 10_000,
      true,
    );
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");

    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("detects a deleted empty tracked file", async () => {
  const cwd = await createRepo();
  try {
    // An empty base blob deleted from the worktree presents empty base bytes and
    // empty final bytes, so a byte-equality shortcut would silently clear it.
    await Deno.writeTextFile(`${cwd}/empty.txt`, "");
    await gitOutput(cwd, ["add", "empty.txt"]);
    await gitOutput(cwd, [
      "-c",
      "user.name=Packet Certifier Test",
      "-c",
      "user.email=packet-certifier@example.test",
      "commit",
      "-m",
      "add empty file",
    ]);
    const h = harness();
    await snapshot(cwd, h);
    await Deno.remove(`${cwd}/empty.txt`);

    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "empty.txt",
    ]);
    assertEquals(report.pathViolations, ["empty.txt"]);
    assertEquals(report.passed, false);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("counts separated edits instead of unchanged lines between hunks", async () => {
  const initial =
    Array.from({ length: 1_200 }, (_, i) => `line ${i}`).join("\n") + "\n";
  const cwd = await createRepo(initial);
  try {
    const h = harness();
    await snapshot(cwd, h);
    const changed = initial.split("\n");
    changed[100] = "changed near the start";
    changed[1_000] = "changed near the end";
    await Deno.writeTextFile(`${cwd}/README.md`, changed.join("\n"));

    const report = await certify(cwd, h, ["README.md"], { maxChangedLines: 4 });
    assertEquals(report.changedFiles[0].added, 2);
    assertEquals(report.changedFiles[0].removed, 2);
    assertEquals(report.budgetViolations.maxChangedLines, false);
    assertEquals(report.passed, true);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});

Deno.test("counts insertions, deletions, empty files, and newline changes", async () => {
  const cases = [
    {
      before: "one\nthree\n",
      after: "one\ntwo\nthree\n",
      added: 1,
      removed: 0,
    },
    {
      before: "one\ntwo\nthree\n",
      after: "one\nthree\n",
      added: 0,
      removed: 1,
    },
    { before: "", after: "text", added: 1, removed: 0 },
    { before: "text", after: "", added: 0, removed: 1 },
    { before: "text\n", after: "text", added: 1, removed: 1 },
    { before: "text", after: "text\n", added: 1, removed: 1 },
  ];
  for (const example of cases) {
    const cwd = await createRepo(example.before);
    try {
      const h = harness();
      await snapshot(cwd, h);
      await Deno.writeTextFile(`${cwd}/README.md`, example.after);
      const report = await certify(cwd, h, ["README.md"]);
      assertEquals(report.changedFiles[0].added, example.added);
      assertEquals(report.changedFiles[0].removed, example.removed);
      assertEquals(Number.isInteger(report.changedFiles[0].added), true);
      assertEquals(Number.isInteger(report.changedFiles[0].removed), true);
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  }
});

/**
 * Install a `git` shim ahead of the real binary on PATH that sleeps once
 * (past the former 30s COMMAND_TIMEOUT_MS but under the current 60s one)
 * before delegating to the real `git` for every invocation, including the
 * one it delayed. Callers must restore PATH in a `finally` so a failed test
 * cannot leak the override into later tests.
 */
async function installSlowGitOnce(
  delaySeconds: number,
): Promise<{ shimDir: string; restore: () => Promise<void> }> {
  const shimDir = await Deno.makeTempDir();
  const marker = `${shimDir}/.slept`;
  await Deno.writeTextFile(
    `${shimDir}/git`,
    `#!/bin/sh\n` +
      `if [ -f '${marker}' ]; then\n` +
      `  exec /usr/bin/git "$@"\n` +
      `else\n` +
      `  touch '${marker}'\n` +
      `  sleep ${delaySeconds}\n` +
      `  exec /usr/bin/git "$@"\n` +
      `fi\n`,
  );
  await Deno.chmod(`${shimDir}/git`, 0o755);
  const originalPath = Deno.env.get("PATH") ?? "/usr/bin:/bin";
  Deno.env.set("PATH", `${shimDir}:${originalPath}`);
  return {
    shimDir,
    restore: async () => {
      Deno.env.set("PATH", originalPath);
      await Deno.remove(shimDir, { recursive: true });
    },
  };
}

Deno.test({
  name:
    "certifies successfully when one Git invocation takes longer than the former 30s timeout but under the raised 60s one",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const cwd = await createRepo();
    const shim = await installSlowGitOnce(35);
    try {
      const h = harness();
      await snapshot(cwd, h);
      await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");
      const report = await certify(cwd, h, ["README.md"]);
      assertEquals(report.passed, true);
    } finally {
      await shim.restore();
      await Deno.remove(cwd, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "a Git invocation past the 60s ceiling fails closed (generic failure; typed timeout is a tracked follow-up)",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    // command()'s catch block collapses an AbortController timeout and an
    // ordinary non-zero exit into the same generic `${label} failed` error —
    // there is no distinct typed timeout class to assert on here, only that
    // the call fails closed rather than hanging forever. Introducing a typed
    // timeout error is tracked separately and intentionally out of scope for
    // this incident port.
    //
    // A shim that never delegates simulates a hung Git process (e.g. lock
    // contention, a stalled filesystem). COMMAND_TIMEOUT_MS is not
    // test-injectable (it is a module-level const, and the model exports
    // only `model`), so this test genuinely waits out the real 60s abort
    // deadline rather than a shortened one — it is a slow, real-time test by
    // necessity, not by oversight. The shim sleeps 600s so the wait is
    // bounded by the abort at 60s rather than by the shim's own sleep.
    // `exec` replaces the shell's own process image with `sleep`, so the
    // AbortController's SIGTERM lands on the process actually holding the
    // stdout/stderr pipes open — a bare (non-exec'd) `sleep` would run as a
    // grandchild that keeps the pipes open after the shell dies, so
    // Deno.Command.output() would hang until the real 600s elapsed instead
    // of returning at the abort deadline.
    const shimDir = await Deno.makeTempDir();
    await Deno.writeTextFile(`${shimDir}/git`, `#!/bin/sh\nexec sleep 600\n`);
    await Deno.chmod(`${shimDir}/git`, 0o755);
    const originalPath = Deno.env.get("PATH") ?? "/usr/bin:/bin";
    const cwd = await createRepo();
    try {
      // snapshotIgnoredState's first internal Git call is "git rev-parse"
      // (canonicalRepoRoot); it never returns, so the whole call must fail
      // once COMMAND_TIMEOUT_MS elapses rather than hang forever.
      Deno.env.set("PATH", `${shimDir}:${originalPath}`);
      const h = harness();
      await assertRejects(
        () => snapshot(cwd, h),
        Error,
        "git rev-parse failed",
      );
    } finally {
      Deno.env.set("PATH", originalPath);
      await Deno.remove(shimDir, { recursive: true });
      await Deno.remove(cwd, { recursive: true });
    }
  },
});

Deno.test("core.commitGraph=false silences stale commit-graph errors that a default-configured Git invocation surfaces", async () => {
  const cwd = await createRepo();
  try {
    // A second commit gives commit-graph write something non-trivial to
    // record so corrupting it is meaningful.
    await Deno.writeTextFile(`${cwd}/README.md`, "second\n");
    await gitOutput(cwd, ["add", "README.md"]);
    await gitOutput(cwd, [
      "-c",
      "user.name=Packet Certifier Test",
      "-c",
      "user.email=packet-certifier@example.test",
      "commit",
      "-m",
      "second",
    ]);
    await gitOutput(cwd, ["commit-graph", "write", "--reachable"]);
    const graphPath = `${cwd}/.git/objects/info/commit-graph`;
    if (!(await exists(graphPath))) {
      throw new Error("expected git commit-graph write to produce a file");
    }
    // Flip bytes past the header so Git's chunk-table parse fails rather than
    // its magic-number check, matching the "stale/corrupt commit-graph"
    // condition the 2026-08-08 incident hit on an actively-developed
    // repository.
    const bytes = await Deno.readFile(graphPath);
    for (let i = 20; i < Math.min(60, bytes.length); i++) bytes[i] = 0xff;
    // Git writes commit-graph files read-only; reopen for write explicitly.
    await Deno.chmod(graphPath, 0o644);
    await Deno.writeFile(graphPath, bytes);

    // Discriminating half: reproduce, against this exact corrupted file,
    // what an empirical run confirmed — `git -c core.commitGraph=true
    // rev-parse --verify HEAD^{commit}` (Git's default) exits 0 but writes
    // "error: improper chunk offset(s) ..." to stderr, while the same
    // command with `-c core.commitGraph=false` produces no stderr at all.
    // Without this half, a test that only checks certify()'s report proves
    // nothing: Git falls back and reports success either way, so a report
    // of `passed: true` cannot tell whether the flag reached Git.
    const withDefault = await new Deno.Command("git", {
      args: ["-c", "core.commitGraph=true", "rev-parse", "--verify", "HEAD^{commit}"],
      cwd,
      stdout: "piped",
      stderr: "piped",
    }).output();
    const withFlagDisabled = await new Deno.Command("git", {
      args: ["-c", "core.commitGraph=false", "rev-parse", "--verify", "HEAD^{commit}"],
      cwd,
      stdout: "piped",
      stderr: "piped",
    }).output();
    const defaultStderr = new TextDecoder().decode(withDefault.stderr);
    const disabledStderr = new TextDecoder().decode(withFlagDisabled.stderr);
    if (!defaultStderr.includes("improper chunk offset")) {
      throw new Error(
        "corrupted commit-graph fixture did not reproduce Git's stale-cache " +
          "error under the default configuration — the fixture is not " +
          "exercising what this test claims",
      );
    }
    assertEquals(disabledStderr, "");

    // Static half: pin that the model's own command() helper always passes
    // this exact flag on every Git invocation, not only in this test's
    // hand-rolled comparison above.
    const source = await Deno.readTextFile(
      new URL("./packet_certifier.ts", import.meta.url),
    );
    if (!source.includes('"core.commitGraph=false"')) {
      throw new Error(
        "packet_certifier.ts no longer passes -c core.commitGraph=false to Git",
      );
    }

    // Model-level half: certification against the same corrupted repository
    // still reports passed: true and the correct changed file.
    const h = harness();
    await snapshot(cwd, h);
    await Deno.writeTextFile(`${cwd}/README.md`, "changed\n");
    const report = await certify(cwd, h, ["README.md"]);
    assertEquals(report.passed, true);
    assertEquals(report.changedFiles.map((change) => change.path), [
      "README.md",
    ]);
  } finally {
    await Deno.remove(cwd, { recursive: true });
  }
});
