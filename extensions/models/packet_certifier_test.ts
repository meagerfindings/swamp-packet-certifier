import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.14";
import { model } from "./packet_certifier.ts";

type Snapshot = {
  hashVersion: "packet-certifier-v6";
  packetId: string;
  invocationId: string;
  resolvedBaseSha: string;
  objectFormat: "sha1" | "sha256";
  rootBinding: string;
  fileCount: number;
  stateHash: string;
  ignoredScope?: "application-owned-v1";
  excludedIgnoredPathPrefixes: string[];
  capturedAt: string;
};

type Report = {
  passed: boolean;
  rootBinding: string;
  worktreeStateHash: string;
  changedFiles: Array<{
    path: string;
    added: number;
    removed: number;
    binary: boolean;
  }>;
  ignoredPathViolations: string[];
  budgetViolations: { maxChangedLines: boolean; binaryFiles: string[] };
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
      { cwd, packetId, invocationId, baseRef: "HEAD" },
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
  if (
    ![...h.store.values()].some((value) =>
      value.packetId === packetId && value.invocationId === invocationId
    )
  ) {
    await snapshot(cwd, h, packetId, invocationId);
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
      "indexed symlink or gitlink",
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

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}
