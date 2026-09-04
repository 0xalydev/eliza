/** Exact crash/replay and divergence proofs for the candidate record inbox. */

import { createHash, createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type {
  AgentBackupRestoreV3StagedRecord,
  AgentBackupRestoreV3StagingSession,
} from "@elizaos/shared";
import { afterEach, describe, expect, it } from "vitest";
import {
  AgentBackupRestoreV3CandidateFs,
  openAgentBackupRestoreV3CandidateFs,
} from "./agent-backup-restore-v3-candidate-fs";
import {
  AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES,
  AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_OWNER_CONTEXT,
  bindAgentBackupRestoreV3CandidateRecordSession,
  computeAgentBackupRestoreV3CandidateRecordCommandSha256,
  readAgentBackupRestoreV3CandidateRecord,
  stageAgentBackupRestoreV3CandidateRecord,
} from "./agent-backup-restore-v3-candidate-records";

const roots = new Set<string>();
const candidates = new Set<AgentBackupRestoreV3CandidateFs>();

function operationControl(signal = new AbortController().signal) {
  return {
    signal,
    deadlineEpochMs: Date.now() + 30_000,
  };
}

function platformTestOption() {
  return process.platform === "linux"
    ? {}
    : ({ testOnlyAllowNonLinuxFdEmulation: true as const } as const);
}

const SESSION = Object.freeze({
  restoreAttemptId: "10000000-0000-4000-8000-000000000001",
  operationId: "20000000-0000-4000-8000-000000000002",
  expectedManifestSha256: "a".repeat(64),
  stagingHandle: "30000000-0000-4000-8000-000000000003",
  cleanupHandle: "40000000-0000-4000-8000-000000000004",
  executionToken: "exact-record-execution-token",
  cleanupRegistered: true as const,
  isolatedCandidate: true as const,
}) satisfies AgentBackupRestoreV3StagingSession;

async function fixture(): Promise<{
  readonly candidateFs: AgentBackupRestoreV3CandidateFs;
  readonly attemptRoot: string;
}> {
  const root = await fs.mkdtemp(
    path.join(await fs.realpath(os.tmpdir()), "restore-v3-record-inbox-"),
  );
  roots.add(root);
  await fs.chmod(root, 0o700);
  const attemptRoot = path.join(root, "attempt");
  await fs.mkdir(attemptRoot, { mode: 0o700 });
  const candidateFs = await openAgentBackupRestoreV3CandidateFs({
    trustedRoot: root,
    attemptRoot,
    control: operationControl(),
    ...platformTestOption(),
  });
  candidates.add(candidateFs);
  return { candidateFs, attemptRoot };
}

function record(
  payload: Uint8Array | string,
  options: {
    readonly componentIndex?: number;
    readonly componentName?: "character" | "database";
    readonly dataIndex?: number;
    readonly offsetBytes?: number;
  } = {},
): AgentBackupRestoreV3StagedRecord {
  return {
    componentIndex: options.componentIndex ?? 0,
    componentName: options.componentName ?? "character",
    dataIndex: options.dataIndex ?? 0,
    offsetBytes: options.offsetBytes ?? 0,
    entry: null,
    payload:
      typeof payload === "string" ? new TextEncoder().encode(payload) : payload,
  };
}

async function exactFilesystemSnapshot(attemptRoot: string) {
  const names = (await fs.readdir(attemptRoot)).sort();
  return Promise.all(
    names.map(async (name) => {
      const filePath = path.join(attemptRoot, name);
      const stats = await fs.lstat(filePath, { bigint: true });
      const contentSha256 = stats.isFile()
        ? createHash("sha256")
            .update(await fs.readFile(filePath))
            .digest("hex")
        : null;
      return Object.freeze({
        name,
        device: stats.dev.toString(10),
        inode: stats.ino.toString(10),
        mode: stats.mode.toString(8),
        links: stats.nlink.toString(10),
        size: stats.size.toString(10),
        modifiedNanoseconds: stats.mtimeNs.toString(10),
        contentSha256,
      });
    }),
  );
}

afterEach(async () => {
  const pendingCandidates = [...candidates];
  candidates.clear();
  await Promise.all(
    pendingCandidates.map((candidateFs) => candidateFs.close()),
  );
  const pendingRoots = [...roots];
  roots.clear();
  await Promise.all(
    pendingRoots.map((root) => fs.rm(root, { recursive: true, force: true })),
  );
});

describe("restore-v3 candidate record inbox", () => {
  it("copies, stages, reads, and exactly replays one deterministic slot", async () => {
    const { candidateFs, attemptRoot } = await fixture();
    const mutable = new TextEncoder().encode("exact-record");
    const staged = record(mutable);
    const pending = stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: staged,
      control: operationControl(),
    });
    mutable.fill(0);
    const receipt = await pending;

    expect(receipt).toMatchObject({
      version: 1,
      payloadName: ".restore-v3-record-c0-d0.payload",
      record: {
        componentIndex: 0,
        componentName: "character",
        dataIndex: 0,
        offsetBytes: 0,
        payloadBytes: 12,
        payloadSha256: createHash("sha256")
          .update("exact-record")
          .digest("hex"),
      },
    });
    const ownerCapabilityHex = createHmac(
      "sha256",
      Buffer.from(SESSION.executionToken, "utf8"),
    )
      .update(AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_OWNER_CONTEXT, "utf8")
      .update(Buffer.of(0))
      .update(Buffer.from(receipt.commandSha256, "hex"))
      .digest("hex");
    const persistedText = Buffer.concat(
      await Promise.all(
        (await fs.readdir(attemptRoot)).map((name) =>
          fs.readFile(path.join(attemptRoot, name)),
        ),
      ),
    ).toString("utf8");
    expect(persistedText).not.toContain(SESSION.executionToken);
    expect(persistedText).not.toContain(ownerCapabilityHex);
    expect(
      computeAgentBackupRestoreV3CandidateRecordCommandSha256(
        SESSION,
        receipt.record,
        receipt.previousReceiptSha256,
      ),
    ).toBe(receipt.commandSha256);
    expect(
      computeAgentBackupRestoreV3CandidateRecordCommandSha256(
        SESSION,
        receipt.record,
        "0".repeat(64),
      ),
    ).not.toBe(receipt.commandSha256);

    const read = await readAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      componentIndex: 0,
      dataIndex: 0,
      control: operationControl(),
    });
    expect(read.receipt).toEqual(receipt);
    expect(Buffer.from(read.payload).toString("utf8")).toBe("exact-record");
    read.payload.fill(0);

    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record("exact-record"),
        control: operationControl(),
      }),
    ).resolves.toEqual(receipt);
  });

  it("keeps absent and stale reads strictly read-only", async () => {
    const { candidateFs, attemptRoot } = await fixture();
    const emptySnapshot = await exactFilesystemSnapshot(attemptRoot);
    await expect(
      readAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        componentIndex: 0,
        dataIndex: 0,
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_SESSION_ABSENT",
    });
    await expect(exactFilesystemSnapshot(attemptRoot)).resolves.toEqual(
      emptySnapshot,
    );

    await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record("bound"),
      control: operationControl(),
    });
    const durableSnapshot = await exactFilesystemSnapshot(attemptRoot);
    await expect(
      readAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: { ...SESSION, executionToken: "stale-execution-token" },
        componentIndex: 0,
        dataIndex: 0,
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_SESSION_CONFLICT",
    });
    await expect(
      readAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        componentIndex: 0,
        dataIndex: 1,
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_ABSENT",
    });
    await expect(exactFilesystemSnapshot(attemptRoot)).resolves.toEqual(
      durableSnapshot,
    );
  });

  it("chains only contiguous component-local record slots", async () => {
    const { candidateFs } = await fixture();
    const first = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record("abc"),
      control: operationControl(),
    });
    const second = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record("defg", { dataIndex: 1, offsetBytes: 3 }),
      control: operationControl(),
    });
    expect(second.previousReceiptSha256).toBe(first.receiptSha256);

    const empty = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record(new Uint8Array(0), {
        componentIndex: 1,
        componentName: "database",
      }),
      control: operationControl(),
    });
    expect(empty.record.payloadBytes).toBe(0);
    const emptyRead = await readAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      componentIndex: 1,
      dataIndex: 0,
      control: operationControl(),
    });
    expect(emptyRead.payload).toHaveLength(0);

    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record("gap", {
          componentIndex: 1,
          componentName: "database",
          dataIndex: 1,
          offsetBytes: 3,
        }),
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CHAIN_CONFLICT",
    });
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record("different"),
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_CONFLICT",
    });
  });

  it("repairs a crash after payload proof and replays a lost durable response", async () => {
    const { candidateFs } = await fixture();
    let crashOnce = true;
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record("first"),
        control: operationControl(),
        testOnlyLifecycle: {
          afterPayloadFinalized() {
            if (crashOnce) {
              crashOnce = false;
              throw new Error("simulated crash after payload proof");
            }
          },
        },
      }),
    ).rejects.toThrow("simulated crash after payload proof");
    const recovered = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record("first"),
      control: operationControl(),
    });

    let loseOnce = true;
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record("second", { dataIndex: 1, offsetBytes: 5 }),
        control: operationControl(),
        testOnlyLifecycle: {
          afterDurableReceipt() {
            if (loseOnce) {
              loseOnce = false;
              throw new Error("simulated lost durable response");
            }
          },
        },
      }),
    ).rejects.toThrow("simulated lost durable response");
    const replayed = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record("second", { dataIndex: 1, offsetBytes: 5 }),
      control: operationControl(),
    });
    expect(replayed.previousReceiptSha256).toBe(recovered.receiptSha256);
  });

  it("rejects hung or mutating test hooks and always releases flock", async () => {
    const hungCase = await fixture();
    const hung = new Promise<void>(() => undefined);
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: hungCase.candidateFs,
        session: SESSION,
        record: record("hung"),
        control: operationControl(),
        testOnlyLifecycle: {
          afterPayloadFinalized: (() => hung) as unknown as () => void,
        },
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_TEST_HOOK_ASYNC",
    });
    const recoveredLock = await hungCase.candidateFs.acquireLock(
      "after-hung-hook.lock",
      operationControl(),
    );
    await recoveredLock.release(operationControl());

    const synchronousMutationCase = await fixture();
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: synchronousMutationCase.candidateFs,
        session: SESSION,
        record: record("exact"),
        control: operationControl(),
        testOnlyLifecycle: {
          afterPayloadFinalized() {
            writeFileSync(
              path.join(
                synchronousMutationCase.attemptRoot,
                ".restore-v3-record-c0-d0.payload",
              ),
              "other",
            );
          },
        },
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FS_PAYLOAD_CONFLICT",
    });
    const mutationLock = await synchronousMutationCase.candidateFs.acquireLock(
      "after-mutating-hook.lock",
      operationControl(),
    );
    await mutationLock.release(operationControl());

    const lateMutationCase = await fixture();
    let lateMutation: Promise<void> | undefined;
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: lateMutationCase.candidateFs,
        session: SESSION,
        record: record("later"),
        control: operationControl(),
        testOnlyLifecycle: {
          afterPayloadFinalized: (() => {
            lateMutation = new Promise((resolve) => {
              setTimeout(() => {
                writeFileSync(
                  path.join(
                    lateMutationCase.attemptRoot,
                    ".restore-v3-record-c0-d0.payload",
                  ),
                  "after",
                );
                resolve();
              }, 10);
            });
            return lateMutation;
          }) as unknown as () => void,
        },
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_TEST_HOOK_ASYNC",
    });
    await lateMutation;
    const lateLock = await lateMutationCase.candidateFs.acquireLock(
      "after-late-hook.lock",
      operationControl(),
    );
    await lateLock.release(operationControl());
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: lateMutationCase.candidateFs,
        session: SESSION,
        record: record("later"),
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FS_PAYLOAD_CONFLICT",
    });

    const finalReceiptCase = await fixture();
    await expect(
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: finalReceiptCase.candidateFs,
        session: SESSION,
        record: record("receipt"),
        control: operationControl(),
        testOnlyLifecycle: {
          afterDurableReceipt() {
            writeFileSync(
              path.join(
                finalReceiptCase.attemptRoot,
                ".restore-v3-record-c0-d0.receipt.json",
              ),
              "{}\n",
            );
          },
        },
      }),
    ).rejects.toBeInstanceOf(Error);
    const finalReceiptLock = await finalReceiptCase.candidateFs.acquireLock(
      "after-final-receipt-hook.lock",
      operationControl(),
    );
    await finalReceiptLock.release(operationControl());
  });

  it("fails closed on session, owner-journal, and payload divergence", async () => {
    const sessionCase = await fixture();
    await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs: sessionCase.candidateFs,
      session: SESSION,
      record: record("session"),
      control: operationControl(),
    });
    await expect(
      readAgentBackupRestoreV3CandidateRecord({
        candidateFs: sessionCase.candidateFs,
        session: { ...SESSION, executionToken: "another-execution-token" },
        componentIndex: 0,
        dataIndex: 0,
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_SESSION_CONFLICT",
    });

    const ownerCase = await fixture();
    const ownerReceipt = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs: ownerCase.candidateFs,
      session: SESSION,
      record: record("owner"),
      control: operationControl(),
    });
    const payloadDerivation = createHash("sha256")
      .update(ownerReceipt.payloadName)
      .digest("hex")
      .slice(0, 32);
    const ownerJournalPath = path.join(
      ownerCase.attemptRoot,
      `.payload-${payloadDerivation}.owner.json`,
    );
    const ownerJournal = JSON.parse(
      await fs.readFile(ownerJournalPath, "utf8"),
    );
    await fs.writeFile(
      ownerJournalPath,
      `${JSON.stringify({
        maximumBytes: ownerJournal.maximumBytes,
        name: ownerJournal.name,
        ownerTokenSha256: "0".repeat(64),
        version: ownerJournal.version,
      })}\n`,
    );
    await expect(
      readAgentBackupRestoreV3CandidateRecord({
        candidateFs: ownerCase.candidateFs,
        session: SESSION,
        componentIndex: 0,
        dataIndex: 0,
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FS_OWNER_CONFLICT",
    });

    const payloadCase = await fixture();
    const payloadReceipt = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs: payloadCase.candidateFs,
      session: SESSION,
      record: record("bytes"),
      control: operationControl(),
    });
    await fs.writeFile(
      path.join(payloadCase.attemptRoot, payloadReceipt.payloadName),
      "other",
    );
    await expect(
      readAgentBackupRestoreV3CandidateRecord({
        candidateFs: payloadCase.candidateFs,
        session: SESSION,
        componentIndex: 0,
        dataIndex: 0,
        control: operationControl(),
      }),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FS_PAYLOAD_CONFLICT",
    });
  });

  it("snapshots only intrinsic bounded UintArrays without invoking iterators", async () => {
    const { candidateFs } = await fixture();
    const proxied = new Proxy(new Uint8Array([1, 2, 3]), {
      get() {
        throw new Error("proxy trap must not run");
      },
    });
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record(proxied),
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
      }),
    );

    class PayloadSubclass extends Uint8Array {}
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record(new PayloadSubclass([1, 2, 3])),
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
      }),
    );

    let iteratorCalls = 0;
    const customIterator = new Uint8Array([1, 2, 3]);
    Object.defineProperty(customIterator, Symbol.iterator, {
      value() {
        iteratorCalls += 1;
        throw new Error("custom iterator must not run");
      },
    });
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record(customIterator),
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
      }),
    );
    expect(iteratorCalls).toBe(0);

    const boundary = new Uint8Array(
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES,
    );
    boundary.fill(0x5a);
    const boundaryReceipt = await stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record(boundary),
      control: operationControl(),
    });
    expect(boundaryReceipt.record.payloadBytes).toBe(
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES,
    );
    const boundaryRead = await readAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      componentIndex: 0,
      dataIndex: 0,
      control: operationControl(),
    });
    expect(boundaryRead.payload).toHaveLength(
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES,
    );
    boundaryRead.payload.fill(0);

    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record(new Uint8Array([1])),
        control: {
          signal: new AbortController().signal,
          deadlineEpochMs: Date.now() - 1,
        },
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_DEADLINE_EXCEEDED",
      }),
    );

    if (typeof SharedArrayBuffer === "function") {
      expect(() =>
        stageAgentBackupRestoreV3CandidateRecord({
          candidateFs,
          session: SESSION,
          record: record(new Uint8Array(new SharedArrayBuffer(32))),
          control: operationControl(),
        }),
      ).toThrowError(
        expect.objectContaining({
          code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
        }),
      );
    }
  });

  it("rejects public-boundary proxies and accessors without invoking them", async () => {
    const { candidateFs } = await fixture();
    let trapCalls = 0;
    const failTrap = () => {
      trapCalls += 1;
      throw new Error("untrusted trap must not run");
    };
    const proxiedSession = new Proxy(
      { ...SESSION },
      {
        get: failTrap,
        getPrototypeOf: failTrap,
        ownKeys: failTrap,
      },
    );
    const proxiedStageInput = new Proxy(
      {
        candidateFs,
        session: SESSION,
        record: record("proxy-stage-input"),
        control: operationControl(),
      },
      {
        get: failTrap,
        getPrototypeOf: failTrap,
        ownKeys: failTrap,
      },
    );
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord(proxiedStageInput),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );

    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: proxiedSession,
        record: record("proxy-session"),
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );

    const proxiedCandidateFs = new Proxy(candidateFs, {
      get: failTrap,
      getPrototypeOf: failTrap,
    });
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: proxiedCandidateFs,
        session: SESSION,
        record: record("proxy-candidate-fs"),
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );

    const forgedCandidateFs = {
      acquireLock: failTrap,
      createPayload: failTrap,
      publishDurableJson: failTrap,
      readDurableJson: failTrap,
      readPayload: failTrap,
      assertAuthority: failTrap,
      assertLockHeld: failTrap,
    };
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: forgedCandidateFs,
        session: SESSION,
        record: record("forged-candidate-fs"),
        control: operationControl(),
      } as never),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );

    await expect(
      bindAgentBackupRestoreV3CandidateRecordSession({
        candidateFs,
        session: SESSION,
        control: operationControl(),
        heldLock: null,
      } as never),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
    });

    const proxiedHeldLock = new Proxy(
      {},
      {
        get: failTrap,
        getPrototypeOf: failTrap,
        ownKeys: failTrap,
      },
    );
    await expect(
      readAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        componentIndex: 0,
        dataIndex: 0,
        control: operationControl(),
        heldLock: proxiedHeldLock,
      } as never),
    ).rejects.toMatchObject({
      code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
    });

    const forgedBrandedPrototype = Object.create(
      AgentBackupRestoreV3CandidateFs.prototype,
    ) as Record<string, unknown>;
    Object.defineProperty(forgedBrandedPrototype, "acquireLock", {
      value: failTrap,
    });
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs: forgedBrandedPrototype,
        session: SESSION,
        record: record("forged-candidate-fs-prototype"),
        control: operationControl(),
      } as never),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );
    expect(Object.isFrozen(candidateFs)).toBe(true);
    expect(Object.isFrozen(AgentBackupRestoreV3CandidateFs.prototype)).toBe(
      true,
    );

    const revokedControl = Proxy.revocable(operationControl(), {});
    revokedControl.revoke();
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record("proxy-control"),
        control: revokedControl.proxy,
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CONTROL_INVALID",
      }),
    );

    const lifecycle = {} as Record<string, unknown>;
    Object.defineProperty(lifecycle, "afterPayloadFinalized", {
      enumerable: true,
      get: failTrap,
    });
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record("accessor-lifecycle"),
        control: operationControl(),
        testOnlyLifecycle: lifecycle,
      } as never),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );

    const receipt = {
      componentIndex: 0,
      componentName: "character",
      dataIndex: 0,
      offsetBytes: 0,
      entry: null,
      payloadBytes: 1,
    } as Record<string, unknown>;
    Object.defineProperty(receipt, "payloadSha256", {
      enumerable: true,
      get: failTrap,
    });
    expect(() =>
      computeAgentBackupRestoreV3CandidateRecordCommandSha256(
        SESSION,
        receipt as never,
        "0".repeat(64),
      ),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );
    expect(trapCalls).toBe(0);
  });

  it("snapshots read slots and operation control before the first await", async () => {
    const { candidateFs } = await fixture();
    const stageControl = operationControl();
    const pendingStage = stageAgentBackupRestoreV3CandidateRecord({
      candidateFs,
      session: SESSION,
      record: record("stable-after-call"),
      control: stageControl,
    });
    stageControl.deadlineEpochMs = Date.now() - 1;
    await expect(pendingStage).resolves.toMatchObject({
      record: { componentIndex: 0, dataIndex: 0 },
    });

    const readControl = operationControl();
    const readInput = {
      candidateFs,
      session: SESSION,
      componentIndex: 0,
      dataIndex: 0,
      control: readControl,
    };
    const pendingRead = readAgentBackupRestoreV3CandidateRecord(readInput);
    readInput.componentIndex = 1;
    readInput.dataIndex = 9;
    readControl.deadlineEpochMs = Date.now() - 1;
    const exactRead = await pendingRead;
    expect(exactRead.receipt.record).toMatchObject({
      componentIndex: 0,
      dataIndex: 0,
    });
    expect(Buffer.from(exactRead.payload).toString("utf8")).toBe(
      "stable-after-call",
    );
    exactRead.payload.fill(0);
  });

  it("refuses test hooks in production before creating durable state", async () => {
    const { candidateFs, attemptRoot } = await fixture();
    const before = await exactFilesystemSnapshot(attemptRoot);
    const previousNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      expect(() =>
        stageAgentBackupRestoreV3CandidateRecord({
          candidateFs,
          session: SESSION,
          record: record("forbidden-production-hook"),
          control: operationControl(),
          testOnlyLifecycle: { afterPayloadFinalized: () => undefined },
        }),
      ).toThrowError(
        expect.objectContaining({
          code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_TEST_HOOK_FORBIDDEN",
        }),
      );
    } finally {
      if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousNodeEnv;
    }
    await expect(exactFilesystemSnapshot(attemptRoot)).resolves.toEqual(before);
  });

  it("rejects oversized, accessor-backed, and mismatched component inputs", async () => {
    const { candidateFs } = await fixture();
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: record(
          new Uint8Array(
            AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES + 1,
          ),
        ),
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
      }),
    );

    const hidden = record("hidden") as unknown as Record<string, unknown>;
    Object.defineProperty(hidden, "hidden", { value: true });
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: hidden as unknown as AgentBackupRestoreV3StagedRecord,
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );

    const accessor = record("accessor") as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "payload", {
      enumerable: true,
      get: () => Buffer.from("accessor"),
    });
    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: accessor as unknown as AgentBackupRestoreV3StagedRecord,
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );

    expect(() =>
      stageAgentBackupRestoreV3CandidateRecord({
        candidateFs,
        session: SESSION,
        record: {
          ...record("wrong-name"),
          componentIndex: 1,
          componentName: "character",
        },
        control: operationControl(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      }),
    );
  });
});
