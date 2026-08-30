/** Exact materializer for authenticated restore-v3 file-set record inboxes. */

import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";
import { ElizaError } from "@elizaos/core";
import {
  AGENT_BACKUP_CAPTURE_V2_LIMITS,
  AGENT_BACKUP_RESTORE_V3_COMPONENT_DESCRIPTORS,
  type AgentBackupRestoreV3ComponentReceipt,
  AgentBackupRestoreV3ComponentReceiptSchema,
  type AgentBackupRestoreV3OperationControl,
  type AgentBackupRestoreV3StagingSession,
  type AgentBackupRestoreV3StreamComponentName,
  compareAgentBackupCaptureV2FilePaths,
} from "@elizaos/shared";
import {
  AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS,
  type AgentBackupRestoreV3CandidateFileTreeFileProof,
  type AgentBackupRestoreV3CandidateFileTreeLimits,
  type AgentBackupRestoreV3CandidateFileTreeProof,
  type AgentBackupRestoreV3CandidateFileTreeWriter,
  type AgentBackupRestoreV3CandidateFs,
  type AgentBackupRestoreV3CandidateFsLock,
} from "./agent-backup-restore-v3-candidate-fs";
import { candidateFsCanonicalJson } from "./agent-backup-restore-v3-candidate-fs-json";
import {
  AgentBackupRestoreV3CandidateRecordError,
  type AgentBackupRestoreV3CandidateRecordReceipt,
  bindAgentBackupRestoreV3CandidateRecordSession,
  computeAgentBackupRestoreV3CandidateSessionSha256,
  readAgentBackupRestoreV3CandidateRecord,
  snapshotAgentBackupRestoreV3CandidateSession,
} from "./agent-backup-restore-v3-candidate-records";

const FILE_SET_FORMAT = "elizaos.agent-backup.restore-v3-candidate-file-set.v1";
const FILE_SET_COMPONENTS = Object.freeze({
  media: Object.freeze({ index: 2, directory: "components/media" }),
  "state-files": Object.freeze({
    index: 3,
    directory: "components/state-files",
  }),
  vault: Object.freeze({ index: 4, directory: "components/vault" }),
} as const);
const EMPTY_SHA256 = createHash("sha256").digest("hex");
const FINISH_MAXIMUM_BYTES = 32 * 1024;

export type AgentBackupRestoreV3CandidateFileSetComponentName = Extract<
  AgentBackupRestoreV3StreamComponentName,
  "media" | "state-files" | "vault"
>;

export interface AgentBackupRestoreV3CandidateFileSetLifecycle {
  readonly afterRecordConsumed?: (
    receipt: Readonly<AgentBackupRestoreV3CandidateRecordReceipt>,
  ) => void;
  readonly afterFilePublished?: (
    proof: Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>,
  ) => void;
  readonly afterDurableFinish?: (
    receipt: Readonly<AgentBackupRestoreV3CandidateFileSetReceipt>,
  ) => void;
}

export interface MaterializeAgentBackupRestoreV3CandidateFileSetInput {
  readonly candidateFs: AgentBackupRestoreV3CandidateFs;
  readonly session: Readonly<AgentBackupRestoreV3StagingSession>;
  readonly receipt: Readonly<AgentBackupRestoreV3ComponentReceipt>;
  readonly control: Readonly<AgentBackupRestoreV3OperationControl>;
  readonly limits?: Partial<AgentBackupRestoreV3CandidateFileTreeLimits>;
  readonly testOnlyLifecycle?: Readonly<AgentBackupRestoreV3CandidateFileSetLifecycle>;
}

export interface AgentBackupRestoreV3CandidateFileSetReceipt {
  readonly version: 1;
  readonly format: typeof FILE_SET_FORMAT;
  readonly sessionSha256: string;
  readonly component: Readonly<AgentBackupRestoreV3ComponentReceipt>;
  readonly outputDirectory: string;
  readonly lastRecordReceiptSha256: string | null;
  readonly tree: Readonly<AgentBackupRestoreV3CandidateFileTreeProof>;
  readonly finishSha256: string;
}

interface CandidateFileSetDurableFinishMarker {
  readonly version: 1;
  readonly format: typeof FILE_SET_FORMAT;
  readonly sessionSha256: string;
  readonly componentSha256: string;
  readonly outputDirectory: string;
  readonly lastRecordReceiptSha256: string | null;
  readonly treeDerivation: string;
  readonly treeDevice: string;
  readonly treeInode: string;
  readonly treeSha256: string;
  readonly treeBytes: number;
  readonly treeFiles: number;
  readonly treeDirectories: number;
  readonly finishSha256: string;
}

export class AgentBackupRestoreV3CandidateFileSetError extends ElizaError {
  override readonly name = "AgentBackupRestoreV3CandidateFileSetError";

  constructor(code: string, message: string, cause?: unknown) {
    super(message, {
      code,
      severity: "fatal",
      ...(cause === undefined ? {} : { cause }),
    });
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

function fileSetError(code: string, message: string, cause?: unknown): never {
  throw new AgentBackupRestoreV3CandidateFileSetError(code, message, cause);
}

function invokeTestOnlyHook<T>(
  hook: ((value: T) => void) | undefined,
  value: T,
  label: string,
): void {
  if (!hook) return;
  if (process.env.NODE_ENV !== "test") {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_TEST_HOOK_FORBIDDEN",
      "Candidate file-set lifecycle hooks are test-only",
    );
  }
  const returned = (hook as (value: T) => unknown)(value);
  if (returned !== undefined) {
    if (returned instanceof Promise) void returned.catch(() => undefined);
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_TEST_HOOK_ASYNC",
      `${label} test hook must settle synchronously`,
    );
  }
}

function exactPlainObject(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    isProxy(value) ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== keys.length ||
    Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")
  ) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_INPUT_INVALID",
      `${label} must be one exact plain data object`,
    );
  }
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      fileSetError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_INPUT_INVALID",
        `${label} cannot contain accessors or hidden fields`,
      );
    }
  }
  return record;
}

function snapshotLimits(
  value: Partial<AgentBackupRestoreV3CandidateFileTreeLimits> | undefined,
): Readonly<AgentBackupRestoreV3CandidateFileTreeLimits> {
  if (value !== undefined) {
    if (
      !value ||
      typeof value !== "object" ||
      isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      fileSetError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT_INVALID",
        "Candidate file-set limits must be one exact plain data object",
      );
    }
    const allowed = new Set([
      "maximumBytes",
      "maximumFiles",
      "maximumDirectories",
      "maximumDepth",
      "maximumPathBytes",
    ]);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || !allowed.has(key)) {
        fileSetError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT_INVALID",
          "Candidate file-set limits contain an unknown field",
        );
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        fileSetError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT_INVALID",
          "Candidate file-set limits contain an accessor or hidden field",
        );
      }
    }
  }
  const resolved = Object.freeze({
    maximumBytes:
      value?.maximumBytes ??
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumBytes,
    maximumFiles:
      value?.maximumFiles ??
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumFiles,
    maximumDirectories:
      value?.maximumDirectories ??
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumDirectories,
    maximumDepth:
      value?.maximumDepth ??
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumDepth,
    maximumPathBytes:
      value?.maximumPathBytes ??
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumPathBytes,
  });
  for (const key of Object.keys(resolved) as Array<keyof typeof resolved>) {
    const limit = resolved[key];
    const maximum = AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS[key];
    if (
      !Number.isSafeInteger(limit) ||
      limit <= 0 ||
      Object.is(limit, -0) ||
      limit > maximum
    ) {
      fileSetError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT_INVALID",
        `Candidate file-set ${key} is outside its supported range`,
      );
    }
  }
  return resolved;
}

function snapshotReceipt(
  value: Readonly<AgentBackupRestoreV3ComponentReceipt>,
): Readonly<AgentBackupRestoreV3ComponentReceipt> {
  const record = exactPlainObject(
    value,
    [
      "componentIndex",
      "componentName",
      "descriptor",
      "dataFrameCount",
      "payloadBytes",
      "payloadSha256",
      "recordStreamContentHmacSha256",
    ],
    "Candidate file-set component receipt",
  );
  const descriptor = exactPlainObject(
    record.descriptor,
    ["name", "format", "compression", "contentKind", "consistency"],
    "Candidate file-set descriptor",
  );
  let parsed: AgentBackupRestoreV3ComponentReceipt;
  try {
    parsed = AgentBackupRestoreV3ComponentReceiptSchema.parse({
      componentIndex: record.componentIndex,
      componentName: record.componentName,
      descriptor: {
        name: descriptor.name,
        format: descriptor.format,
        compression: descriptor.compression,
        contentKind: descriptor.contentKind,
        consistency: descriptor.consistency,
      },
      dataFrameCount: record.dataFrameCount,
      payloadBytes: record.payloadBytes,
      payloadSha256: record.payloadSha256,
      recordStreamContentHmacSha256: record.recordStreamContentHmacSha256,
    });
  } catch (cause) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_INPUT_INVALID",
      "Candidate file-set component receipt is not canonical",
      cause,
    );
  }
  const policy =
    FILE_SET_COMPONENTS[
      parsed.componentName as AgentBackupRestoreV3CandidateFileSetComponentName
    ];
  const expectedDescriptor =
    AGENT_BACKUP_RESTORE_V3_COMPONENT_DESCRIPTORS[parsed.componentIndex];
  if (
    !policy ||
    policy.index !== parsed.componentIndex ||
    !expectedDescriptor ||
    candidateFsCanonicalJson(parsed.descriptor) !==
      candidateFsCanonicalJson(expectedDescriptor)
  ) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_COMPONENT_INVALID",
      "Candidate file-set receipt is not one exact media/state-files/vault component",
    );
  }
  return Object.freeze({
    ...parsed,
    descriptor: Object.freeze({ ...parsed.descriptor }),
  });
}

function finishMarkerName(componentIndex: number): string {
  return `.restore-v3-component-c${componentIndex}.file-set.finish.json`;
}

function finishDigestBody(
  sessionSha256: string,
  component: Readonly<AgentBackupRestoreV3ComponentReceipt>,
  outputDirectory: string,
  lastRecordReceiptSha256: string | null,
  tree: Readonly<AgentBackupRestoreV3CandidateFileTreeProof>,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    version: 1 as const,
    format: FILE_SET_FORMAT,
    sessionSha256,
    component,
    outputDirectory,
    lastRecordReceiptSha256,
    tree: Object.freeze({
      derivation: tree.derivation,
      device: tree.device,
      inode: tree.inode,
      sha256: tree.sha256,
      bytes: tree.bytes,
      files: tree.files,
      directories: tree.directories,
    }),
  });
}

function buildFinishReceipt(
  sessionSha256: string,
  component: Readonly<AgentBackupRestoreV3ComponentReceipt>,
  outputDirectory: string,
  lastRecordReceiptSha256: string | null,
  tree: Readonly<AgentBackupRestoreV3CandidateFileTreeProof>,
): Readonly<AgentBackupRestoreV3CandidateFileSetReceipt> {
  const digestBody = finishDigestBody(
    sessionSha256,
    component,
    outputDirectory,
    lastRecordReceiptSha256,
    tree,
  );
  return Object.freeze({
    version: 1 as const,
    format: FILE_SET_FORMAT,
    sessionSha256,
    component,
    outputDirectory,
    lastRecordReceiptSha256,
    tree,
    finishSha256: createHash("sha256")
      .update(candidateFsCanonicalJson(digestBody), "utf8")
      .digest("hex"),
  });
}

function durableFinishMarker(
  receipt: Readonly<AgentBackupRestoreV3CandidateFileSetReceipt>,
): Readonly<CandidateFileSetDurableFinishMarker> {
  return Object.freeze({
    version: 1 as const,
    format: FILE_SET_FORMAT,
    sessionSha256: receipt.sessionSha256,
    componentSha256: createHash("sha256")
      .update(candidateFsCanonicalJson(receipt.component), "utf8")
      .digest("hex"),
    outputDirectory: receipt.outputDirectory,
    lastRecordReceiptSha256: receipt.lastRecordReceiptSha256,
    treeDerivation: receipt.tree.derivation,
    treeDevice: receipt.tree.device,
    treeInode: receipt.tree.inode,
    treeSha256: receipt.tree.sha256,
    treeBytes: receipt.tree.bytes,
    treeFiles: receipt.tree.files,
    treeDirectories: receipt.tree.directories,
    finishSha256: receipt.finishSha256,
  });
}

async function requireNoAdditionalRecord(
  input: MaterializeAgentBackupRestoreV3CandidateFileSetInput,
  component: Readonly<AgentBackupRestoreV3ComponentReceipt>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<void> {
  try {
    const unexpected = await readAgentBackupRestoreV3CandidateRecord({
      candidateFs: input.candidateFs,
      session: input.session,
      componentIndex: component.componentIndex,
      dataIndex: component.dataFrameCount,
      control: input.control,
      heldLock: lock,
    });
    unexpected.payload.fill(0);
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_RECORD_COUNT_MISMATCH",
      "Candidate file-set inbox contains a record beyond its authenticated finish",
    );
  } catch (cause) {
    if (
      cause instanceof AgentBackupRestoreV3CandidateRecordError &&
      cause.code === "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_ABSENT"
    ) {
      return;
    }
    throw cause;
  }
}

async function validatePersistedFinish(
  input: MaterializeAgentBackupRestoreV3CandidateFileSetInput,
  expected: Readonly<AgentBackupRestoreV3CandidateFileSetReceipt>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<Readonly<AgentBackupRestoreV3CandidateFileSetReceipt>> {
  const persisted = await input.candidateFs.readDurableJson(
    finishMarkerName(expected.component.componentIndex),
    { maximumBytes: FINISH_MAXIMUM_BYTES },
    input.control,
    lock,
  );
  const marker = durableFinishMarker(expected);
  if (
    persisted === null ||
    candidateFsCanonicalJson(persisted) !== candidateFsCanonicalJson(marker)
  ) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_FINISH_CONFLICT",
      "Candidate file-set finish marker differs from the exact replay",
    );
  }
  const proved = await input.candidateFs.proveFileTree(
    expected.outputDirectory,
    expected.tree.entries,
    input.limits,
    input.control,
    lock,
  );
  if (
    proved.derivation !== expected.tree.derivation ||
    proved.device !== expected.tree.device ||
    proved.inode !== expected.tree.inode ||
    proved.sha256 !== expected.tree.sha256 ||
    proved.bytes !== expected.tree.bytes ||
    proved.files !== expected.tree.files ||
    proved.directories !== expected.tree.directories
  ) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_TREE_CONFLICT",
      "Candidate file-set changed after its durable finish",
    );
  }
  return expected;
}

async function materializeCopiedFileSet(
  input: MaterializeAgentBackupRestoreV3CandidateFileSetInput,
  component: Readonly<AgentBackupRestoreV3ComponentReceipt>,
): Promise<Readonly<AgentBackupRestoreV3CandidateFileSetReceipt>> {
  const limits = snapshotLimits(input.limits);
  const policy =
    FILE_SET_COMPONENTS[
      component.componentName as AgentBackupRestoreV3CandidateFileSetComponentName
    ];
  if (!policy) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_COMPONENT_INVALID",
      "Candidate file-set policy is unavailable",
    );
  }
  if (
    component.dataFrameCount > AGENT_BACKUP_CAPTURE_V2_LIMITS.maxDataFrames ||
    component.payloadBytes > limits.maximumBytes ||
    (component.dataFrameCount === 0 &&
      (component.payloadBytes !== 0 ||
        component.payloadSha256 !== EMPTY_SHA256))
  ) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT",
      "Candidate file-set receipt exceeds its authenticated bounds or has an inexact empty proof",
    );
  }

  const sessionSha256 = computeAgentBackupRestoreV3CandidateSessionSha256(
    input.session,
  );
  const componentHash = createHash("sha256");
  const proofs: AgentBackupRestoreV3CandidateFileTreeFileProof[] = [];
  const normalizedPaths = new Set<string>();
  const directoryPaths = new Set<string>();
  let bytes = 0;
  let lastPath: string | null = null;
  let currentSpec: Readonly<{
    path: string;
    sizeBytes: number;
    mode: number;
    mtimeMs: number;
  }> | null = null;
  let currentOffset = 0;
  let currentRecords = 0;
  let currentHash: ReturnType<typeof createHash> | null = null;
  let writer: AgentBackupRestoreV3CandidateFileTreeWriter | null = null;
  let lastRecordReceiptSha256: string | null = null;
  let lock: AgentBackupRestoreV3CandidateFsLock | null = null;
  let result: Readonly<AgentBackupRestoreV3CandidateFileSetReceipt> | null =
    null;
  let primaryFailure: unknown;

  const finalizeFile = async (): Promise<void> => {
    if (!currentSpec || !currentHash || !writer) return;
    if (currentOffset !== currentSpec.sizeBytes) {
      fileSetError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_FILE_TRUNCATED",
        "Candidate file-set file ended before its declared size",
      );
    }
    const expectedSha256 = currentHash.digest("hex");
    currentHash = null;
    const proof = await writer.finalize(input.control);
    writer = null;
    if (proof.sha256 !== expectedSha256) {
      fileSetError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_FILE_CONFLICT",
        "Candidate file differs from the exact inbox bytes",
      );
    }
    proofs.push(proof);
    invokeTestOnlyHook(
      input.testOnlyLifecycle?.afterFilePublished,
      proof,
      "afterFilePublished",
    );
    currentSpec = null;
    currentOffset = 0;
    currentRecords = 0;
  };

  try {
    lock = await input.candidateFs.acquireLock(
      `.restore-v3-materialize-c${component.componentIndex}.lock`,
      input.control,
    );
    const boundSessionSha256 =
      await bindAgentBackupRestoreV3CandidateRecordSession({
        candidateFs: input.candidateFs,
        session: input.session,
        control: input.control,
        heldLock: lock,
      });
    if (boundSessionSha256 !== sessionSha256) {
      fileSetError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_SESSION_CONFLICT",
        "Candidate file-set session differs from its exact inbox binding",
      );
    }
    await input.candidateFs.ensureFileTreeDirectory(
      policy.directory,
      input.control,
      lock,
    );
    for (
      let dataIndex = 0;
      dataIndex < component.dataFrameCount;
      dataIndex += 1
    ) {
      const inbox = await readAgentBackupRestoreV3CandidateRecord({
        candidateFs: input.candidateFs,
        session: input.session,
        componentIndex: component.componentIndex,
        dataIndex,
        control: input.control,
        heldLock: lock,
      });
      try {
        const record = inbox.receipt.record;
        const entry = record.entry;
        if (
          record.componentIndex !== component.componentIndex ||
          record.componentName !== component.componentName ||
          record.dataIndex !== dataIndex ||
          record.offsetBytes !== bytes ||
          record.payloadBytes !== inbox.payload.byteLength ||
          !entry
        ) {
          fileSetError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_RECORD_INVALID",
            "Candidate file-set record is missing exact contiguous metadata",
          );
        }
        if (!currentSpec || currentSpec.path !== entry.path) {
          await finalizeFile();
          if (
            lastPath !== null &&
            compareAgentBackupCaptureV2FilePaths(entry.path, lastPath) <= 0
          ) {
            fileSetError(
              "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_PATH_ORDER_INVALID",
              "Candidate file-set paths must be unique in unsigned UTF-8 order",
            );
          }
          const normalizedPath = entry.path.normalize("NFC");
          if (normalizedPaths.has(normalizedPath)) {
            fileSetError(
              "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_PATH_DUPLICATE",
              "Candidate file-set contains canonically equivalent Unicode paths",
            );
          }
          normalizedPaths.add(normalizedPath);
          if (entry.fileOffsetBytes !== 0) {
            fileSetError(
              "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_OFFSET_INVALID",
              "Candidate file-set file must begin at offset zero",
            );
          }
          if (proofs.length >= limits.maximumFiles) {
            fileSetError(
              "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT",
              "Candidate file-set exceeds its file-count bound",
            );
          }
          const segments = entry.path.split("/");
          const newDirectoryPaths: string[] = [];
          let directoryPath = "";
          for (let index = 0; index < segments.length - 1; index += 1) {
            directoryPath = directoryPath
              ? `${directoryPath}/${segments[index] as string}`
              : (segments[index] as string);
            if (!directoryPaths.has(directoryPath)) {
              newDirectoryPaths.push(directoryPath);
            }
          }
          if (
            directoryPaths.size + newDirectoryPaths.length >
            limits.maximumDirectories
          ) {
            fileSetError(
              "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT",
              "Candidate file-set exceeds its unique directory-count bound",
            );
          }
          for (const newDirectoryPath of newDirectoryPaths) {
            directoryPaths.add(newDirectoryPath);
          }
          currentSpec = Object.freeze({
            path: entry.path,
            sizeBytes: entry.fileSizeBytes,
            mode: entry.mode,
            mtimeMs: entry.mtimeMs,
          });
          currentHash = createHash("sha256");
          currentOffset = 0;
          currentRecords = 0;
          lastPath = entry.path;
          writer = await input.candidateFs.createFileTreeFile(
            policy.directory,
            currentSpec,
            limits,
            input.control,
            lock,
          );
        }
        if (
          !currentSpec ||
          !currentHash ||
          !writer ||
          entry.fileSizeBytes !== currentSpec.sizeBytes ||
          entry.mode !== currentSpec.mode ||
          entry.mtimeMs !== currentSpec.mtimeMs ||
          entry.fileOffsetBytes !== currentOffset ||
          inbox.payload.byteLength > currentSpec.sizeBytes - currentOffset ||
          (inbox.payload.byteLength === 0 &&
            (currentSpec.sizeBytes !== 0 ||
              currentOffset !== 0 ||
              currentRecords !== 0))
        ) {
          fileSetError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_METADATA_CHANGED",
            "Candidate file-set metadata changed within one file",
          );
        }
        componentHash.update(inbox.payload);
        currentHash.update(inbox.payload);
        if (inbox.payload.byteLength > 0 && !writer.replayed) {
          await writer.write(inbox.payload, input.control);
        }
        currentOffset += inbox.payload.byteLength;
        currentRecords += 1;
        bytes += inbox.payload.byteLength;
        if (bytes > limits.maximumBytes) {
          fileSetError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_LIMIT",
            "Candidate file-set exceeds its total byte bound",
          );
        }
        lastRecordReceiptSha256 = inbox.receipt.receiptSha256;
        invokeTestOnlyHook(
          input.testOnlyLifecycle?.afterRecordConsumed,
          inbox.receipt,
          "afterRecordConsumed",
        );
      } finally {
        inbox.payload.fill(0);
      }
    }
    await finalizeFile();
    await requireNoAdditionalRecord(input, component, lock);
    if (
      bytes !== component.payloadBytes ||
      componentHash.digest("hex") !== component.payloadSha256
    ) {
      fileSetError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_COMPONENT_CONFLICT",
        "Candidate file-set inbox differs from its authenticated component finish",
      );
    }
    const tree = await input.candidateFs.proveFileTree(
      policy.directory,
      proofs,
      limits,
      input.control,
      lock,
    );
    const finish = buildFinishReceipt(
      sessionSha256,
      component,
      policy.directory,
      lastRecordReceiptSha256,
      tree,
    );
    await input.candidateFs.publishDurableJson(
      finishMarkerName(component.componentIndex),
      durableFinishMarker(finish),
      { maximumBytes: FINISH_MAXIMUM_BYTES },
      input.control,
      lock,
    );
    result = await validatePersistedFinish(input, finish, lock);
    invokeTestOnlyHook(
      input.testOnlyLifecycle?.afterDurableFinish,
      result,
      "afterDurableFinish",
    );
    result = await validatePersistedFinish(input, finish, lock);
  } catch (cause) {
    primaryFailure = cause;
  }

  const cleanupFailures: unknown[] = [];
  if (writer) {
    try {
      await writer.close();
    } catch (cause) {
      cleanupFailures.push(cause);
    }
  }
  if (lock) {
    try {
      await lock.release(input.control);
    } catch (cause) {
      cleanupFailures.push(cause);
    }
  }
  if (primaryFailure !== undefined && cleanupFailures.length > 0) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_CLEANUP_FAILED",
      "Candidate file-set materialization and bounded cleanup both failed",
      new AggregateError([primaryFailure, ...cleanupFailures]),
    );
  }
  if (primaryFailure !== undefined) throw primaryFailure;
  if (cleanupFailures.length === 1) throw cleanupFailures[0];
  if (cleanupFailures.length > 1) throw new AggregateError(cleanupFailures);
  if (!result) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_FINISH_INVALID",
      "Candidate file-set materialization ended without an exact finish receipt",
    );
  }
  return result;
}

/** Snapshots the authenticated receipt synchronously, then replays its inbox. */
export function materializeAgentBackupRestoreV3CandidateFileSet(
  input: Readonly<MaterializeAgentBackupRestoreV3CandidateFileSetInput>,
): Promise<Readonly<AgentBackupRestoreV3CandidateFileSetReceipt>> {
  if (!input || typeof input !== "object" || isProxy(input)) {
    fileSetError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_SET_INPUT_INVALID",
      "Candidate file-set materialization input must be one non-proxy object",
    );
  }
  const receipt = snapshotReceipt(input.receipt);
  const session = snapshotAgentBackupRestoreV3CandidateSession(input.session);
  const limits = snapshotLimits(input.limits);
  const control = Object.freeze({
    signal: input.control.signal,
    deadlineEpochMs: input.control.deadlineEpochMs,
  });
  return materializeCopiedFileSet(
    Object.freeze({
      candidateFs: input.candidateFs,
      session,
      receipt,
      control,
      limits,
      testOnlyLifecycle: input.testOnlyLifecycle,
    }),
    receipt,
  );
}
