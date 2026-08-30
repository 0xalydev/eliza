/**
 * Exact no-follow file-tree materialization below one isolated candidate.
 *
 * Every published file is written through a descriptor-bound private partial,
 * fsynced, metadata-bound, then linked without replacement. The deterministic
 * partial makes a pre-publication crash recoverable while an exact final file
 * makes response-loss replay read-only.
 */

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import fs, { type FileHandle } from "node:fs/promises";
import path from "node:path";
import { isProxy } from "node:util/types";
import {
  AGENT_BACKUP_CAPTURE_V2_LIMITS,
  type AgentBackupRestoreV3OperationControl,
  compareAgentBackupCaptureV2FilePaths,
} from "@elizaos/shared";
import {
  type AgentBackupRestoreV3CandidateFsControl,
  AgentBackupRestoreV3CandidateFsError,
  type AgentBackupRestoreV3CandidateFsIdentity,
  type AgentBackupRestoreV3CandidateFsLock,
  assertActive,
  boundedInternalCleanup,
  CANDIDATE_FS_IO_CHUNK_BYTES,
  type CandidateFsExactStats,
  candidateFsError,
  candidateFsIdentity,
  controlled,
  controlledAcquire,
  fileStatExact,
  internalCleanupControl,
  isErrno,
  lstatExact,
  requirePathSegment,
  requirePositiveSafeInteger,
  requirePrivateDirectory,
  requireRelativePath,
  sameIdentity,
  sameStableFile,
  writeAll,
} from "./agent-backup-restore-v3-candidate-fs-control";
import { candidateFsCanonicalJson } from "./agent-backup-restore-v3-candidate-fs-json";

const FILE_TREE_DERIVATION =
  "elizaos.agent-backup.restore-v3-candidate-file-tree.v1";
const RESERVED_PREFIX = ".restore-v3-";
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const INTRINSIC_UINT8_ARRAY_SET = Uint8Array.prototype.set;
const MAXIMUM_DATE_EPOCH_MS = 8_640_000_000_000_000;
const CANDIDATE_FILE_STAGING_MODE = 0o600;
// Linux uapi O_PATH. Node/Bun do not expose it consistently in fs.constants.
const LINUX_O_PATH = 0o10000000;

export const AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS = Object.freeze(
  {
    maximumBytes: AGENT_BACKUP_CAPTURE_V2_LIMITS.maxPlainBytes,
    maximumFiles: AGENT_BACKUP_CAPTURE_V2_LIMITS.maxFiles,
    maximumDirectories: AGENT_BACKUP_CAPTURE_V2_LIMITS.maxFiles,
    maximumDepth: 32,
    maximumPathBytes: AGENT_BACKUP_CAPTURE_V2_LIMITS.maxPathBytes,
  },
);

export interface AgentBackupRestoreV3CandidateFileTreeLimits {
  readonly maximumBytes: number;
  readonly maximumFiles: number;
  readonly maximumDirectories: number;
  readonly maximumDepth: number;
  readonly maximumPathBytes: number;
}

export interface AgentBackupRestoreV3CandidateFileTreeFileSpec {
  readonly path: string;
  readonly sizeBytes: number;
  readonly mode: number;
  readonly mtimeMs: number;
}

export interface AgentBackupRestoreV3CandidateFileTreeFileProof
  extends AgentBackupRestoreV3CandidateFileTreeFileSpec,
    AgentBackupRestoreV3CandidateFsIdentity {
  readonly sha256: string;
}

export interface AgentBackupRestoreV3CandidateFileTreeProof
  extends AgentBackupRestoreV3CandidateFsIdentity {
  readonly derivation: typeof FILE_TREE_DERIVATION;
  readonly sha256: string;
  readonly bytes: number;
  readonly files: number;
  readonly directories: number;
  readonly entries: readonly Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>[];
}

function fileTreeError(code: string, message: string, cause?: unknown): never {
  candidateFsError(code, message, cause === undefined ? undefined : { cause });
}

function resolveLimits(
  value: Partial<AgentBackupRestoreV3CandidateFileTreeLimits> | undefined,
): Readonly<AgentBackupRestoreV3CandidateFileTreeLimits> {
  const limits = Object.freeze({
    maximumBytes: requirePositiveSafeInteger(
      value?.maximumBytes ??
        AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumBytes,
      "maximumBytes",
    ),
    maximumFiles: requirePositiveSafeInteger(
      value?.maximumFiles ??
        AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumFiles,
      "maximumFiles",
    ),
    maximumDirectories: requirePositiveSafeInteger(
      value?.maximumDirectories ??
        AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumDirectories,
      "maximumDirectories",
    ),
    maximumDepth: requirePositiveSafeInteger(
      value?.maximumDepth ??
        AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumDepth,
      "maximumDepth",
    ),
    maximumPathBytes: requirePositiveSafeInteger(
      value?.maximumPathBytes ??
        AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumPathBytes,
      "maximumPathBytes",
    ),
  });
  if (
    limits.maximumBytes >
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumBytes ||
    limits.maximumFiles >
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumFiles ||
    limits.maximumDirectories >
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumDirectories ||
    limits.maximumDepth >
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumDepth ||
    limits.maximumPathBytes >
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMITS.maximumPathBytes
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMIT_INVALID",
      "Candidate file-tree limits cannot exceed the authenticated stream bounds",
    );
  }
  return limits;
}

function exactMtimeMs(stats: CandidateFsExactStats): number {
  if (stats.modifiedNanoseconds % 1_000_000n !== 0n) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
      "Candidate file mtime is not exactly representable in milliseconds",
    );
  }
  const value = Number(stats.modifiedNanoseconds / 1_000_000n);
  if (!Number.isSafeInteger(value) || value < 0) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
      "Candidate file mtime is outside the exact stream range",
    );
  }
  return value;
}

async function applyExactMtimeMs(
  handle: FileHandle,
  mtimeMs: number,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
): Promise<void> {
  const targetNs = BigInt(mtimeMs) * 1_000_000n;
  const exactTime = new Date(mtimeMs);
  await controlled(() => handle.utimes(exactTime, exactTime), control);
  const firstObserved = await controlled(() => fileStatExact(handle), control);
  let deltaNs = targetNs - firstObserved.modifiedNanoseconds;
  if (deltaNs === 0n) return;

  let seconds = mtimeMs / 1_000;
  let previousDeltaMagnitude = deltaNs < 0n ? -deltaNs : deltaNs;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const previousSeconds = seconds;
    seconds += Number(deltaNs) / 1e9;
    if (!Number.isFinite(seconds)) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
        "Candidate file mtime correction could not converge exactly",
      );
    }
    await controlled(() => handle.utimes(seconds, seconds), control);
    const observed = await controlled(() => fileStatExact(handle), control);
    deltaNs = targetNs - observed.modifiedNanoseconds;
    if (deltaNs === 0n) return;
    const deltaMagnitude = deltaNs < 0n ? -deltaNs : deltaNs;
    if (
      seconds === previousSeconds ||
      deltaMagnitude >= previousDeltaMagnitude
    ) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
        "Candidate file mtime correction did not make exact progress",
      );
    }
    previousDeltaMagnitude = deltaMagnitude;
  }
  fileTreeError(
    "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
    "Candidate file mtime did not converge to its exact nanosecond target",
  );
}

function requireRegularSingleLink(
  stats: CandidateFsExactStats,
  message: string,
): void {
  if (!stats.file || stats.symbolicLink || stats.linkCount !== 1) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_UNSAFE",
      message,
    );
  }
}

function requireCanonicalFilePath(
  value: string,
  limits: Readonly<AgentBackupRestoreV3CandidateFileTreeLimits>,
): readonly string[] {
  const platformPath = requireRelativePath(value, "candidate file path");
  const encoded = new TextEncoder().encode(value);
  if (
    encoded.byteLength > limits.maximumPathBytes ||
    new TextDecoder("utf-8", { fatal: true }).decode(encoded) !== value
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_PATH_FORBIDDEN",
      "Candidate file path is not bounded canonical UTF-8",
    );
  }
  const segments = platformPath.split(path.sep);
  if (
    segments.length > limits.maximumDepth ||
    segments.some((segment) =>
      segment.toLowerCase().startsWith(RESERVED_PREFIX),
    )
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_PATH_FORBIDDEN",
      "Candidate file path is too deep or uses a reserved control name",
    );
  }
  return Object.freeze(segments);
}

function parseFileSpec(
  value: Readonly<AgentBackupRestoreV3CandidateFileTreeFileSpec>,
  limits: Readonly<AgentBackupRestoreV3CandidateFileTreeLimits>,
): Readonly<AgentBackupRestoreV3CandidateFileTreeFileSpec> {
  if (
    !value ||
    typeof value !== "object" ||
    isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== 4 ||
    !Number.isSafeInteger(value.sizeBytes) ||
    value.sizeBytes < 0 ||
    value.sizeBytes > limits.maximumBytes ||
    !Number.isSafeInteger(value.mode) ||
    value.mode < 0 ||
    value.mode > 0o777 ||
    !Number.isSafeInteger(value.mtimeMs) ||
    value.mtimeMs < 0 ||
    value.mtimeMs > MAXIMUM_DATE_EPOCH_MS
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_SPEC_INVALID",
      "Candidate file specification is not exact and canonical",
    );
  }
  for (const key of ["path", "sizeBytes", "mode", "mtimeMs"] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_SPEC_INVALID",
        "Candidate file specification contains an accessor or hidden field",
      );
    }
  }
  requireCanonicalFilePath(value.path, limits);
  return Object.freeze({
    path: value.path,
    sizeBytes: value.sizeBytes,
    mode: value.mode,
    mtimeMs: value.mtimeMs,
  });
}

function parseExpectedProof(
  value: Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>,
  limits: Readonly<AgentBackupRestoreV3CandidateFileTreeLimits>,
): Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof> {
  if (
    !value ||
    typeof value !== "object" ||
    isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== 7 ||
    Object.keys(value).sort().join("\0") !==
      [
        "device",
        "inode",
        "mode",
        "mtimeMs",
        "path",
        "sha256",
        "sizeBytes",
      ].join("\0") ||
    !SHA256_PATTERN.test(value.sha256) ||
    !/^(?:0|[1-9][0-9]*)$/.test(value.device) ||
    !/^(?:0|[1-9][0-9]*)$/.test(value.inode)
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_PROOF_INVALID",
      "Candidate file proof is not exact and canonical",
    );
  }
  for (const key of [
    "path",
    "sizeBytes",
    "mode",
    "mtimeMs",
    "sha256",
    "device",
    "inode",
  ] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_PROOF_INVALID",
        "Candidate file proof contains an accessor or hidden field",
      );
    }
  }
  const spec = parseFileSpec(
    {
      path: value.path,
      sizeBytes: value.sizeBytes,
      mode: value.mode,
      mtimeMs: value.mtimeMs,
    },
    limits,
  );
  return Object.freeze({
    ...spec,
    sha256: value.sha256,
    device: value.device,
    inode: value.inode,
  });
}

async function ensureDirectories(
  authority: AgentBackupRestoreV3CandidateFsControl,
  segments: readonly string[],
  control: Readonly<AgentBackupRestoreV3OperationControl>,
): Promise<void> {
  const resolved: string[] = [];
  for (const rawSegment of segments) {
    const segment = requirePathSegment(rawSegment, "candidate directory");
    const parent = await authority.openDirectorySegments(resolved, control);
    try {
      const childPath = path.join(parent.anchor, segment);
      try {
        await controlled(() => fs.mkdir(childPath, { mode: 0o700 }), control);
        await controlled(() => parent.handle.sync(), control);
      } catch (cause) {
        if (!isErrno(cause, "EEXIST")) throw cause;
      }
    } finally {
      await boundedInternalCleanup(() => parent.handle.close());
    }
    resolved.push(segment);
    const child = await authority.openDirectorySegments(resolved, control);
    await boundedInternalCleanup(() => child.handle.close());
  }
}

function partialName(relativePath: string): string {
  return `${RESERVED_PREFIX}partial-${createHash("sha256")
    .update(relativePath, "utf8")
    .digest("hex")}`;
}

async function openBoundRegularFile(
  targetPath: string,
  flags: number,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  mode?: number,
): Promise<{
  readonly handle: FileHandle;
  readonly stats: CandidateFsExactStats;
}> {
  const handle = await controlledAcquire(
    () => fs.open(targetPath, flags, mode),
    (lateHandle) => lateHandle.close(),
    control,
  );
  try {
    const [visible, opened] = await controlled(
      () => Promise.all([lstatExact(targetPath), fileStatExact(handle)]),
      control,
    );
    if (!sameIdentity(visible, opened)) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
        "Candidate file pathname changed during no-follow open",
      );
    }
    return { handle, stats: opened };
  } catch (cause) {
    await boundedInternalCleanup(() => handle.close());
    throw cause;
  }
}

async function hashOpenedFile(
  handle: FileHandle,
  opened: CandidateFsExactStats,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
): Promise<string> {
  const hash = createHash("sha256");
  const chunk = new Uint8Array(
    Math.min(CANDIDATE_FS_IO_CHUNK_BYTES, Math.max(1, opened.size)),
  );
  let position = 0;
  try {
    while (position < opened.size) {
      const requested = Math.min(chunk.byteLength, opened.size - position);
      const read = await controlled(
        () => handle.read(chunk, 0, requested, position),
        control,
      );
      if (read.bytesRead <= 0) {
        fileTreeError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_TRUNCATED",
          "Candidate file ended during exact proof",
        );
      }
      hash.update(chunk.subarray(0, read.bytesRead));
      chunk.fill(0, 0, read.bytesRead);
      position += read.bytesRead;
    }
    return hash.digest("hex");
  } finally {
    chunk.fill(0);
  }
}

async function proveOpenedFile(
  handle: FileHandle,
  targetPath: string,
  expectedIdentity: CandidateFsExactStats,
  spec: Readonly<AgentBackupRestoreV3CandidateFileTreeFileSpec>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  allowStagingMode = false,
): Promise<Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>> {
  const [visible, before] = await controlled(
    () => Promise.all([lstatExact(targetPath), fileStatExact(handle)]),
    control,
  );
  requireRegularSingleLink(
    visible,
    "Candidate output path is not one regular single-link file",
  );
  requireRegularSingleLink(
    before,
    "Candidate output descriptor is not one regular single-link file",
  );
  if (
    !sameIdentity(visible, expectedIdentity) ||
    !sameIdentity(before, expectedIdentity) ||
    before.size !== spec.sizeBytes ||
    ((before.mode & 0o777) !== spec.mode &&
      (!allowStagingMode ||
        (before.mode & 0o777) !== CANDIDATE_FILE_STAGING_MODE)) ||
    exactMtimeMs(before) !== spec.mtimeMs
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
      "Candidate output differs from its exact path, size, mode, or mtime",
    );
  }
  const sha256 = await hashOpenedFile(handle, before, control);
  const [visibleAfterHash, afterHash] = await controlled(
    () => Promise.all([lstatExact(targetPath), fileStatExact(handle)]),
    control,
  );
  if (
    !sameStableFile(before, afterHash) ||
    !sameStableFile(visible, visibleAfterHash) ||
    !sameIdentity(afterHash, visibleAfterHash)
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
      "Candidate output changed during exact proof",
    );
  }
  if ((afterHash.mode & 0o777) !== spec.mode) {
    await controlled(() => handle.chmod(spec.mode), control);
    await controlled(() => handle.sync(), control);
  }
  const [visibleAfter, after] = await controlled(
    () => Promise.all([lstatExact(targetPath), fileStatExact(handle)]),
    control,
  );
  requireRegularSingleLink(
    visibleAfter,
    "Candidate output path changed while applying its final mode",
  );
  requireRegularSingleLink(
    after,
    "Candidate output descriptor changed while applying its final mode",
  );
  if (
    !sameIdentity(afterHash, after) ||
    !sameIdentity(visibleAfter, after) ||
    after.size !== spec.sizeBytes ||
    (after.mode & 0o777) !== spec.mode ||
    exactMtimeMs(after) !== spec.mtimeMs
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
      "Candidate output differs after applying its exact final mode",
    );
  }
  return Object.freeze({
    ...spec,
    ...candidateFsIdentity(after),
    sha256,
  });
}

async function proveFinalPath(
  targetPath: string,
  spec: Readonly<AgentBackupRestoreV3CandidateFileTreeFileSpec>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
): Promise<Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>> {
  const visible = await controlled(() => lstatExact(targetPath), control);
  requireRegularSingleLink(
    visible,
    "Candidate final path is not one regular single-link file",
  );
  const visibleMode = visible.mode & 0o777;
  if (
    visible.size !== spec.sizeBytes ||
    (visibleMode !== spec.mode &&
      visibleMode !== CANDIDATE_FILE_STAGING_MODE) ||
    exactMtimeMs(visible) !== spec.mtimeMs
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
      "Candidate final path differs from its exact size, mode, or mtime",
    );
  }

  if ((visibleMode & 0o444) !== 0) {
    const opened = await openBoundRegularFile(
      targetPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
      control,
    );
    try {
      return await proveOpenedFile(
        opened.handle,
        targetPath,
        visible,
        spec,
        control,
        true,
      );
    } finally {
      await boundedInternalCleanup(() => opened.handle.close());
    }
  }

  let authorityHandle: FileHandle | null = null;
  let readHandle: FileHandle | null = null;
  let restoreAnchor = targetPath;
  let result: Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof> | null =
    null;
  let primaryFailure: unknown;
  try {
    if (process.platform === "linux") {
      authorityHandle = await controlledAcquire(
        () => fs.open(targetPath, LINUX_O_PATH | constants.O_NOFOLLOW),
        (lateHandle) => lateHandle.close(),
        control,
      );
      const bound = await controlled(
        () => fileStatExact(authorityHandle as FileHandle),
        control,
      );
      requireRegularSingleLink(
        bound,
        "Candidate final O_PATH authority is not one regular single-link file",
      );
      if (!sameIdentity(bound, visible)) {
        fileTreeError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
          "Candidate final path changed during O_PATH binding",
        );
      }
      restoreAnchor = `/proc/self/fd/${authorityHandle.fd}`;
    }

    assertActive(control);
    await fs.chmod(restoreAnchor, CANDIDATE_FILE_STAGING_MODE);
    assertActive(control);
    readHandle = await controlledAcquire(
      () =>
        fs.open(
          restoreAnchor,
          process.platform === "linux"
            ? constants.O_RDONLY
            : constants.O_RDONLY | constants.O_NOFOLLOW,
        ),
      (lateHandle) => lateHandle.close(),
      control,
    );
    const opened = await controlled(
      () => fileStatExact(readHandle as FileHandle),
      control,
    );
    if (!sameIdentity(opened, visible)) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
        "Candidate final descriptor differs from its permission authority",
      );
    }
    result = await proveOpenedFile(
      readHandle,
      targetPath,
      visible,
      spec,
      control,
      true,
    );
  } catch (cause) {
    primaryFailure = cause;
  }

  const cleanupFailures: unknown[] = [];
  try {
    await boundedInternalCleanup(() => fs.chmod(restoreAnchor, spec.mode));
  } catch (cause) {
    cleanupFailures.push(cause);
  }
  if (readHandle) {
    try {
      await boundedInternalCleanup(() => (readHandle as FileHandle).close());
    } catch (cause) {
      cleanupFailures.push(cause);
    }
  }
  if (authorityHandle) {
    try {
      await boundedInternalCleanup(() =>
        (authorityHandle as FileHandle).close(),
      );
    } catch (cause) {
      cleanupFailures.push(cause);
    }
  }
  if (primaryFailure !== undefined && cleanupFailures.length > 0) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CLEANUP_FAILED",
      "Candidate final proof and permission restoration both failed",
      new AggregateError([primaryFailure, ...cleanupFailures]),
    );
  }
  if (primaryFailure !== undefined) throw primaryFailure;
  if (cleanupFailures.length === 1) throw cleanupFailures[0];
  if (cleanupFailures.length > 1) throw new AggregateError(cleanupFailures);
  if (!result) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
      "Candidate final permission proof ended without a result",
    );
  }
  const finalVisible = await controlled(() => lstatExact(targetPath), control);
  if (
    !sameIdentity(finalVisible, visible) ||
    finalVisible.size !== spec.sizeBytes ||
    (finalVisible.mode & 0o777) !== spec.mode ||
    exactMtimeMs(finalVisible) !== spec.mtimeMs
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
      "Candidate final path changed after permission-safe proof",
    );
  }
  return result;
}

export class AgentBackupRestoreV3CandidateFileTreeWriter {
  readonly spec: Readonly<AgentBackupRestoreV3CandidateFileTreeFileSpec>;
  readonly replayed: boolean;
  #owner: AgentBackupRestoreV3CandidateFsControl;
  #parentHandle: FileHandle | null;
  #targetPath: string;
  #partialPath: string;
  #handle: FileHandle | null;
  #identity: CandidateFsExactStats | null;
  #lock: AgentBackupRestoreV3CandidateFsLock;
  #ownsLock: boolean;
  #position = 0;
  #replayedProof: Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof> | null;
  #writing = false;
  #closed = false;

  constructor(input: {
    owner: AgentBackupRestoreV3CandidateFsControl;
    parentHandle: FileHandle | null;
    targetPath: string;
    partialPath: string;
    handle: FileHandle | null;
    identity: CandidateFsExactStats | null;
    spec: Readonly<AgentBackupRestoreV3CandidateFileTreeFileSpec>;
    lock: AgentBackupRestoreV3CandidateFsLock;
    ownsLock: boolean;
    replayedProof?: Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>;
  }) {
    this.#owner = input.owner;
    this.#parentHandle = input.parentHandle;
    this.#targetPath = input.targetPath;
    this.#partialPath = input.partialPath;
    this.#handle = input.handle;
    this.#identity = input.identity;
    this.spec = input.spec;
    this.#lock = input.lock;
    this.#ownsLock = input.ownsLock;
    this.#replayedProof = input.replayedProof ?? null;
    this.replayed = this.#replayedProof !== null;
  }

  get acknowledgedBytes(): number {
    return this.#position;
  }

  write(
    fragment: Uint8Array,
    control: Readonly<AgentBackupRestoreV3OperationControl>,
  ): Promise<void> {
    if (
      !fragment ||
      typeof fragment !== "object" ||
      isProxy(fragment) ||
      !(fragment instanceof Uint8Array) ||
      Object.getPrototypeOf(fragment) !== Uint8Array.prototype ||
      Object.getOwnPropertyDescriptor(fragment, Symbol.iterator) !==
        undefined ||
      fragment.byteLength === 0 ||
      fragment.byteLength > CANDIDATE_FS_IO_CHUNK_BYTES
    ) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_FRAGMENT_INVALID",
        "Candidate file-tree write requires one intrinsic bounded fragment",
      );
    }
    if (
      this.#closed ||
      this.#writing ||
      this.replayed ||
      !this.#handle ||
      !this.#identity ||
      this.#position > this.spec.sizeBytes - fragment.byteLength
    ) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_WRITER_INVALID",
        "Candidate file-tree writer state or byte bound is invalid",
      );
    }
    const owned = new Uint8Array(fragment.byteLength);
    INTRINSIC_UINT8_ARRAY_SET.call(owned, fragment, 0);
    this.#writing = true;
    return (async () => {
      try {
        await this.#owner.assertLockHeld(this.#lock, control);
        const before = await controlled(
          () => fileStatExact(this.#handle as FileHandle),
          control,
        );
        requireRegularSingleLink(
          before,
          "Candidate partial changed before its descriptor-bound write",
        );
        if (!sameIdentity(before, this.#identity as CandidateFsExactStats)) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
            "Candidate partial inode changed before write",
          );
        }
        await writeAll(
          this.#handle as FileHandle,
          owned,
          this.#position,
          control,
        );
        this.#position += owned.byteLength;
        await this.#owner.assertLockHeld(this.#lock, control);
      } catch (cause) {
        this.#closed = true;
        try {
          await this.#dispose();
        } catch (cleanupCause) {
          throw new AgentBackupRestoreV3CandidateFsError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CLEANUP_FAILED",
            "Candidate file write and bounded cleanup both failed",
            { cause: new AggregateError([cause, cleanupCause]) },
          );
        }
        throw cause;
      } finally {
        owned.fill(0);
        this.#writing = false;
      }
    })();
  }

  async finalize(
    control: Readonly<AgentBackupRestoreV3OperationControl>,
  ): Promise<Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>> {
    if (this.#closed || this.#writing) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_WRITER_INVALID",
        "Candidate file-tree writer cannot finalize in its current state",
      );
    }
    this.#closed = true;
    let result: Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof> | null =
      null;
    let primaryFailure: unknown;
    try {
      await this.#owner.assertLockHeld(this.#lock, control);
      if (this.#replayedProof) {
        result = this.#replayedProof;
      } else {
        if (
          !this.#handle ||
          !this.#identity ||
          !this.#parentHandle ||
          this.#position !== this.spec.sizeBytes
        ) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_TRUNCATED",
            "Candidate file-tree writer did not receive the exact file size",
          );
        }
        await applyExactMtimeMs(
          this.#handle as FileHandle,
          this.spec.mtimeMs,
          control,
        );
        await controlled(() => (this.#handle as FileHandle).sync(), control);
        const beforeLink = await controlled(
          () => fileStatExact(this.#handle as FileHandle),
          control,
        );
        if (
          !sameIdentity(beforeLink, this.#identity as CandidateFsExactStats) ||
          beforeLink.size !== this.spec.sizeBytes ||
          (beforeLink.mode & 0o777) !== CANDIDATE_FILE_STAGING_MODE ||
          exactMtimeMs(beforeLink) !== this.spec.mtimeMs
        ) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_METADATA_CHANGED",
            "Candidate partial differs from its finalized metadata",
          );
        }
        try {
          await controlled(
            () => fs.link(this.#partialPath, this.#targetPath),
            control,
          );
        } catch (cause) {
          if (!isErrno(cause, "EEXIST")) throw cause;
          const target = await lstatExact(this.#targetPath);
          if (!sameIdentity(target, beforeLink) || target.linkCount !== 2) {
            fileTreeError(
              "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONFLICT",
              "Candidate final path was occupied by another inode",
              cause,
            );
          }
        }
        const linked = await controlled(
          () => fileStatExact(this.#handle as FileHandle),
          control,
        );
        if (!sameIdentity(linked, beforeLink) || linked.linkCount !== 2) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
            "Candidate file did not enter its exact two-link publish state",
          );
        }
        assertActive(control);
        await fs.unlink(this.#partialPath);
        await controlled(
          () => (this.#parentHandle as FileHandle).sync(),
          control,
        );
        result = await proveOpenedFile(
          this.#handle,
          this.#targetPath,
          this.#identity,
          this.spec,
          control,
          true,
        );
      }
    } catch (cause) {
      primaryFailure = cause;
    }
    try {
      await this.#dispose();
    } catch (cleanupCause) {
      if (primaryFailure !== undefined) {
        throw new AgentBackupRestoreV3CandidateFsError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CLEANUP_FAILED",
          "Candidate file finalization and bounded cleanup both failed",
          { cause: new AggregateError([primaryFailure, cleanupCause]) },
        );
      }
      throw cleanupCause;
    }
    if (primaryFailure !== undefined) throw primaryFailure;
    if (!result) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_WRITER_INVALID",
        "Candidate file finalization ended without an exact proof",
      );
    }
    return result;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    if (this.#writing) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_WRITER_INVALID",
        "Candidate file-tree writer cannot close during a write",
      );
    }
    this.#closed = true;
    await this.#dispose();
  }

  async #dispose(): Promise<void> {
    const failures: unknown[] = [];
    const handle = this.#handle;
    this.#handle = null;
    if (handle) {
      try {
        await boundedInternalCleanup(() => handle.close());
      } catch (cause) {
        failures.push(cause);
      }
    }
    const parent = this.#parentHandle;
    this.#parentHandle = null;
    if (parent) {
      try {
        await boundedInternalCleanup(() => parent.close());
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (this.#ownsLock) {
      this.#ownsLock = false;
      try {
        await this.#lock.release(internalCleanupControl());
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) throw new AggregateError(failures);
  }
}

export async function ensureCandidateFsFileTreeDirectory(
  authority: AgentBackupRestoreV3CandidateFsControl,
  relativeDirectory: string,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  heldLock?: AgentBackupRestoreV3CandidateFsLock,
): Promise<void> {
  const segments = requireRelativePath(
    relativeDirectory,
    "candidate file-tree directory",
  ).split(path.sep);
  await authority.assertAuthority(control);
  const operationLock = await authority.operationLock(
    `.file-tree-${createHash("sha256")
      .update(relativeDirectory)
      .digest("hex")
      .slice(0, 16)}`,
    control,
    heldLock,
  );
  const activeLock = operationLock ?? heldLock;
  if (!activeLock) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FS_LOCK_INVALID",
      "Candidate file-tree directory did not obtain its exact inode lock",
    );
  }
  try {
    await ensureDirectories(authority, segments, control);
    await authority.assertLockHeld(activeLock, control);
  } finally {
    if (operationLock) {
      await operationLock.release(internalCleanupControl());
    }
  }
}

export async function createCandidateFsFileTreeFile(
  authority: AgentBackupRestoreV3CandidateFsControl,
  relativeDirectory: string,
  specValue: Readonly<AgentBackupRestoreV3CandidateFileTreeFileSpec>,
  limitsValue: Partial<AgentBackupRestoreV3CandidateFileTreeLimits> | undefined,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  heldLock?: AgentBackupRestoreV3CandidateFsLock,
): Promise<AgentBackupRestoreV3CandidateFileTreeWriter> {
  const limits = resolveLimits(limitsValue);
  const spec = parseFileSpec(specValue, limits);
  const rootSegments = requireRelativePath(
    relativeDirectory,
    "candidate file-tree directory",
  ).split(path.sep);
  const fileSegments = requireCanonicalFilePath(spec.path, limits);
  await authority.assertAuthority(control);
  const operationLock = await authority.operationLock(
    `.file-${createHash("sha256")
      .update(relativeDirectory)
      .update("\0")
      .update(spec.path)
      .digest("hex")
      .slice(0, 16)}`,
    control,
    heldLock,
  );
  const activeLock = operationLock ?? heldLock;
  if (!activeLock) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FS_LOCK_INVALID",
      "Candidate file writer did not obtain its exact inode lock",
    );
  }
  let parentHandle: FileHandle | null = null;
  let handle: FileHandle | null = null;
  try {
    const parentSegments = [...rootSegments, ...fileSegments.slice(0, -1)];
    await ensureDirectories(authority, parentSegments, control);
    const parent = await authority.openDirectorySegments(
      parentSegments,
      control,
    );
    parentHandle = parent.handle;
    const fileName = fileSegments[fileSegments.length - 1] as string;
    const targetPath = path.join(parent.anchor, fileName);
    const partialPath = path.join(parent.anchor, partialName(spec.path));

    let targetStats: CandidateFsExactStats | null = null;
    try {
      targetStats = await controlled(() => lstatExact(targetPath), control);
    } catch (cause) {
      if (!isErrno(cause, "ENOENT")) throw cause;
    }
    if (targetStats) {
      let partialStats: CandidateFsExactStats | null = null;
      try {
        partialStats = await controlled(() => lstatExact(partialPath), control);
      } catch (cause) {
        if (!isErrno(cause, "ENOENT")) throw cause;
      }
      if (partialStats) {
        if (
          !sameIdentity(partialStats, targetStats) ||
          partialStats.linkCount !== 2 ||
          !partialStats.file ||
          partialStats.symbolicLink
        ) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONFLICT",
            "Candidate final and partial paths do not describe one crash state",
          );
        }
        assertActive(control);
        await fs.unlink(partialPath);
        await controlled(() => (parentHandle as FileHandle).sync(), control);
        targetStats = await controlled(() => lstatExact(targetPath), control);
      }
      requireRegularSingleLink(
        targetStats,
        "Candidate final path is a symbolic link, hardlink, or non-regular file",
      );
      const proof = await proveFinalPath(targetPath, spec, control);
      await authority.assertLockHeld(activeLock, control);
      const writer = new AgentBackupRestoreV3CandidateFileTreeWriter({
        owner: authority,
        parentHandle,
        targetPath,
        partialPath,
        handle: null,
        identity: null,
        spec,
        lock: activeLock,
        ownsLock: operationLock !== null,
        replayedProof: proof,
      });
      parentHandle = null;
      return writer;
    }

    try {
      const opened = await openBoundRegularFile(
        partialPath,
        constants.O_RDWR | constants.O_NOFOLLOW,
        control,
      );
      handle = opened.handle;
      requireRegularSingleLink(
        opened.stats,
        "Candidate recoverable partial is not one regular single-link file",
      );
      await controlled(() => (handle as FileHandle).truncate(0), control);
      await controlled(() => (handle as FileHandle).chmod(0o600), control);
    } catch (cause) {
      if (!isErrno(cause, "ENOENT")) throw cause;
      const opened = await openBoundRegularFile(
        partialPath,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_RDWR |
          constants.O_NOFOLLOW,
        control,
        0o600,
      );
      handle = opened.handle;
      requireRegularSingleLink(
        opened.stats,
        "Candidate newly-created partial is not one regular single-link file",
      );
    }
    const identity = await controlled(
      () => fileStatExact(handle as FileHandle),
      control,
    );
    requireRegularSingleLink(
      identity,
      "Candidate partial changed before writer handoff",
    );
    if (identity.size !== 0) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONFLICT",
        "Candidate recoverable partial could not be reset exactly",
      );
    }
    await controlled(() => (parentHandle as FileHandle).sync(), control);
    await authority.assertLockHeld(activeLock, control);
    const writer = new AgentBackupRestoreV3CandidateFileTreeWriter({
      owner: authority,
      parentHandle,
      targetPath,
      partialPath,
      handle,
      identity,
      spec,
      lock: activeLock,
      ownsLock: operationLock !== null,
    });
    parentHandle = null;
    handle = null;
    return writer;
  } catch (cause) {
    const failures: unknown[] = [cause];
    if (handle) {
      try {
        await boundedInternalCleanup(() => (handle as FileHandle).close());
      } catch (cleanupCause) {
        failures.push(cleanupCause);
      }
    }
    if (parentHandle) {
      try {
        await boundedInternalCleanup(() =>
          (parentHandle as FileHandle).close(),
        );
      } catch (cleanupCause) {
        failures.push(cleanupCause);
      }
    }
    if (operationLock) {
      try {
        await operationLock.release(internalCleanupControl());
      } catch (cleanupCause) {
        failures.push(cleanupCause);
      }
    }
    if (failures.length === 1) throw cause;
    throw new AgentBackupRestoreV3CandidateFsError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CLEANUP_FAILED",
      "Candidate file writer setup and bounded cleanup both failed",
      { cause: new AggregateError(failures) },
    );
  }
}

function treeDigest(
  entries: readonly Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>[],
): string {
  return createHash("sha256")
    .update(
      candidateFsCanonicalJson({
        derivation: FILE_TREE_DERIVATION,
        entries: entries.map((entry) => ({
          pathUtf8Hex: Buffer.from(entry.path, "utf8").toString("hex"),
          sha256: entry.sha256,
          sizeBytes: entry.sizeBytes,
          mode: entry.mode,
          mtimeMs: entry.mtimeMs,
          device: entry.device,
          inode: entry.inode,
        })),
      }),
      "utf8",
    )
    .digest("hex");
}

export async function proveCandidateFsFileTree(
  authority: AgentBackupRestoreV3CandidateFsControl,
  relativeDirectory: string,
  expectedValue: readonly Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>[],
  limitsValue: Partial<AgentBackupRestoreV3CandidateFileTreeLimits> | undefined,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  heldLock?: AgentBackupRestoreV3CandidateFsLock,
): Promise<Readonly<AgentBackupRestoreV3CandidateFileTreeProof>> {
  const limits = resolveLimits(limitsValue);
  if (
    !expectedValue ||
    typeof expectedValue !== "object" ||
    isProxy(expectedValue) ||
    !Array.isArray(expectedValue) ||
    Object.getPrototypeOf(expectedValue) !== Array.prototype ||
    Object.getOwnPropertyDescriptor(expectedValue, Symbol.iterator) !==
      undefined ||
    expectedValue.length > limits.maximumFiles ||
    Reflect.ownKeys(expectedValue).length !== expectedValue.length + 1
  ) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMIT",
      "Candidate expected file list exceeds its explicit bound",
    );
  }
  const expected: Readonly<AgentBackupRestoreV3CandidateFileTreeFileProof>[] =
    [];
  for (let index = 0; index < expectedValue.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(
      expectedValue,
      String(index),
    );
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_EXPECTATION_INVALID",
        "Candidate expected file list contains an accessor or sparse slot",
      );
    }
    expected.push(parseExpectedProof(descriptor.value, limits));
  }
  let expectedBytes = 0;
  for (const [index, entry] of expected.entries()) {
    expectedBytes += entry.sizeBytes;
    if (
      expectedBytes > limits.maximumBytes ||
      (index > 0 &&
        compareAgentBackupCaptureV2FilePaths(
          expected[index - 1]?.path ?? "",
          entry.path,
        ) >= 0)
    ) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_EXPECTATION_INVALID",
        "Candidate expected files are duplicated, unordered, or oversized",
      );
    }
  }
  const expectedByPath = new Map(
    expected.map((entry) => [entry.path, entry] as const),
  );
  const rootSegments = requireRelativePath(
    relativeDirectory,
    "candidate file-tree directory",
  ).split(path.sep);
  await authority.assertAuthority(control);
  const operationLock = await authority.operationLock(
    `.prove-files-${createHash("sha256")
      .update(relativeDirectory)
      .digest("hex")
      .slice(0, 16)}`,
    control,
    heldLock,
  );
  const activeLock = operationLock ?? heldLock;
  if (!activeLock) {
    fileTreeError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FS_LOCK_INVALID",
      "Candidate file-tree proof did not obtain its exact inode lock",
    );
  }
  let rootHandle: FileHandle | null = null;
  try {
    const root = await authority.openDirectorySegments(rootSegments, control);
    rootHandle = root.handle;
    const observed: AgentBackupRestoreV3CandidateFileTreeFileProof[] = [];
    let directories = 0;
    let bytes = 0;
    const walk = async (
      directoryHandle: FileHandle,
      anchor: string,
      testPath: string,
      relative: string,
      expectedDirectory: CandidateFsExactStats,
      depth: number,
    ): Promise<void> => {
      if (depth > limits.maximumDepth) {
        fileTreeError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMIT",
          "Candidate file-tree exceeds its depth bound",
        );
      }
      const beforeNames = (
        await controlled(() => fs.readdir(anchor), control)
      ).sort(compareAgentBackupCaptureV2FilePaths);
      for (const rawName of beforeNames) {
        const name = requirePathSegment(rawName, "candidate tree entry");
        if (name.toLowerCase().startsWith(RESERVED_PREFIX)) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONTROL_RESIDUE",
            "Candidate file-tree contains an unpublished control partial",
          );
        }
        const childRelative = relative ? `${relative}/${name}` : name;
        requireCanonicalFilePath(childRelative, limits);
        const childPath = path.join(anchor, name);
        const visible = await controlled(() => lstatExact(childPath), control);
        if (visible.symbolicLink) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_UNSAFE",
            "Candidate file-tree contains a symbolic link",
          );
        }
        if (visible.directory) {
          const child = await controlledAcquire(
            () =>
              fs.open(
                childPath,
                constants.O_RDONLY |
                  constants.O_DIRECTORY |
                  constants.O_NOFOLLOW,
              ),
            (lateHandle) => lateHandle.close(),
            control,
          );
          try {
            const opened = await controlled(
              () => fileStatExact(child),
              control,
            );
            requirePrivateDirectory(
              opened,
              "Candidate file-tree directory is not private",
            );
            if (!sameIdentity(opened, visible)) {
              fileTreeError(
                "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
                "Candidate directory changed during no-follow descent",
              );
            }
            directories += 1;
            if (directories > limits.maximumDirectories) {
              fileTreeError(
                "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMIT",
                "Candidate file-tree directory count exceeds its derived bound",
              );
            }
            await walk(
              child,
              authority.directoryAnchor(child, path.join(testPath, name)),
              path.join(testPath, name),
              childRelative,
              opened,
              depth + 1,
            );
          } finally {
            await boundedInternalCleanup(() => child.close());
          }
          continue;
        }
        requireRegularSingleLink(
          visible,
          "Candidate file-tree contains a linked or non-regular file",
        );
        const expectation = expectedByPath.get(childRelative);
        if (
          !expectation ||
          observed.some((entry) => entry.path === childRelative)
        ) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONFLICT",
            "Candidate file-tree contains an unexpected or unordered file",
          );
        }
        const proof = await proveFinalPath(childPath, expectation, control);
        if (
          proof.sha256 !== expectation.sha256 ||
          proof.device !== expectation.device ||
          proof.inode !== expectation.inode
        ) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONFLICT",
            "Candidate file differs from its immutable expected proof",
          );
        }
        observed.push(proof);
        bytes += proof.sizeBytes;
        if (
          observed.length > limits.maximumFiles ||
          bytes > limits.maximumBytes
        ) {
          fileTreeError(
            "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_LIMIT",
            "Candidate file-tree exceeds its file or byte bound",
          );
        }
      }
      const [afterNames, afterDirectory] = await controlled(
        () => Promise.all([fs.readdir(anchor), fileStatExact(directoryHandle)]),
        control,
      );
      afterNames.sort(compareAgentBackupCaptureV2FilePaths);
      if (
        beforeNames.length !== afterNames.length ||
        beforeNames.some((name, index) => name !== afterNames[index]) ||
        !sameIdentity(afterDirectory, expectedDirectory) ||
        afterDirectory.mode !== expectedDirectory.mode ||
        afterDirectory.modifiedNanoseconds !==
          expectedDirectory.modifiedNanoseconds
      ) {
        fileTreeError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
          "Candidate directory changed during exact proof",
        );
      }
      requirePrivateDirectory(
        afterDirectory,
        "Candidate file-tree directory ceased to be private during proof",
      );
    };
    await walk(root.handle, root.anchor, root.testPath, "", root.stats, 0);
    observed.sort((left, right) =>
      compareAgentBackupCaptureV2FilePaths(left.path, right.path),
    );
    if (observed.length !== expected.length || bytes !== expectedBytes) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONFLICT",
        "Candidate file-tree is incomplete",
      );
    }
    for (const [index, proof] of observed.entries()) {
      if (proof.path !== expected[index]?.path) {
        fileTreeError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_CONFLICT",
          "Candidate file-tree differs from canonical full-path UTF-8 order",
        );
      }
    }
    await authority.assertLockHeld(activeLock, control);
    const rootAfter = await controlled(
      () => fileStatExact(root.handle),
      control,
    );
    if (!sameIdentity(rootAfter, root.stats)) {
      fileTreeError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_FILE_TREE_INODE_CHANGED",
        "Candidate file-tree root identity changed",
      );
    }
    return Object.freeze({
      derivation: FILE_TREE_DERIVATION,
      ...candidateFsIdentity(rootAfter),
      sha256: treeDigest(observed),
      bytes,
      files: observed.length,
      directories,
      entries: Object.freeze(observed.map((entry) => Object.freeze(entry))),
    });
  } finally {
    if (rootHandle) {
      await boundedInternalCleanup(() => (rootHandle as FileHandle).close());
    }
    if (operationLock) {
      await operationLock.release(internalCleanupControl());
    }
  }
}
