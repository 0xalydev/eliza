/**
 * Exact, immutable restore-v3 record inbox below one candidate filesystem.
 *
 * This layer owns only durable record slots. It does not interpret character,
 * database, or file-set payloads and has no path to live runtime state.
 */

import { Buffer } from "node:buffer";
import {
  createHash,
  createHmac,
  type Hmac,
  timingSafeEqual,
} from "node:crypto";
import { isProxy } from "node:util/types";
import { ElizaError } from "@elizaos/core";
import {
  AGENT_BACKUP_RESTORE_V3_STREAM_COMPONENTS,
  type AgentBackupRestoreV3OperationControl,
  type AgentBackupRestoreV3StagedRecord,
  type AgentBackupRestoreV3StageRecordReceipt,
  AgentBackupRestoreV3StageRecordReceiptSchema,
  type AgentBackupRestoreV3StagingSession,
  type AgentBackupRestoreV3StreamComponentName,
  parseAgentBackupRestoreV3StagingSession,
} from "@elizaos/shared";
import type {
  AgentBackupRestoreV3CandidateFs,
  AgentBackupRestoreV3CandidateFsLock,
  AgentBackupRestoreV3CandidatePayloadReceipt,
  AgentBackupRestoreV3CandidatePayloadWriter,
} from "./agent-backup-restore-v3-candidate-fs";
import { candidateFsCanonicalJson } from "./agent-backup-restore-v3-candidate-fs-json";

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const UINT64_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_UINT64 = 18_446_744_073_709_551_615n;
const RECORD_RECEIPT_MAXIMUM_BYTES = 32 * 1024;
const SESSION_JOURNAL_MAXIMUM_BYTES = 8 * 1024;
const RECORD_LOCK_NAME = "restore-v3-record-inbox.lock";
const SESSION_JOURNAL_NAME = ".restore-v3-record-inbox.session.json";
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteLength",
)?.get;
const TYPED_ARRAY_BUFFER_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "buffer",
)?.get;
const INTRINSIC_UINT8_ARRAY_SET = Uint8Array.prototype.set;

export const AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_FORMAT =
  "elizaos.agent-backup.restore-v3-candidate-record.v1" as const;
export const AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_COMMAND_CONTEXT =
  "elizaos.agent-backup.restore-v3-candidate-record-command.v1" as const;
export const AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CHAIN_CONTEXT =
  "elizaos.agent-backup.restore-v3-candidate-record-chain.v1" as const;
export const AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_OWNER_CONTEXT =
  "elizaos.agent-backup.restore-v3-candidate-record-owner.v1" as const;
export const AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES =
  256 * 1024;

interface CandidateRecordSessionJournal {
  readonly version: 1;
  readonly format: "elizaos.agent-backup.restore-v3-candidate-record-session.v1";
  readonly restoreAttemptId: string;
  readonly operationId: string;
  readonly expectedManifestSha256: string;
  readonly stagingHandleSha256: string;
  readonly cleanupHandleSha256: string;
  readonly executionTokenSha256: string;
  readonly cleanupRegistered: true;
  readonly isolatedCandidate: true;
  readonly sessionSha256: string;
}

export interface AgentBackupRestoreV3CandidateRecordReceipt {
  readonly version: 1;
  readonly format: typeof AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_FORMAT;
  readonly sessionSha256: string;
  readonly commandSha256: string;
  readonly ownerTokenSha256: string;
  readonly payloadName: string;
  readonly previousReceiptSha256: string;
  readonly record: Readonly<AgentBackupRestoreV3StageRecordReceipt>;
  readonly payload: Readonly<AgentBackupRestoreV3CandidatePayloadReceipt>;
  readonly receiptSha256: string;
}

export interface AgentBackupRestoreV3CandidateRecordRead {
  readonly receipt: Readonly<AgentBackupRestoreV3CandidateRecordReceipt>;
  /** Caller-owned plaintext copy; the caller must zeroize it after use. */
  readonly payload: Uint8Array;
}

/** Test-only crash/response-loss seams. Production callers omit this object. */
export interface AgentBackupRestoreV3CandidateRecordLifecycle {
  readonly afterPayloadFinalized?: (
    receipt: Readonly<AgentBackupRestoreV3CandidatePayloadReceipt>,
  ) => void;
  readonly afterDurableReceipt?: (
    receipt: Readonly<AgentBackupRestoreV3CandidateRecordReceipt>,
  ) => void;
}

export interface StageAgentBackupRestoreV3CandidateRecordInput {
  readonly candidateFs: AgentBackupRestoreV3CandidateFs;
  readonly session: Readonly<AgentBackupRestoreV3StagingSession>;
  readonly record: Readonly<AgentBackupRestoreV3StagedRecord>;
  readonly control: Readonly<AgentBackupRestoreV3OperationControl>;
  readonly testOnlyLifecycle?: Readonly<AgentBackupRestoreV3CandidateRecordLifecycle>;
}

export interface ReadAgentBackupRestoreV3CandidateRecordInput {
  readonly candidateFs: AgentBackupRestoreV3CandidateFs;
  readonly session: Readonly<AgentBackupRestoreV3StagingSession>;
  readonly componentIndex: number;
  readonly dataIndex: number;
  readonly control: Readonly<AgentBackupRestoreV3OperationControl>;
}

export class AgentBackupRestoreV3CandidateRecordError extends ElizaError {
  override readonly name = "AgentBackupRestoreV3CandidateRecordError";

  constructor(
    code: string,
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message, {
      code,
      severity: "fatal",
      ...(options?.cause === undefined ? {} : { cause: options.cause }),
    });
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

function recordError(code: string, message: string, cause?: unknown): never {
  throw new AgentBackupRestoreV3CandidateRecordError(code, message, {
    cause,
  });
}

function invokeTestOnlyLifecycleHook<T>(
  hook: ((value: T) => void) | undefined,
  value: T,
  label: string,
): void {
  if (!hook) return;
  if (process.env.NODE_ENV !== "test") {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_TEST_HOOK_FORBIDDEN",
      "Candidate record lifecycle hooks are forbidden outside tests",
    );
  }
  const returned = (hook as (value: T) => unknown)(value);
  if (returned !== undefined) {
    if (returned instanceof Promise) {
      void returned.catch(() => undefined);
    }
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_TEST_HOOK_ASYNC",
      `${label} test hook must settle synchronously`,
    );
  }
}

function sha256Utf8(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function exactDigestMatches(left: string, right: string): boolean {
  if (!SHA256_PATTERN.test(left) || !SHA256_PATTERN.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function requirePlainRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== keys.length ||
    Reflect.ownKeys(value).some((key) => typeof key !== "string")
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      `${label} must be one exact plain data object`,
    );
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join("\0") !== [...keys].sort().join("\0")) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      `${label} fields differ from the exact record contract`,
    );
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
        `${label} cannot contain accessors or hidden fields`,
      );
    }
  }
  return record;
}

function snapshotSession(
  input: Readonly<AgentBackupRestoreV3StagingSession>,
): Readonly<AgentBackupRestoreV3StagingSession> {
  const record = requirePlainRecord(
    input,
    [
      "restoreAttemptId",
      "operationId",
      "expectedManifestSha256",
      "stagingHandle",
      "cleanupHandle",
      "executionToken",
      "cleanupRegistered",
      "isolatedCandidate",
    ],
    "Candidate staging session",
  );
  try {
    return parseAgentBackupRestoreV3StagingSession({
      restoreAttemptId: record.restoreAttemptId,
      operationId: record.operationId,
      expectedManifestSha256: record.expectedManifestSha256,
      stagingHandle: record.stagingHandle,
      cleanupHandle: record.cleanupHandle,
      executionToken: record.executionToken,
      cleanupRegistered: record.cleanupRegistered,
      isolatedCandidate: record.isolatedCandidate,
    });
  } catch (cause) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_SESSION_INVALID",
      "Candidate record session is not exact and canonical",
      cause,
    );
  }
}

function snapshotEntry(
  value: unknown,
): AgentBackupRestoreV3StagedRecord["entry"] {
  if (value === null) return null;
  const record = requirePlainRecord(
    value,
    ["path", "fileOffsetBytes", "fileSizeBytes", "mode", "mtimeMs"],
    "Candidate record entry",
  );
  return Object.freeze({
    path: record.path as string,
    fileOffsetBytes: record.fileOffsetBytes as number,
    fileSizeBytes: record.fileSizeBytes as number,
    mode: record.mode as number,
    mtimeMs: record.mtimeMs as number,
  });
}

interface CopiedRecord {
  readonly receipt: Readonly<AgentBackupRestoreV3StageRecordReceipt>;
  readonly payload: Uint8Array;
}

function assertSnapshotControl(
  control: Readonly<AgentBackupRestoreV3OperationControl>,
): void {
  if (!(control?.signal instanceof AbortSignal)) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CONTROL_INVALID",
      "Candidate record snapshot requires one exact AbortSignal",
    );
  }
  if (control.signal.aborted) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_ABORTED",
      "Candidate record snapshot was cancelled",
      control.signal.reason,
    );
  }
  if (
    !Number.isSafeInteger(control.deadlineEpochMs) ||
    control.deadlineEpochMs <= Date.now()
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_DEADLINE_EXCEEDED",
      "Candidate record snapshot exceeded its exact deadline",
    );
  }
}

function snapshotRecord(
  input: Readonly<AgentBackupRestoreV3StagedRecord>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
): CopiedRecord {
  assertSnapshotControl(control);
  const record = requirePlainRecord(
    input,
    [
      "componentIndex",
      "componentName",
      "dataIndex",
      "offsetBytes",
      "entry",
      "payload",
    ],
    "Candidate staged record",
  );
  const payloadValue = record.payload;
  if (
    !payloadValue ||
    typeof payloadValue !== "object" ||
    isProxy(payloadValue) ||
    !(payloadValue instanceof Uint8Array) ||
    Object.getPrototypeOf(payloadValue) !== Uint8Array.prototype ||
    Object.getOwnPropertyDescriptor(payloadValue, Symbol.iterator) !==
      undefined ||
    !TYPED_ARRAY_BYTE_LENGTH_GETTER ||
    !TYPED_ARRAY_BUFFER_GETTER
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
      "Candidate record payload must be one intrinsic non-proxy Uint8Array",
    );
  }
  let payloadBytes: number;
  let payloadBuffer: unknown;
  try {
    payloadBytes = TYPED_ARRAY_BYTE_LENGTH_GETTER.call(payloadValue) as number;
    payloadBuffer = TYPED_ARRAY_BUFFER_GETTER.call(payloadValue);
  } catch (cause) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
      "Candidate record payload lacks exact TypedArray internal slots",
      cause,
    );
  }
  if (
    payloadBytes > AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES ||
    !(payloadBuffer instanceof ArrayBuffer)
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_INVALID",
      "Candidate record payload exceeds 256 KiB or uses shared storage",
    );
  }
  const payload = new Uint8Array(payloadBytes);
  try {
    INTRINSIC_UINT8_ARRAY_SET.call(payload, payloadValue, 0);
    assertSnapshotControl(control);
    const receipt = AgentBackupRestoreV3StageRecordReceiptSchema.parse({
      componentIndex: record.componentIndex,
      componentName: record.componentName,
      dataIndex: record.dataIndex,
      offsetBytes: record.offsetBytes,
      entry: snapshotEntry(record.entry),
      payloadBytes: payload.byteLength,
      payloadSha256: sha256Bytes(payload),
    });
    if (
      AGENT_BACKUP_RESTORE_V3_STREAM_COMPONENTS[receipt.componentIndex] !==
      receipt.componentName
    ) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
        "Candidate record component name differs from its exact index",
      );
    }
    return Object.freeze({
      receipt: freezeStageReceipt(receipt),
      payload,
    });
  } catch (cause) {
    payload.fill(0);
    if (cause instanceof AgentBackupRestoreV3CandidateRecordError) throw cause;
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      "Candidate record metadata is not exact and canonical",
      cause,
    );
  }
}

function freezeStageReceipt(
  receipt: AgentBackupRestoreV3StageRecordReceipt,
): Readonly<AgentBackupRestoreV3StageRecordReceipt> {
  return Object.freeze({
    ...receipt,
    entry: receipt.entry ? Object.freeze({ ...receipt.entry }) : null,
  });
}

function buildSessionJournal(
  session: Readonly<AgentBackupRestoreV3StagingSession>,
): Readonly<CandidateRecordSessionJournal> {
  const body = Object.freeze({
    version: 1 as const,
    format:
      "elizaos.agent-backup.restore-v3-candidate-record-session.v1" as const,
    restoreAttemptId: session.restoreAttemptId,
    operationId: session.operationId,
    expectedManifestSha256: session.expectedManifestSha256,
    stagingHandleSha256: sha256Utf8(session.stagingHandle),
    cleanupHandleSha256: sha256Utf8(session.cleanupHandle),
    executionTokenSha256: sha256Utf8(session.executionToken),
    cleanupRegistered: true as const,
    isolatedCandidate: true as const,
  });
  return Object.freeze({
    ...body,
    sessionSha256: sha256Utf8(candidateFsCanonicalJson(body)),
  });
}

function validateSessionJournal(
  value: unknown,
  expected: Readonly<CandidateRecordSessionJournal>,
): Readonly<CandidateRecordSessionJournal> {
  const record = requirePlainRecord(
    value,
    [
      "version",
      "format",
      "restoreAttemptId",
      "operationId",
      "expectedManifestSha256",
      "stagingHandleSha256",
      "cleanupHandleSha256",
      "executionTokenSha256",
      "cleanupRegistered",
      "isolatedCandidate",
      "sessionSha256",
    ],
    "Candidate record session journal",
  );
  if (candidateFsCanonicalJson(record) !== candidateFsCanonicalJson(expected)) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_SESSION_CONFLICT",
      "Candidate record session differs from its durable attempt binding",
    );
  }
  return expected;
}

function recordPayloadName(componentIndex: number, dataIndex: number): string {
  return `.restore-v3-record-c${componentIndex}-d${dataIndex}.payload`;
}

function recordReceiptName(componentIndex: number, dataIndex: number): string {
  return `.restore-v3-record-c${componentIndex}-d${dataIndex}.receipt.json`;
}

function commandBody(
  sessionSha256: string,
  receipt: Readonly<AgentBackupRestoreV3StageRecordReceipt>,
  previousReceiptSha256: string,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    context: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_COMMAND_CONTEXT,
    sessionSha256,
    previousReceiptSha256,
    record: receipt,
  });
}

export function computeAgentBackupRestoreV3CandidateRecordCommandSha256(
  sessionInput: Readonly<AgentBackupRestoreV3StagingSession>,
  receiptInput: Readonly<AgentBackupRestoreV3StageRecordReceipt>,
  previousReceiptSha256: string,
): string {
  const session = snapshotSession(sessionInput);
  let receipt: AgentBackupRestoreV3StageRecordReceipt;
  try {
    receipt = AgentBackupRestoreV3StageRecordReceiptSchema.parse(receiptInput);
  } catch (cause) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      "Candidate command receipt is not exact and canonical",
      cause,
    );
  }
  if (
    AGENT_BACKUP_RESTORE_V3_STREAM_COMPONENTS[receipt.componentIndex] !==
      receipt.componentName ||
    !SHA256_PATTERN.test(previousReceiptSha256)
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      "Candidate command component or previous receipt is not exact",
    );
  }
  return sha256Utf8(
    candidateFsCanonicalJson(
      commandBody(
        buildSessionJournal(session).sessionSha256,
        receipt,
        previousReceiptSha256,
      ),
    ),
  );
}

interface DerivedOwnerCapability {
  readonly capability: Uint8Array;
  readonly sha256: string;
}

function deriveOwnerCapability(
  executionToken: string,
  commandSha256: string,
): DerivedOwnerCapability {
  const key = Buffer.from(executionToken, "utf8");
  const commandDigest = Buffer.from(commandSha256, "hex");
  let hmac: Hmac | null = null;
  let digest: Buffer | null = null;
  try {
    hmac = createHmac("sha256", key);
    hmac.update(AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_OWNER_CONTEXT, "utf8");
    hmac.update(Buffer.of(0));
    hmac.update(commandDigest);
    digest = hmac.digest();
    const capability = new Uint8Array(digest.byteLength);
    INTRINSIC_UINT8_ARRAY_SET.call(capability, digest, 0);
    return Object.freeze({
      capability,
      sha256: sha256Bytes(capability),
    });
  } finally {
    digest?.fill(0);
    commandDigest.fill(0);
    key.fill(0);
    hmac?.destroy();
  }
}

function chainGenesis(
  sessionSha256: string,
  componentIndex: number,
  componentName: AgentBackupRestoreV3StreamComponentName,
): string {
  return sha256Utf8(
    candidateFsCanonicalJson({
      context: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CHAIN_CONTEXT,
      kind: "component-genesis",
      sessionSha256,
      componentIndex,
      componentName,
    }),
  );
}

function receiptBody(
  receipt: Omit<AgentBackupRestoreV3CandidateRecordReceipt, "receiptSha256">,
): Omit<AgentBackupRestoreV3CandidateRecordReceipt, "receiptSha256"> {
  return Object.freeze({
    version: 1,
    format: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_FORMAT,
    sessionSha256: receipt.sessionSha256,
    commandSha256: receipt.commandSha256,
    ownerTokenSha256: receipt.ownerTokenSha256,
    payloadName: receipt.payloadName,
    previousReceiptSha256: receipt.previousReceiptSha256,
    record: receipt.record,
    payload: receipt.payload,
  });
}

function freezeRecordReceipt(
  body: Omit<AgentBackupRestoreV3CandidateRecordReceipt, "receiptSha256">,
): Readonly<AgentBackupRestoreV3CandidateRecordReceipt> {
  const exactBody = receiptBody(body);
  return Object.freeze({
    ...exactBody,
    record: freezeStageReceipt({ ...exactBody.record }),
    payload: Object.freeze({ ...exactBody.payload }),
    receiptSha256: sha256Utf8(candidateFsCanonicalJson(exactBody)),
  });
}

function parsePayloadReceipt(
  value: unknown,
): Readonly<AgentBackupRestoreV3CandidatePayloadReceipt> {
  const record = requirePlainRecord(
    value,
    ["device", "inode", "sizeBytes", "sha256"],
    "Candidate record payload receipt",
  );
  if (
    !Number.isSafeInteger(record.sizeBytes) ||
    (record.sizeBytes as number) < 0 ||
    (record.sizeBytes as number) >
      AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES ||
    typeof record.sha256 !== "string" ||
    !SHA256_PATTERN.test(record.sha256) ||
    typeof record.device !== "string" ||
    !UINT64_PATTERN.test(record.device) ||
    BigInt(record.device) > MAX_UINT64 ||
    typeof record.inode !== "string" ||
    !UINT64_PATTERN.test(record.inode) ||
    BigInt(record.inode) > MAX_UINT64
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_INVALID",
      "Candidate payload receipt is not exact and bounded",
    );
  }
  return Object.freeze({
    device: record.device,
    inode: record.inode,
    sizeBytes: record.sizeBytes,
    sha256: record.sha256,
  }) as Readonly<AgentBackupRestoreV3CandidatePayloadReceipt>;
}

function parseRecordReceipt(
  value: unknown,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  sessionJournal: Readonly<CandidateRecordSessionJournal>,
): Readonly<AgentBackupRestoreV3CandidateRecordReceipt> {
  const persisted = requirePlainRecord(
    value,
    [
      "version",
      "format",
      "sessionSha256",
      "commandSha256",
      "ownerTokenSha256",
      "payloadName",
      "previousReceiptSha256",
      "record",
      "payload",
      "receiptSha256",
    ],
    "Candidate record receipt",
  );
  let stageReceipt: AgentBackupRestoreV3StageRecordReceipt;
  try {
    stageReceipt = AgentBackupRestoreV3StageRecordReceiptSchema.parse(
      persisted.record,
    );
  } catch (cause) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_INVALID",
      "Candidate record receipt metadata is malformed",
      cause,
    );
  }
  if (
    AGENT_BACKUP_RESTORE_V3_STREAM_COMPONENTS[stageReceipt.componentIndex] !==
    stageReceipt.componentName
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_INVALID",
      "Candidate record receipt component differs from its exact index",
    );
  }
  const payload = parsePayloadReceipt(persisted.payload);
  if (
    typeof persisted.previousReceiptSha256 !== "string" ||
    !SHA256_PATTERN.test(persisted.previousReceiptSha256)
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_INVALID",
      "Candidate record previous receipt digest is malformed",
    );
  }
  const commandSha256 = sha256Utf8(
    candidateFsCanonicalJson(
      commandBody(
        sessionJournal.sessionSha256,
        stageReceipt,
        persisted.previousReceiptSha256,
      ),
    ),
  );
  const owner = deriveOwnerCapability(session.executionToken, commandSha256);
  try {
    const expectedBody = receiptBody({
      version: 1,
      format: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_FORMAT,
      sessionSha256: sessionJournal.sessionSha256,
      commandSha256,
      ownerTokenSha256: owner.sha256,
      payloadName: recordPayloadName(
        stageReceipt.componentIndex,
        stageReceipt.dataIndex,
      ),
      previousReceiptSha256: persisted.previousReceiptSha256 as string,
      record: freezeStageReceipt(stageReceipt),
      payload,
    });
    if (
      persisted.version !== 1 ||
      persisted.format !== AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_FORMAT ||
      typeof persisted.receiptSha256 !== "string" ||
      !SHA256_PATTERN.test(persisted.receiptSha256) ||
      !exactDigestMatches(
        persisted.sessionSha256 as string,
        sessionJournal.sessionSha256,
      ) ||
      !exactDigestMatches(persisted.commandSha256 as string, commandSha256) ||
      !exactDigestMatches(persisted.ownerTokenSha256 as string, owner.sha256) ||
      persisted.payloadName !== expectedBody.payloadName ||
      payload.sizeBytes !== stageReceipt.payloadBytes ||
      !exactDigestMatches(payload.sha256, stageReceipt.payloadSha256) ||
      !exactDigestMatches(
        persisted.receiptSha256,
        sha256Utf8(candidateFsCanonicalJson(expectedBody)),
      )
    ) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_CONFLICT",
        "Candidate record receipt differs from its session, command, owner, or payload",
      );
    }
    return Object.freeze({
      ...expectedBody,
      receiptSha256: persisted.receiptSha256,
    });
  } finally {
    owner.capability.fill(0);
  }
}

async function createOrReplaySessionJournal(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<Readonly<CandidateRecordSessionJournal>> {
  const expected = buildSessionJournal(session);
  await candidateFs.publishDurableJson(
    SESSION_JOURNAL_NAME,
    expected,
    { maximumBytes: SESSION_JOURNAL_MAXIMUM_BYTES },
    control,
    lock,
  );
  const persisted = await candidateFs.readDurableJson(
    SESSION_JOURNAL_NAME,
    { maximumBytes: SESSION_JOURNAL_MAXIMUM_BYTES },
    control,
    lock,
  );
  if (persisted === null) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_SESSION_CONFLICT",
      "Candidate record session disappeared after durable publication",
    );
  }
  return validateSessionJournal(persisted, expected);
}

async function requireExistingSessionJournal(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<Readonly<CandidateRecordSessionJournal>> {
  const expected = buildSessionJournal(session);
  const persisted = await candidateFs.readDurableJson(
    SESSION_JOURNAL_NAME,
    { maximumBytes: SESSION_JOURNAL_MAXIMUM_BYTES },
    control,
    lock,
  );
  if (persisted === null) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_SESSION_ABSENT",
      "Candidate record read requires an existing durable session binding",
    );
  }
  return validateSessionJournal(persisted, expected);
}

async function readReceiptSlot(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  sessionJournal: Readonly<CandidateRecordSessionJournal>,
  componentIndex: number,
  dataIndex: number,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<Readonly<AgentBackupRestoreV3CandidateRecordReceipt> | null> {
  const value = await candidateFs.readDurableJson(
    recordReceiptName(componentIndex, dataIndex),
    { maximumBytes: RECORD_RECEIPT_MAXIMUM_BYTES },
    control,
    lock,
  );
  if (value === null) return null;
  const receipt = parseRecordReceipt(value, session, sessionJournal);
  if (
    receipt.record.componentIndex !== componentIndex ||
    receipt.record.dataIndex !== dataIndex
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_CONFLICT",
      "Candidate record receipt occupies the wrong deterministic slot",
    );
  }
  return receipt;
}

async function previousChainReceipt(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  sessionJournal: Readonly<CandidateRecordSessionJournal>,
  record: Readonly<AgentBackupRestoreV3StageRecordReceipt>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<string> {
  if (record.dataIndex === 0) {
    if (record.offsetBytes !== 0) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CHAIN_CONFLICT",
        "First candidate record must begin at component offset zero",
      );
    }
    return chainGenesis(
      sessionJournal.sessionSha256,
      record.componentIndex,
      record.componentName,
    );
  }
  const previous = await readReceiptSlot(
    candidateFs,
    session,
    sessionJournal,
    record.componentIndex,
    record.dataIndex - 1,
    control,
    lock,
  );
  if (
    !previous ||
    previous.record.componentName !== record.componentName ||
    previous.record.offsetBytes + previous.record.payloadBytes !==
      record.offsetBytes
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CHAIN_CONFLICT",
      "Candidate record does not extend its exact contiguous predecessor",
    );
  }
  return previous.receiptSha256;
}

async function validateReceiptChain(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  sessionJournal: Readonly<CandidateRecordSessionJournal>,
  receipt: Readonly<AgentBackupRestoreV3CandidateRecordReceipt>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<void> {
  const expectedPrevious = await previousChainReceipt(
    candidateFs,
    session,
    sessionJournal,
    receipt.record,
    control,
    lock,
  );
  if (!exactDigestMatches(receipt.previousReceiptSha256, expectedPrevious)) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CHAIN_CONFLICT",
      "Candidate record receipt is not chained to its exact predecessor",
    );
  }
}

async function readPayloadForReceipt(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  receipt: Readonly<AgentBackupRestoreV3CandidateRecordReceipt>,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<Uint8Array> {
  const owner = deriveOwnerCapability(
    session.executionToken,
    receipt.commandSha256,
  );
  try {
    if (!exactDigestMatches(owner.sha256, receipt.ownerTokenSha256)) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_OWNER_CONFLICT",
        "Candidate record owner differs from its exact execution session",
      );
    }
    const read = await candidateFs.readPayload(
      receipt.payloadName,
      receipt.payload,
      {
        maximumBytes: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES,
        ownerToken: owner.capability,
      },
      control,
      lock,
    );
    return read.payload;
  } finally {
    owner.capability.fill(0);
  }
}

async function revalidateOwnedPayload(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  payloadName: string,
  payloadReceipt: Readonly<AgentBackupRestoreV3CandidatePayloadReceipt>,
  ownerCapability: Uint8Array,
  expectedPayload: Uint8Array,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<void> {
  await candidateFs.assertAuthority(control);
  await candidateFs.assertLockHeld(lock, control);
  const read = await candidateFs.readPayload(
    payloadName,
    payloadReceipt,
    {
      maximumBytes: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES,
      ownerToken: ownerCapability,
    },
    control,
    lock,
  );
  try {
    if (
      read.payload.byteLength !== expectedPayload.byteLength ||
      !timingSafeEqual(read.payload, expectedPayload)
    ) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_CONFLICT",
        "Candidate record payload changed across its test lifecycle seam",
      );
    }
  } finally {
    read.payload.fill(0);
  }
  await candidateFs.assertAuthority(control);
  await candidateFs.assertLockHeld(lock, control);
}

async function revalidateFinalRecord(
  candidateFs: AgentBackupRestoreV3CandidateFs,
  session: Readonly<AgentBackupRestoreV3StagingSession>,
  sessionJournal: Readonly<CandidateRecordSessionJournal>,
  expectedReceipt: Readonly<AgentBackupRestoreV3CandidateRecordReceipt>,
  expectedPayload: Uint8Array,
  control: Readonly<AgentBackupRestoreV3OperationControl>,
  lock: AgentBackupRestoreV3CandidateFsLock,
): Promise<Readonly<AgentBackupRestoreV3CandidateRecordReceipt>> {
  await candidateFs.assertAuthority(control);
  await candidateFs.assertLockHeld(lock, control);
  const persisted = await readReceiptSlot(
    candidateFs,
    session,
    sessionJournal,
    expectedReceipt.record.componentIndex,
    expectedReceipt.record.dataIndex,
    control,
    lock,
  );
  if (
    !persisted ||
    !exactDigestMatches(persisted.receiptSha256, expectedReceipt.receiptSha256)
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_CONFLICT",
      "Candidate record changed before final acknowledgement",
    );
  }
  await validateReceiptChain(
    candidateFs,
    session,
    sessionJournal,
    persisted,
    control,
    lock,
  );
  const payload = await readPayloadForReceipt(
    candidateFs,
    session,
    persisted,
    control,
    lock,
  );
  try {
    if (
      payload.byteLength !== expectedPayload.byteLength ||
      !timingSafeEqual(payload, expectedPayload)
    ) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_CONFLICT",
        "Candidate record payload changed before final acknowledgement",
      );
    }
  } finally {
    payload.fill(0);
  }
  await candidateFs.assertAuthority(control);
  await candidateFs.assertLockHeld(lock, control);
  return persisted;
}

async function stageCopiedRecord(
  input: Omit<
    StageAgentBackupRestoreV3CandidateRecordInput,
    "session" | "record"
  > & {
    readonly session: Readonly<AgentBackupRestoreV3StagingSession>;
    readonly record: Readonly<AgentBackupRestoreV3StageRecordReceipt>;
    readonly payload: Uint8Array;
  },
): Promise<Readonly<AgentBackupRestoreV3CandidateRecordReceipt>> {
  let lock: AgentBackupRestoreV3CandidateFsLock | null = null;
  let writer: AgentBackupRestoreV3CandidatePayloadWriter | null = null;
  let ownerCapability: Uint8Array | null = null;
  let result: Readonly<AgentBackupRestoreV3CandidateRecordReceipt> | null =
    null;
  let primaryFailure: unknown;
  try {
    lock = await input.candidateFs.acquireLock(RECORD_LOCK_NAME, input.control);
    const sessionJournal = await createOrReplaySessionJournal(
      input.candidateFs,
      input.session,
      input.control,
      lock,
    );
    const previousReceiptSha256 = await previousChainReceipt(
      input.candidateFs,
      input.session,
      sessionJournal,
      input.record,
      input.control,
      lock,
    );
    const existing = await readReceiptSlot(
      input.candidateFs,
      input.session,
      sessionJournal,
      input.record.componentIndex,
      input.record.dataIndex,
      input.control,
      lock,
    );
    if (existing) {
      if (
        candidateFsCanonicalJson(existing.record) !==
          candidateFsCanonicalJson(input.record) ||
        !exactDigestMatches(
          existing.previousReceiptSha256,
          previousReceiptSha256,
        )
      ) {
        recordError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_CONFLICT",
          "Candidate record replay differs from its immutable slot",
        );
      }
      result = await revalidateFinalRecord(
        input.candidateFs,
        input.session,
        sessionJournal,
        existing,
        input.payload,
        input.control,
        lock,
      );
    } else {
      const commandSha256 = sha256Utf8(
        candidateFsCanonicalJson(
          commandBody(
            sessionJournal.sessionSha256,
            input.record,
            previousReceiptSha256,
          ),
        ),
      );
      const owner = deriveOwnerCapability(
        input.session.executionToken,
        commandSha256,
      );
      ownerCapability = owner.capability;
      const payloadName = recordPayloadName(
        input.record.componentIndex,
        input.record.dataIndex,
      );
      writer = await input.candidateFs.createPayload(
        payloadName,
        {
          maximumBytes: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_MAXIMUM_BYTES,
          ownerToken: owner.capability,
        },
        input.control,
        lock,
      );
      if (writer.acknowledgedBytes > input.payload.byteLength) {
        recordError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_CONFLICT",
          "Candidate record partial payload exceeds the exact command",
        );
      }
      if (writer.acknowledgedBytes < input.payload.byteLength) {
        await writer.write(
          input.payload.subarray(writer.acknowledgedBytes),
          input.control,
        );
      }
      const payloadReceipt = await writer.finalize(input.control);
      writer = null;
      if (
        payloadReceipt.sizeBytes !== input.record.payloadBytes ||
        !exactDigestMatches(payloadReceipt.sha256, input.record.payloadSha256)
      ) {
        recordError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_PAYLOAD_CONFLICT",
          "Candidate record payload differs from its exact command digest",
        );
      }
      invokeTestOnlyLifecycleHook(
        input.testOnlyLifecycle?.afterPayloadFinalized,
        payloadReceipt,
        "afterPayloadFinalized",
      );
      await revalidateOwnedPayload(
        input.candidateFs,
        payloadName,
        payloadReceipt,
        owner.capability,
        input.payload,
        input.control,
        lock,
      );
      const receipt = freezeRecordReceipt({
        version: 1,
        format: AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_FORMAT,
        sessionSha256: sessionJournal.sessionSha256,
        commandSha256,
        ownerTokenSha256: owner.sha256,
        payloadName,
        previousReceiptSha256,
        record: input.record,
        payload: payloadReceipt,
      });
      await input.candidateFs.publishDurableJson(
        recordReceiptName(input.record.componentIndex, input.record.dataIndex),
        receipt,
        { maximumBytes: RECORD_RECEIPT_MAXIMUM_BYTES },
        input.control,
        lock,
      );
      const persisted = await readReceiptSlot(
        input.candidateFs,
        input.session,
        sessionJournal,
        input.record.componentIndex,
        input.record.dataIndex,
        input.control,
        lock,
      );
      if (
        !persisted ||
        !exactDigestMatches(persisted.receiptSha256, receipt.receiptSha256)
      ) {
        recordError(
          "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_CONFLICT",
          "Candidate record durable receipt could not be replayed exactly",
        );
      }
      invokeTestOnlyLifecycleHook(
        input.testOnlyLifecycle?.afterDurableReceipt,
        persisted,
        "afterDurableReceipt",
      );
      result = await revalidateFinalRecord(
        input.candidateFs,
        input.session,
        sessionJournal,
        persisted,
        input.payload,
        input.control,
        lock,
      );
    }
  } catch (cause) {
    primaryFailure = cause;
  }

  let cleanupFailure: unknown;
  const cleanupFailures: unknown[] = [];
  if (writer) {
    try {
      await writer.close();
      writer = null;
    } catch (cause) {
      cleanupFailures.push(cause);
    }
  }
  if (lock) {
    try {
      await lock.release(input.control);
      lock = null;
    } catch (cause) {
      cleanupFailures.push(cause);
    }
  }
  input.payload.fill(0);
  ownerCapability?.fill(0);
  ownerCapability = null;
  if (cleanupFailures.length === 1) cleanupFailure = cleanupFailures[0];
  if (cleanupFailures.length > 1) {
    cleanupFailure = new AggregateError(cleanupFailures);
  }
  if (primaryFailure !== undefined && cleanupFailure !== undefined) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CLEANUP_FAILED",
      "Candidate record stage and bounded cleanup both failed",
      new AggregateError([primaryFailure, cleanupFailure]),
    );
  }
  if (primaryFailure !== undefined) throw primaryFailure;
  if (cleanupFailure !== undefined) throw cleanupFailure;
  if (!result) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_INVALID",
      "Candidate record stage ended without an exact receipt",
    );
  }
  return result;
}

/** Copies caller-owned plaintext synchronously, then durably stages one slot. */
export function stageAgentBackupRestoreV3CandidateRecord(
  input: Readonly<StageAgentBackupRestoreV3CandidateRecordInput>,
): Promise<Readonly<AgentBackupRestoreV3CandidateRecordReceipt>> {
  const session = snapshotSession(input.session);
  const copied = snapshotRecord(input.record, input.control);
  return stageCopiedRecord({
    candidateFs: input.candidateFs,
    session,
    record: copied.receipt,
    payload: copied.payload,
    control: input.control,
    testOnlyLifecycle: input.testOnlyLifecycle,
  });
}

/** Reads one immutable record and its already-proved FD-bound payload. */
export async function readAgentBackupRestoreV3CandidateRecord(
  input: Readonly<ReadAgentBackupRestoreV3CandidateRecordInput>,
): Promise<Readonly<AgentBackupRestoreV3CandidateRecordRead>> {
  const session = snapshotSession(input.session);
  if (
    !Number.isSafeInteger(input.componentIndex) ||
    input.componentIndex < 0 ||
    !AGENT_BACKUP_RESTORE_V3_STREAM_COMPONENTS[input.componentIndex] ||
    !Number.isSafeInteger(input.dataIndex) ||
    input.dataIndex < 0
  ) {
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_INPUT_INVALID",
      "Candidate record slot is not exact and canonical",
    );
  }
  let lock: AgentBackupRestoreV3CandidateFsLock | null = null;
  let payload: Uint8Array | null = null;
  let receipt: Readonly<AgentBackupRestoreV3CandidateRecordReceipt> | null =
    null;
  let primaryFailure: unknown;
  try {
    lock = await input.candidateFs.acquireLock(RECORD_LOCK_NAME, input.control);
    const sessionJournal = await requireExistingSessionJournal(
      input.candidateFs,
      session,
      input.control,
      lock,
    );
    receipt = await readReceiptSlot(
      input.candidateFs,
      session,
      sessionJournal,
      input.componentIndex,
      input.dataIndex,
      input.control,
      lock,
    );
    if (!receipt) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_ABSENT",
        "Candidate record slot is absent",
      );
    }
    await validateReceiptChain(
      input.candidateFs,
      session,
      sessionJournal,
      receipt,
      input.control,
      lock,
    );
    payload = await readPayloadForReceipt(
      input.candidateFs,
      session,
      receipt,
      input.control,
      lock,
    );
  } catch (cause) {
    primaryFailure = cause;
  }

  let cleanupFailure: unknown;
  try {
    if (lock) {
      await lock.release(input.control);
      lock = null;
    }
  } catch (cause) {
    cleanupFailure = cause;
  }
  if (
    primaryFailure !== undefined ||
    cleanupFailure !== undefined ||
    !payload ||
    !receipt
  ) {
    payload?.fill(0);
    if (primaryFailure !== undefined && cleanupFailure !== undefined) {
      recordError(
        "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_CLEANUP_FAILED",
        "Candidate record read and bounded cleanup both failed",
        new AggregateError([primaryFailure, cleanupFailure]),
      );
    }
    if (primaryFailure !== undefined) throw primaryFailure;
    if (cleanupFailure !== undefined) throw cleanupFailure;
    recordError(
      "AGENT_BACKUP_RESTORE_V3_CANDIDATE_RECORD_RECEIPT_INVALID",
      "Candidate record read ended without an exact result",
    );
  }
  return Object.freeze({ receipt, payload });
}
