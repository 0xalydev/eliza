/**
 * Preserves connector ciphertext and key-file compatibility with real crypto,
 * temporary files and child processes. Delayed real writes exercise exclusive
 * publication, and the harness reaps every child even when readiness fails.
 */

import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  decryptTokenEnvelope,
  encryptTokenPayload,
  resolveTokenEncryptionKey,
} from "./token-encryption.js";

const KEY = Buffer.alloc(32, 7);
const LEGACY_ENVELOPE = {
  __enc: "aes-256-gcm" as const,
  v: 1 as const,
  iv: "AAECAwQFBgcICQoL",
  tag: "M8rZ1OYoJsWd/+uvKkWHzg==",
  ct: "dOSOEX5w9D9G",
};
const tempDirs: string[] = [];
const raceChildPath = fileURLToPath(
  new URL("./fixtures/token-encryption-race-child.ts", import.meta.url),
);

type ChildOutcome =
  | {
      kind: "closed";
      code: number | null;
      signal: NodeJS.Signals | null;
      stdout: string;
      stderr: string;
    }
  | { kind: "spawn-error"; error: Error };
interface Participant {
  child: ChildProcess;
  outcome: Promise<ChildOutcome>;
}

function freshDirectory(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "token-encryption-"));
  tempDirs.push(dir);
  return dir;
}

function startParticipant(dir: string, id: number, mode = "race"): Participant {
  const child = spawn("bun", [raceChildPath, dir, String(id), mode], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const outcome = new Promise<ChildOutcome>((resolve) => {
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => resolve({ kind: "spawn-error", error }));
    child.on("close", (code, signal) =>
      resolve({ kind: "closed", code, signal, stdout, stderr }),
    );
  });
  return { child, outcome };
}

async function stopParticipants(participants: Participant[]): Promise<void> {
  for (const { child } of participants) {
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
  }
  await Promise.all(participants.map(({ outcome }) => outcome));
}

async function successfulKey(participant: Participant): Promise<string> {
  const outcome = await participant.outcome;
  if (outcome.kind === "spawn-error") throw outcome.error;
  if (outcome.code !== 0) {
    throw new Error(
      `Key participant exited ${outcome.code}/${outcome.signal}: ${outcome.stderr}`,
    );
  }
  return outcome.stdout;
}

async function waitForFiles(
  dir: string,
  names: string[],
  timeoutMs = 10_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (names.every((name) => fs.existsSync(path.join(dir, name)))) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(
    `Timed out waiting for key-creation participants: ${names.join(", ")}`,
  );
}

afterEach(() => {
  for (const dir of tempDirs.splice(0))
    fs.rmSync(dir, { recursive: true, force: true });
});

describe("connector token encryption compatibility", () => {
  it("decrypts the exact v1 AES-256-GCM envelope emitted by legacy plugins", () => {
    expect(decryptTokenEnvelope(LEGACY_ENVELOPE, KEY)).toBe("legacy-v1");
  });

  it("emits the unchanged discriminator/version and round-trips plaintext", () => {
    const envelope = encryptTokenPayload("current", KEY);
    expect({ algorithm: envelope.__enc, version: envelope.v }).toEqual({
      algorithm: "aes-256-gcm",
      version: 1,
    });
    expect(decryptTokenEnvelope(envelope, KEY)).toBe("current");
  });

  it("preserves env decoding and the .encryption-key path and mode", () => {
    expect(
      resolveTokenEncryptionKey("/unused", {
        ELIZA_TOKEN_ENCRYPTION_KEY: KEY.toString("hex"),
      }).equals(KEY),
    ).toBe(true);
    const dir = freshDirectory();
    const generated = resolveTokenEncryptionKey(dir, {});
    const file = path.join(dir, ".encryption-key");
    expect(generated).toHaveLength(32);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(resolveTokenEncryptionKey(dir, {}).equals(generated)).toBe(true);
  });

  it("returns the exclusive-create winner's key to every concurrent process", async () => {
    const dir = freshDirectory();
    const participants = Array.from({ length: 16 }, (_, id) =>
      startParticipant(dir, id),
    );
    try {
      await waitForFiles(
        dir,
        participants.map((_, id) => `ready-${id}`),
      );
      fs.writeFileSync(path.join(dir, "start"), "go");
      const keys = await Promise.all(participants.map(successfulKey));
      expect(new Set(keys).size).toBe(1);
      expect(keys[0]).toHaveLength(64);
      expect(
        fs.readFileSync(path.join(dir, ".encryption-key"), "utf8").trim(),
      ).toBe(Buffer.from(keys[0], "hex").toString("base64"));
      expect(fs.statSync(path.join(dir, ".encryption-key")).mode & 0o777).toBe(
        0o600,
      );
      expect(
        fs.readdirSync(dir).filter((name) => name.endsWith(".tmp")),
      ).toEqual([]);
    } finally {
      await stopParticipants(participants);
    }
  }, 30_000);

  it("never exposes an incomplete key while a competing creator is paused before its write", async () => {
    const dir = freshDirectory();
    const paused = startParticipant(dir, 0, "hold-write");
    try {
      await waitForFiles(dir, ["paused"]);
      const winner = resolveTokenEncryptionKey(dir, {});
      const envelope = encryptTokenPayload("concurrent credential", winner);
      fs.writeFileSync(path.join(dir, "release"), "continue");
      const delayedKey = Buffer.from(await successfulKey(paused), "hex");
      expect(decryptTokenEnvelope(envelope, delayedKey)).toBe(
        "concurrent credential",
      );
      expect(delayedKey.equals(winner)).toBe(true);
      expect(resolveTokenEncryptionKey(dir, {}).equals(winner)).toBe(true);
      expect(fs.readdirSync(dir).sort()).toEqual([
        ".encryption-key",
        "paused",
        "release",
      ]);
    } finally {
      fs.writeFileSync(path.join(dir, "release"), "continue");
      await stopParticipants([paused]);
    }
  }, 30_000);

  it("cleans its candidate when a competing publication contains an invalid key", async () => {
    const dir = freshDirectory();
    const paused = startParticipant(dir, 0, "hold-write");
    try {
      await waitForFiles(dir, ["paused"]);
      const file = path.join(dir, ".encryption-key");
      fs.writeFileSync(file, "invalid-key", { flag: "wx", mode: 0o600 });
      fs.writeFileSync(path.join(dir, "release"), "continue");
      const outcome = await paused.outcome;
      if (outcome.kind !== "closed") throw outcome.error;
      expect(outcome.code).not.toBe(0);
      expect(outcome.stderr).toContain("exactly 32 bytes");
      expect(fs.readFileSync(file, "utf8")).toBe("invalid-key");
      expect(fs.readdirSync(dir).sort()).toEqual([
        ".encryption-key",
        "paused",
        "release",
      ]);
    } finally {
      fs.writeFileSync(path.join(dir, "release"), "continue");
      await stopParticipants([paused]);
    }
  }, 30_000);

  it("rejects an invalid existing key without replacing it or creating a candidate", () => {
    const dir = freshDirectory();
    const file = path.join(dir, ".encryption-key");
    fs.writeFileSync(file, "invalid-key", { mode: 0o600 });
    expect(() => resolveTokenEncryptionKey(dir, {})).toThrow(
      /exactly 32 bytes/,
    );
    expect(fs.readFileSync(file, "utf8")).toBe("invalid-key");
    expect(fs.readdirSync(dir)).toEqual([".encryption-key"]);
  });

  it("reaps a real participant when readiness times out", async () => {
    const dir = freshDirectory();
    const participant = startParticipant(dir, 0, "no-ready");
    try {
      await expect(waitForFiles(dir, ["never-ready"], 50)).rejects.toThrow(
        /Timed out/,
      );
    } finally {
      await stopParticipants([participant]);
    }
    const outcome = await participant.outcome;
    expect(outcome.kind).toBe("closed");
    if (outcome.kind !== "closed") throw outcome.error;
    expect(outcome.signal).toBe("SIGKILL");
  });
});
