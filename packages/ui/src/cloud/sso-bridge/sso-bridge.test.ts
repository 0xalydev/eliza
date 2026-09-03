/** Pure-logic contract for the SSO bridge client module: hostname role table, returnTo sanitation, state-nonce + PKCE-verifier lifecycle, loop guard, logged-out marker, URL builders, and the mint/exchange/burn fetch wrappers — jsdom storage + hand-rolled fetch stubs, nothing mocked at module level. */
// @vitest-environment jsdom

import {
  registerStewardTokenPersistence,
  STEWARD_TOKEN_KEY,
  writeStoredStewardToken,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { appModeNavigation } from "../app-mode/app-mode";
import {
  peekPendingOnboardingSession,
  storePendingOnboardingSession,
  TELEGRAM_ACCOUNT_CLAIM_PURPOSE,
} from "../join/lib/onboarding-continuation";
import {
  consumeStewardServerCookieSynced,
  invalidateStewardServerCookieSyncMarker,
  markStewardServerCookieSynced,
} from "../lib/steward-session-cookie-sync-marker";
import {
  buildBridgeExchangeUrl,
  buildBridgeMintUrl,
  buildSsoBridgeErrorUrl,
  burnSsoBridgeCode,
  clearSsoBridgeAttempt,
  clearSsoLoggedOut,
  consumeSsoBridgeState,
  consumeSsoBridgeVerifier,
  createSsoBridgeHandshake,
  isSsoLoggedOut,
  isWellFormedSsoChallenge,
  isWellFormedSsoCode,
  isWellFormedSsoState,
  markSsoBridgeAttempt,
  markSsoLoggedOut,
  mintSsoCode,
  pairedAppLoginUrlForMintHost,
  pairedAppOrigin,
  performSsoExchange,
  prepareSsoAccountSwitch,
  redirectToSsoBridge,
  type SsoBridgeFetch,
  type SsoBridgeLockManager,
  sanitizeBridgeReturnTo,
  shouldAttemptSsoBridge,
  shouldAutoBridgeToSso,
  signOutFromSsoBridgedHost,
  ssoBridgeRoleForHostname,
} from "./sso-bridge";

const STATE = "a".repeat(64);
const CHALLENGE = "c".repeat(64);
const VERIFIER = "d".repeat(64);
const CODE = `esso_${"b".repeat(64)}`;
const NEXT_CODE = `esso_${"f".repeat(64)}`;
const SSO_LOGGED_OUT_KEY = "eliza_sso_logged_out";
const SSO_LOGOUT_GENERATION_KEY = "eliza_sso_logout_generation";
const SSO_FINALIZATION_INTENT_KEY = "eliza_sso_finalization_intent";

class SerialSsoBridgeLockManager implements SsoBridgeLockManager {
  private tail: Promise<void> = Promise.resolve();

  async request<T>(
    _name: string,
    options: { mode: "exclusive"; signal: AbortSignal },
    callback: () => T | PromiseLike<T>,
  ): Promise<T> {
    const previous = this.tail;
    let release: () => void = () => {};
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    if (options.signal.aborted) {
      release();
      throw new DOMException("Lock request aborted", "AbortError");
    }
    try {
      return await callback();
    } finally {
      release();
    }
  }
}

class ManualSsoBridgeLockManager implements SsoBridgeLockManager {
  private readonly pending: Array<() => void> = [];

  request<T>(
    _name: string,
    options: { mode: "exclusive"; signal: AbortSignal },
    callback: () => T | PromiseLike<T>,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.pending.push(() => {
        if (options.signal.aborted) {
          reject(new DOMException("Lock request aborted", "AbortError"));
          return;
        }
        Promise.resolve(callback()).then(resolve, reject);
      });
    });
  }

  releaseNext(): void {
    const release = this.pending.shift();
    if (!release) throw new Error("No pending SSO lock request");
    release();
  }

  get pendingCount(): number {
    return this.pending.length;
  }
}

function installSsoBridgeLockManager(
  lockManager: SsoBridgeLockManager = new SerialSsoBridgeLockManager(),
): void {
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: lockManager,
  });
}

function simulateOtherRealmLogout(nonce: string): void {
  localStorage.setItem(SSO_LOGOUT_GENERATION_KEY, nonce);
  localStorage.setItem(SSO_FINALIZATION_INTENT_KEY, nonce);
  localStorage.setItem(SSO_LOGGED_OUT_KEY, "1");
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64url(value: unknown): string {
  return btoa(JSON.stringify(value))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function jwt(payload: Record<string, unknown>): string {
  return [
    base64url({ alg: "none", typ: "JWT" }),
    base64url(payload),
    "sig",
  ].join(".");
}

function liveToken(userId: string = "u1"): string {
  return jwt({ userId, exp: Math.floor(Date.now() / 1000) + 3600 });
}

function logoutBarrierResponse(): Response {
  return json(200, {
    success: true,
    logoutProofVersion: 1,
    barrierState: "confirmed",
    barrierConfirmed: true,
    message: "Logged out successfully",
  });
}

function logoutAlreadyAbsentResponse(): Response {
  return json(200, {
    success: true,
    logoutProofVersion: 1,
    barrierState: "already_absent",
    barrierConfirmed: false,
    message: "Logged out successfully",
  });
}

function clearCookies(): void {
  for (const part of document.cookie.split(";")) {
    const name = part.split("=")[0]?.trim();
    if (name)
      // biome-ignore lint/suspicious/noDocumentCookie: jsdom must clear the synchronous cookie jar the bridge reads.
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  }
}

beforeEach(() => {
  installSsoBridgeLockManager();
  invalidateStewardServerCookieSyncMarker();
  localStorage.clear();
  sessionStorage.clear();
  clearCookies();
});

afterEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  clearCookies();
  Reflect.deleteProperty(navigator, "locks");
});

describe("ssoBridgeRoleForHostname", () => {
  it("exact allowlist only — prod pair", () => {
    expect(ssoBridgeRoleForHostname("cloud.eliza.app")).toBe("exchange");
    expect(ssoBridgeRoleForHostname("eliza.app")).toBe("mint");
    expect(ssoBridgeRoleForHostname("www.eliza.app")).toBe("mint");
  });

  it("staging pair maps to itself", () => {
    expect(ssoBridgeRoleForHostname("cloud-staging.eliza.app")).toBe(
      "exchange",
    );
    expect(ssoBridgeRoleForHostname("staging.eliza.app")).toBe("mint");
  });

  it("everything else is inert", () => {
    for (const host of [
      "localhost",
      "127.0.0.1",
      "elizacloud.ai",
      "app.elizacloud.ai",
      "dev.elizacloud.ai",
      "blob.elizacloud.ai",
      "abc12345.apps.elizacloud.ai",
      "some-sandbox-id.elizacloud.ai",
      "elizacloud.ai.evil.com",
      "app.elizacloud.ai.evil.com",
      "",
    ]) {
      expect(ssoBridgeRoleForHostname(host)).toBe("none");
    }
  });

  it("is case-insensitive", () => {
    expect(ssoBridgeRoleForHostname("Cloud.Eliza.App")).toBe("exchange");
  });
});

describe("sanitizeBridgeReturnTo", () => {
  it("keeps ordinary relative paths", () => {
    expect(sanitizeBridgeReturnTo("/chat?x=1#y")).toBe("/chat?x=1#y");
    expect(sanitizeBridgeReturnTo("/")).toBe("/");
    expect(sanitizeBridgeReturnTo("/auth/bridged")).toBe("/auth/bridged");
  });

  it("rejects open-redirect shapes to /", () => {
    expect(sanitizeBridgeReturnTo("//evil.com")).toBe("/");
    expect(sanitizeBridgeReturnTo("/\\evil.com")).toBe("/");
    expect(sanitizeBridgeReturnTo("/a\\b")).toBe("/");
    expect(sanitizeBridgeReturnTo("https://evil.com")).toBe("/");
    expect(sanitizeBridgeReturnTo("javascript:alert(1)")).toBe("/");
    expect(sanitizeBridgeReturnTo("chat")).toBe("/");
    expect(sanitizeBridgeReturnTo("")).toBe("/");
    expect(sanitizeBridgeReturnTo(null)).toBe("/");
    expect(sanitizeBridgeReturnTo(`/${"a".repeat(2100)}`)).toBe("/");
  });

  it("rejects the bridge path itself (self-loop)", () => {
    expect(sanitizeBridgeReturnTo("/auth/bridge")).toBe("/");
    expect(sanitizeBridgeReturnTo("/auth/bridge?code=x")).toBe("/");
  });
});

describe("buildSsoBridgeErrorUrl", () => {
  it("preserves a safe deep-link for local recovery", () => {
    expect(
      buildSsoBridgeErrorUrl("sync_failed", "/chat?thread=one#latest"),
    ).toBe(
      "/auth/error?reason=sync_failed&returnTo=%2Fchat%3Fthread%3Done%23latest",
    );
  });

  it("fails a cross-origin recovery target closed to the local root", () => {
    expect(
      buildSsoBridgeErrorUrl("auth_failed", "https://evil.example/chat"),
    ).toBe("/auth/error?reason=auth_failed&returnTo=%2F");
  });
});

describe("pairedAppLoginUrlForMintHost", () => {
  it("restarts a mint-host recovery on the paired app and preserves its deep-link", () => {
    expect(
      pairedAppLoginUrlForMintHost(
        "staging.eliza.app",
        "/chat?thread=one#latest",
      ),
    ).toBe(
      "https://cloud-staging.eliza.app/login?returnTo=%2Fchat%3Fthread%3Done%23latest",
    );
  });

  it("is inert off a mint host and sanitizes an unsafe destination", () => {
    expect(
      pairedAppLoginUrlForMintHost("cloud-staging.eliza.app", "/chat"),
    ).toBeNull();
    expect(
      pairedAppLoginUrlForMintHost(
        "staging.eliza.app",
        "https://evil.example/steal",
      ),
    ).toBe("https://cloud-staging.eliza.app/login?returnTo=%2F");
  });
});

describe("handshake secrets (state nonce + PKCE verifier)", () => {
  it("creates a well-formed nonce and verifier, stored for single-shot consumption; the challenge is the verifier's sha256", async () => {
    const handshake = await createSsoBridgeHandshake();
    expect(handshake).not.toBeNull();
    expect(isWellFormedSsoState(handshake?.state)).toBe(true);
    expect(isWellFormedSsoChallenge(handshake?.challenge)).toBe(true);

    expect(consumeSsoBridgeState()).toBe(handshake?.state ?? "");
    // Consumption is destructive: a second read yields nothing.
    expect(consumeSsoBridgeState()).toBeNull();

    const verifier = consumeSsoBridgeVerifier();
    expect(isWellFormedSsoChallenge(verifier)).toBe(true);
    // The verifier itself NEVER equals the challenge that rode the URL…
    expect(verifier).not.toBe(handshake?.challenge);
    // …but commits to it.
    expect(await sha256Hex(verifier ?? "")).toBe(handshake?.challenge ?? "");
    expect(consumeSsoBridgeVerifier()).toBeNull();
  });

  it("does not navigate when logout wins while the PKCE digest is pending", async () => {
    let resolveDigest: (value: ArrayBuffer) => void = () => {};
    const pendingDigest = new Promise<ArrayBuffer>((resolve) => {
      resolveDigest = resolve;
    });
    const digest = vi
      .spyOn(globalThis.crypto.subtle, "digest")
      .mockReturnValueOnce(pendingDigest);
    const replace = vi
      .spyOn(appModeNavigation, "replace")
      .mockImplementation(() => {});

    try {
      const redirect = redirectToSsoBridge("/join", "cloud.eliza.app");
      await vi.waitFor(() => expect(digest).toHaveBeenCalledTimes(1));
      markSsoLoggedOut();
      resolveDigest(new Uint8Array(32).buffer);

      await expect(redirect).resolves.toBe(false);
      expect(replace).not.toHaveBeenCalled();
      expect(sessionStorage.getItem("eliza_sso_bridge_state")).toBeNull();
      expect(sessionStorage.getItem("eliza_sso_bridge_verifier")).toBeNull();
      expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
    } finally {
      digest.mockRestore();
      replace.mockRestore();
    }
  });

  it("rejects malformed echoes", () => {
    expect(isWellFormedSsoState("")).toBe(false);
    expect(isWellFormedSsoState(null)).toBe(false);
    expect(isWellFormedSsoState("A".repeat(64))).toBe(false);
    expect(isWellFormedSsoState("a".repeat(63))).toBe(false);
    expect(isWellFormedSsoChallenge("")).toBe(false);
    expect(isWellFormedSsoChallenge("g".repeat(64))).toBe(false);
  });
});

describe("loop guard", () => {
  it("blocks re-attempts inside the window, allows after it", () => {
    expect(shouldAttemptSsoBridge()).toBe(true);
    markSsoBridgeAttempt(1_000_000);
    expect(shouldAttemptSsoBridge(1_000_000 + 60_000)).toBe(false);
    expect(shouldAttemptSsoBridge(1_000_000 + 6 * 60 * 1000)).toBe(true);
    clearSsoBridgeAttempt();
    expect(shouldAttemptSsoBridge(1_000_000 + 60_000)).toBe(true);
  });
});

describe("logged-out marker", () => {
  it("persists until cleared", () => {
    expect(isSsoLoggedOut()).toBe(false);
    markSsoLoggedOut();
    expect(isSsoLoggedOut()).toBe(true);
    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
    clearSsoLoggedOut();
    expect(isSsoLoggedOut()).toBe(false);
  });
});

describe("handshake URLs", () => {
  it("pairs prod app host with prod dashboard; mint carries state + challenge, exchange carries code + state — never the verifier", () => {
    expect(
      buildBridgeMintUrl("cloud.eliza.app", STATE, CHALLENGE, "/chat"),
    ).toBe(
      `https://eliza.app/auth/bridge?state=${STATE}&challenge=${CHALLENGE}&returnTo=%2Fchat`,
    );
    expect(buildBridgeExchangeUrl("eliza.app", CODE, STATE, "/chat")).toBe(
      `https://cloud.eliza.app/auth/bridge?code=${CODE}&state=${STATE}&returnTo=%2Fchat`,
    );
    expect(pairedAppOrigin("www.eliza.app")).toBe("https://cloud.eliza.app");
  });

  it("pairs staging with staging — never across environments", () => {
    expect(
      buildBridgeMintUrl("cloud-staging.eliza.app", STATE, CHALLENGE, "/"),
    ).toContain("https://staging.eliza.app/auth/bridge");
    expect(
      buildBridgeExchangeUrl("staging.eliza.app", CODE, STATE, "/"),
    ).toContain("https://cloud-staging.eliza.app/auth/bridge");
    expect(pairedAppOrigin("staging.eliza.app")).toBe(
      "https://cloud-staging.eliza.app",
    );
  });

  it("wrong-side or unknown hostnames build nothing", () => {
    expect(buildBridgeMintUrl("eliza.app", STATE, CHALLENGE, "/")).toBeNull();
    expect(buildBridgeMintUrl("localhost", STATE, CHALLENGE, "/")).toBeNull();
    expect(
      buildBridgeExchangeUrl("cloud.eliza.app", CODE, STATE, "/"),
    ).toBeNull();
    expect(buildBridgeExchangeUrl("localhost", CODE, STATE, "/")).toBeNull();
    expect(pairedAppOrigin("cloud.eliza.app")).toBeNull();
    expect(pairedAppOrigin("localhost")).toBeNull();
  });

  it("malformed state or challenge builds nothing", () => {
    expect(
      buildBridgeMintUrl("cloud.eliza.app", "junk", CHALLENGE, "/"),
    ).toBeNull();
    expect(
      buildBridgeMintUrl("cloud.eliza.app", STATE, "junk", "/"),
    ).toBeNull();
  });

  it("sanitizes returnTo in both builders", () => {
    expect(
      buildBridgeMintUrl("cloud.eliza.app", STATE, CHALLENGE, "//evil.com"),
    ).toContain("returnTo=%2F");
    expect(
      buildBridgeExchangeUrl("eliza.app", CODE, STATE, "https://evil.com"),
    ).toContain("returnTo=%2F");
  });
});

describe("shouldAutoBridgeToSso", () => {
  it("requires the exchange role", () => {
    expect(shouldAutoBridgeToSso("eliza.app")).toBe(false);
    expect(shouldAutoBridgeToSso("localhost")).toBe(false);
    expect(shouldAutoBridgeToSso("cloud.eliza.app")).toBe(true);
  });

  it("starts the auth-origin handoff without a cross-host cookie hint", () => {
    expect(document.cookie).not.toContain("steward-authed=1");
    expect(shouldAutoBridgeToSso("cloud.eliza.app")).toBe(true);
  });

  it("honors the explicit logged-out marker", () => {
    markSsoLoggedOut();
    expect(shouldAutoBridgeToSso("cloud.eliza.app")).toBe(false);
    clearSsoLoggedOut();
    expect(shouldAutoBridgeToSso("cloud.eliza.app")).toBe(true);
  });

  it("honors the loop guard", () => {
    markSsoBridgeAttempt();
    expect(shouldAutoBridgeToSso("cloud.eliza.app")).toBe(false);
  });
});

describe("code shape", () => {
  it("accepts only esso_-prefixed 64-hex codes", () => {
    expect(isWellFormedSsoCode(CODE)).toBe(true);
    expect(isWellFormedSsoCode("esso_short")).toBe(false);
    expect(isWellFormedSsoCode(`eac_${"b".repeat(64)}`)).toBe(false);
    expect(isWellFormedSsoCode(null)).toBe(false);
  });
});

type FetchCall = { url: string; init: RequestInit | undefined };

function fetchStub(responder: (url: string) => Response): {
  fn: typeof fetch;
  calls: FetchCall[];
} {
  const calls: FetchCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    return Promise.resolve(responder(url));
  }) as typeof fetch;
  return { fn, calls };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function stewardSessionResponse(userId: string = "u1"): Response {
  return json(200, {
    ok: true,
    userId,
    stewardUserId: `steward-${userId}`,
  });
}

describe("mintSsoCode", () => {
  it("refuses without a local session", async () => {
    const { fn, calls } = fetchStub(() => json(200, { ok: true, code: CODE }));
    const result = await mintSsoCode("eliza.app", CHALLENGE, fn);
    expect(result).toEqual({ ok: false, error: "No local session" });
    expect(calls).toEqual([]);
  });

  it("POSTs the localStorage token as Bearer with the app origin's challenge", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, liveToken());
    const { fn, calls } = fetchStub(() => json(200, { ok: true, code: CODE }));
    const result = await mintSsoCode("eliza.app", CHALLENGE, fn);
    expect(result).toEqual({ ok: true, code: CODE });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://eliza.app/api/auth/sso-bridge/mint");
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get("authorization")).toBe(
      `Bearer ${localStorage.getItem(STEWARD_TOKEN_KEY)}`,
    );
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      codeChallenge: CHALLENGE,
    });
  });

  it("refuses a malformed challenge without calling out", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, liveToken());
    const { fn, calls } = fetchStub(() => json(200, { ok: true, code: CODE }));
    const result = await mintSsoCode("eliza.app", "junk", fn);
    expect(result.ok).toBe(false);
    expect(calls).toEqual([]);
  });

  it("maps HTTP failures and malformed bodies to failures", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, liveToken());
    const denied = await mintSsoCode(
      "eliza.app",
      CHALLENGE,
      fetchStub(() => json(401, { error: "nope" })).fn,
    );
    expect(denied.ok).toBe(false);
    const junkCode = await mintSsoCode(
      "eliza.app",
      CHALLENGE,
      fetchStub(() => json(200, { ok: true, code: "not-a-code" })).fn,
    );
    expect(junkCode.ok).toBe(false);
  });

  it("bounds an unresolved mint and permits the next attempt", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, liveToken());
    let signal: AbortSignal | null = null;
    const hangingFetch = ((_input: RequestInfo | URL, init?: RequestInit) => {
      signal = init?.signal ?? null;
      return new Promise<Response>(() => {});
    }) as typeof fetch;
    vi.useFakeTimers();

    try {
      const timedOut = mintSsoCode("eliza.app", CHALLENGE, hangingFetch);
      await vi.advanceTimersByTimeAsync(0);
      expect(signal).toBeInstanceOf(AbortSignal);
      await vi.advanceTimersByTimeAsync(10_000);
      await expect(timedOut).resolves.toMatchObject({ ok: false });
      expect((signal as AbortSignal | null)?.aborted).toBe(true);

      const retry = mintSsoCode(
        "eliza.app",
        CHALLENGE,
        fetchStub(() => json(200, { ok: true, code: CODE })).fn,
      );
      await expect(retry).resolves.toEqual({ ok: true, code: CODE });
    } finally {
      vi.useRealTimers();
    }
  });

  it("is inert off the deployed host map", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, liveToken());
    const { fn, calls } = fetchStub(() => json(200, { ok: true, code: CODE }));
    const result = await mintSsoCode("localhost", CHALLENGE, fn);
    expect(result.ok).toBe(false);
    expect(calls).toEqual([]);
  });
});

describe("performSsoExchange", () => {
  it("fails closed before exchange when Web Locks are unavailable", async () => {
    const { fn, calls } = fetchStub(() =>
      json(200, { ok: true, token: liveToken() }),
    );

    await expect(
      performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn, () => true, {
        lockManager: null,
      }),
    ).rejects.toThrow("Web Locks are unavailable for SSO coordination");
    expect(calls).toHaveLength(0);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("bounds Web Lock acquisition before mutating session authority", async () => {
    const lockManager: SsoBridgeLockManager = {
      request: (_name, options) =>
        new Promise((_resolve, reject) => {
          const rejectAborted = () =>
            reject(new DOMException("Lock request aborted", "AbortError"));
          if (options.signal.aborted) rejectAborted();
          else
            options.signal.addEventListener("abort", rejectAborted, {
              once: true,
            });
        }),
    };
    const { fn, calls } = fetchStub(() =>
      json(200, { ok: true, token: liveToken() }),
    );
    vi.useFakeTimers();

    try {
      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
        () => true,
        { lockManager, lockTimeoutMs: 25 },
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(calls).toHaveLength(1);
      const rejection = expect(exchange).rejects.toThrow(
        "Timed out waiting for SSO session coordination",
      );
      await vi.advanceTimersByTimeAsync(25);
      await rejection;
    } finally {
      vi.useRealTimers();
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("POSTs code + verifier, hydrates the local session, clears the bridge markers", async () => {
    markSsoBridgeAttempt();
    markSsoLoggedOut();
    const token = liveToken();
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token })
        : stewardSessionResponse(),
    );
    const events: string[] = [];
    const listener = () => events.push("steward-token-sync");
    window.addEventListener("steward-token-sync", listener);
    try {
      const result = await performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
      );
      expect(result).toEqual({ ok: true });
    } finally {
      window.removeEventListener("steward-token-sync", listener);
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(calls[0].url).toBe(
      "https://cloud.eliza.app/api/auth/sso-bridge/exchange",
    );
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      code: CODE,
      codeVerifier: VERIFIER,
    });
    expect(calls[1].url).toContain("/api/auth/steward-session");
    expect(consumeStewardServerCookieSynced(token, calls[1].url)).toBe(true);
    expect(events).toEqual(["steward-token-sync"]);
    expect(shouldAttemptSsoBridge()).toBe(true);
    expect(isSsoLoggedOut()).toBe(false);
  });

  it("fails closed when cookie sync returns a malformed 2xx body", async () => {
    const token = liveToken();
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token })
        : json(200, {
            ok: true,
            userId: "u1",
            stewardUserId: "",
          }),
    );
    const diagnostics: Array<{ scope?: unknown }> = [];
    const listener = (event: Event) => {
      diagnostics.push((event as CustomEvent<{ scope?: unknown }>).detail);
    };
    window.addEventListener("eliza:renderer-diagnostic", listener);

    try {
      await expect(
        performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn),
      ).resolves.toEqual({
        ok: false,
        error: "Could not establish the Eliza Cloud browser session",
      });
    } finally {
      window.removeEventListener("eliza:renderer-diagnostic", listener);
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(consumeStewardServerCookieSynced(token, calls[1].url)).toBe(false);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        scope: "steward.sso-bridge.cookie-sync-response",
      }),
    );
  });

  it("bounds an unresolved exchange and permits the next attempt", async () => {
    let signal: AbortSignal | null = null;
    const hangingFetch: SsoBridgeFetch = (_input, init) => {
      signal = init?.signal ?? null;
      return new Promise<Response>(() => {});
    };
    vi.useFakeTimers();

    try {
      const timedOut = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        hangingFetch,
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(signal).toBeInstanceOf(AbortSignal);
      await vi.advanceTimersByTimeAsync(10_000);
      await expect(timedOut).resolves.toMatchObject({ ok: false });
      expect((signal as AbortSignal | null)?.aborted).toBe(true);

      const retryToken = liveToken("retry-user");
      const retry = fetchStub((url) =>
        url.includes("/sso-bridge/exchange")
          ? json(200, { ok: true, token: retryToken })
          : stewardSessionResponse("retry-user"),
      );
      await expect(
        performSsoExchange(NEXT_CODE, VERIFIER, "cloud.eliza.app", retry.fn),
      ).resolves.toEqual({ ok: true });
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(retryToken);
    } finally {
      vi.useRealTimers();
    }
  });

  it("propagates an unexpected token-persistence failure", async () => {
    const persistenceFailure = new Error("secure-store persistence failed");
    const unregister = registerStewardTokenPersistence(async () => {
      throw persistenceFailure;
    });
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token: liveToken() })
        : stewardSessionResponse(),
    );

    try {
      await expect(
        performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn),
      ).rejects.toMatchObject({
        name: "StewardTokenPersistenceError",
        message: persistenceFailure.message,
        cause: persistenceFailure,
      });
    } finally {
      unregister();
    }

    expect(calls).toHaveLength(1);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("refuses a superseded exchange while token persistence is queued without follow-up effects", async () => {
    markSsoBridgeAttempt();
    markSsoLoggedOut();
    let releaseQueueOwner: () => void = () => {};
    const queueOwnerPersistence = new Promise<void>((resolve) => {
      releaseQueueOwner = resolve;
    });
    let markQueueOwned: () => void = () => {};
    const queueOwned = new Promise<void>((resolve) => {
      markQueueOwned = resolve;
    });
    const persistedTokens: string[] = [];
    const unregister = registerStewardTokenPersistence(async (token) => {
      persistedTokens.push(token);
      if (token === "queue-owner-token") {
        markQueueOwned();
        await queueOwnerPersistence;
      }
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
    });
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token: liveToken() })
        : stewardSessionResponse(),
    );
    const events: string[] = [];
    const listener = () => events.push("steward-token-sync");
    window.addEventListener("steward-token-sync", listener);
    let current = true;
    const isCurrent = vi.fn(() => current);

    try {
      const queueOwner = writeStoredStewardToken("queue-owner-token");
      await queueOwned;
      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
        isCurrent,
      );
      await vi.waitFor(() => expect(calls).toHaveLength(1));
      await Promise.resolve();
      expect(isCurrent).not.toHaveBeenCalled();

      current = false;
      releaseQueueOwner();
      await queueOwner;
      await expect(exchange).resolves.toEqual({
        ok: false,
        error: "SSO exchange superseded",
      });
    } finally {
      releaseQueueOwner();
      unregister();
      window.removeEventListener("steward-token-sync", listener);
    }

    expect(persistedTokens).toEqual(["queue-owner-token"]);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("queue-owner-token");
    expect(calls).toHaveLength(1);
    expect(events).toEqual([]);
    expect(shouldAttemptSsoBridge()).toBe(false);
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("revalidates JWT expiry inside the queued persistence commit guard", async () => {
    let now = 2_000_000_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);
    const expiringToken = jwt({
      userId: "expiring-user",
      exp: Math.floor(now / 1000) + 1,
    });
    let releaseQueueOwner: () => void = () => {};
    const queueOwnerPersistence = new Promise<void>((resolve) => {
      releaseQueueOwner = resolve;
    });
    let markQueueOwned: () => void = () => {};
    const queueOwned = new Promise<void>((resolve) => {
      markQueueOwned = resolve;
    });
    const persistedTokens: string[] = [];
    const unregister = registerStewardTokenPersistence(async (token) => {
      persistedTokens.push(token);
      if (token === "queue-owner-token") {
        markQueueOwned();
        await queueOwnerPersistence;
      }
      localStorage.setItem(STEWARD_TOKEN_KEY, token);
    });
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token: expiringToken })
        : stewardSessionResponse("expiring-user"),
    );
    const isCurrent = vi.fn(() => true);

    try {
      const queueOwner = writeStoredStewardToken("queue-owner-token");
      await queueOwned;
      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
        isCurrent,
      );
      await vi.waitFor(() => expect(isCurrent).toHaveBeenCalledTimes(1));
      now += 2_000;
      releaseQueueOwner();

      await queueOwner;
      await expect(exchange).resolves.toEqual({
        ok: false,
        error: "SSO exchange session expired",
      });
    } finally {
      releaseQueueOwner();
      unregister();
      nowSpy.mockRestore();
    }

    expect(persistedTokens).toEqual(["queue-owner-token"]);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("queue-owner-token");
    expect(calls).toHaveLength(1);
  });

  it("scrubs a token that expires after persistence and before success", async () => {
    let now = 2_000_000_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);
    const expiringToken = jwt({
      userId: "expiring-user",
      exp: Math.floor(now / 1000) + 1,
    });
    let resolveCookieSync: (response: Response) => void = () => {};
    const cookieSync = new Promise<Response>((resolve) => {
      resolveCookieSync = resolve;
    });
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token: expiringToken })
        : // This responder is replaced below for the deferred session POST.
          stewardSessionResponse("expiring-user"),
    );
    const deferredFetch: SsoBridgeFetch = (input, init) => {
      const url = String(input);
      if (url.includes("/sso-bridge/exchange")) return fn(input, init);
      calls.push({ url, init });
      return cookieSync;
    };
    const realFetch = globalThis.fetch;
    const cookieClearCalls: FetchCall[] = [];
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      cookieClearCalls.push({ url: String(input), init });
      return Promise.resolve(new Response(null, { status: 204 }));
    }) as typeof fetch;

    try {
      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        deferredFetch,
      );
      await vi.waitFor(() => {
        expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(expiringToken);
        expect(calls).toHaveLength(2);
      });
      now += 2_000;
      resolveCookieSync(stewardSessionResponse("expiring-user"));

      await expect(exchange).resolves.toEqual({
        ok: false,
        error: "SSO exchange session expired",
      });
    } finally {
      resolveCookieSync(stewardSessionResponse("expiring-user"));
      nowSpy.mockRestore();
      globalThis.fetch = realFetch;
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(cookieClearCalls.length).toBeGreaterThan(0);
    expect(
      cookieClearCalls.every(({ init }) => init?.method === "DELETE"),
    ).toBe(true);
    expect(consumeStewardServerCookieSynced(expiringToken, calls[1].url)).toBe(
      false,
    );
  });

  it("rejects another realm's logout generation at the queued write guard", async () => {
    let releaseQueueOwner: () => void = () => {};
    const queueOwnerPersistence = new Promise<void>((resolve) => {
      releaseQueueOwner = resolve;
    });
    let markQueueOwned: () => void = () => {};
    const queueOwned = new Promise<void>((resolve) => {
      markQueueOwned = resolve;
    });
    const token = liveToken("cross-tab-user");
    const persistedTokens: string[] = [];
    const unregister = registerStewardTokenPersistence(async (nextToken) => {
      persistedTokens.push(nextToken);
      if (nextToken === "queue-owner-token") {
        markQueueOwned();
        await queueOwnerPersistence;
      }
      localStorage.setItem(STEWARD_TOKEN_KEY, nextToken);
    });
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token })
        : stewardSessionResponse("cross-tab-user"),
    );
    const isCurrent = vi.fn(() => true);

    try {
      const queueOwner = writeStoredStewardToken("queue-owner-token");
      await queueOwned;
      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
        isCurrent,
      );
      await vi.waitFor(() => expect(isCurrent).toHaveBeenCalledTimes(1));
      simulateOtherRealmLogout("other-realm-write-guard");
      releaseQueueOwner();

      await queueOwner;
      await expect(exchange).resolves.toEqual({
        ok: false,
        error: "SSO exchange superseded",
      });
    } finally {
      releaseQueueOwner();
      unregister();
    }

    expect(persistedTokens).toEqual(["queue-owner-token"]);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("queue-owner-token");
    expect(calls).toHaveLength(1);
    expect(isCurrent).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
  });

  it("scrubs persisted auth when another realm logs out before success", async () => {
    const token = liveToken("cross-tab-user");
    let resolveCookieSync: (response: Response) => void = () => {};
    const cookieSync = new Promise<Response>((resolve) => {
      resolveCookieSync = resolve;
    });
    const calls: FetchCall[] = [];
    const fn: SsoBridgeFetch = (input, init) => {
      const url = String(input);
      calls.push({ url, init });
      return url.includes("/sso-bridge/exchange")
        ? Promise.resolve(json(200, { ok: true, token }))
        : cookieSync;
    };

    const exchange = performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn);
    await vi.waitFor(() => {
      expect(calls).toHaveLength(2);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    });
    simulateOtherRealmLogout("other-realm-before-success");
    resolveCookieSync(stewardSessionResponse("cross-tab-user"));

    await expect(exchange).resolves.toEqual({
      ok: false,
      error: "SSO exchange superseded",
    });
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
    expect(consumeStewardServerCookieSynced(token, calls[1].url)).toBe(false);
  });

  it("establishes bridged auth without sending or consuming a Telegram claim", async () => {
    storePendingOnboardingSession(
      "opaque-telegram-claim-token",
      TELEGRAM_ACCOUNT_CLAIM_PURPOSE,
    );
    const token = liveToken();
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token })
        : stewardSessionResponse(),
    );

    await expect(
      performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn),
    ).resolves.toEqual({ ok: true });

    expect(calls).toHaveLength(2);
    expect(JSON.parse(String(calls[1]?.init?.body))).toEqual({ token });
    expect(peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE)).toBe(
      "opaque-telegram-claim-token",
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
  });

  it("keeps Telegram claim authority but rejects a failed cookie sync", async () => {
    storePendingOnboardingSession(
      "opaque-telegram-claim-token",
      TELEGRAM_ACCOUNT_CLAIM_PURPOSE,
    );
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token: liveToken() })
        : json(500, { error: "unexpected session mutation" }),
    );

    const result = await performSsoExchange(
      CODE,
      VERIFIER,
      "cloud.eliza.app",
      fn,
    );

    expect(result).toEqual({
      ok: false,
      error: "Could not establish the Eliza Cloud browser session",
    });
    expect(calls).toHaveLength(2);
    expect(peekPendingOnboardingSession(TELEGRAM_ACCOUNT_CLAIM_PURPOSE)).toBe(
      "opaque-telegram-claim-token",
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("rolls back the bearer when cookie sync has a transport failure", async () => {
    const token = liveToken("cookie-sync-network-user");
    const fn: SsoBridgeFetch = (input) =>
      String(input).includes("/sso-bridge/exchange")
        ? Promise.resolve(json(200, { ok: true, token }))
        : Promise.reject(new TypeError("network unavailable"));
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;

    try {
      await expect(
        performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn),
      ).resolves.toEqual({
        ok: false,
        error: "Could not establish the Eliza Cloud browser session",
      });
    } finally {
      globalThis.fetch = realFetch;
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });

  it("honors cookie-sync session_ended as a cross-host logout", async () => {
    markSsoBridgeAttempt();
    const token = liveToken();
    const { fn, calls } = fetchStub((url) =>
      url.includes("/sso-bridge/exchange")
        ? json(200, { ok: true, token })
        : json(401, {
            error: "Session was signed out",
            code: "session_ended",
          }),
    );
    const realFetch = globalThis.fetch;
    const cookieClearCalls: FetchCall[] = [];
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      cookieClearCalls.push({ url: String(input), init });
      return Promise.resolve(new Response(null, { status: 204 }));
    }) as typeof fetch;
    const eventTokens: Array<string | null> = [];
    const listener = () =>
      eventTokens.push(localStorage.getItem(STEWARD_TOKEN_KEY));
    window.addEventListener("steward-token-sync", listener);

    let result: Awaited<ReturnType<typeof performSsoExchange>>;
    try {
      result = await performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn);
    } finally {
      window.removeEventListener("steward-token-sync", listener);
      globalThis.fetch = realFetch;
    }

    expect(result).toEqual({ ok: false, error: "Session was signed out" });
    expect(calls).toHaveLength(2);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(isSsoLoggedOut()).toBe(true);
    expect(shouldAutoBridgeToSso("cloud.eliza.app")).toBe(false);
    expect(eventTokens.length).toBeGreaterThan(0);
    expect(eventTokens.every((eventToken) => eventToken === null)).toBe(true);
    expect(cookieClearCalls.length).toBeGreaterThan(0);
    expect(
      cookieClearCalls.every(({ init }) => init?.method === "DELETE"),
    ).toBe(true);
  });

  it("lets the newer intent finish before a late older exchange response", async () => {
    const staleToken = liveToken("stale-user");
    const currentToken = liveToken("current-user");
    let resolveStaleExchange: (response: Response) => void = () => {};
    const staleExchange = new Promise<Response>((resolve) => {
      resolveStaleExchange = resolve;
    });
    let resolveCurrentSession: (response: Response) => void = () => {};
    const currentSession = new Promise<Response>((resolve) => {
      resolveCurrentSession = resolve;
    });
    const currentSessionSignals: AbortSignal[] = [];
    const fn: SsoBridgeFetch = (input, init) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body)) as {
        code?: string;
        token?: string;
      };
      if (url.includes("/sso-bridge/exchange")) {
        return body.code === CODE
          ? staleExchange
          : Promise.resolve(json(200, { ok: true, token: currentToken }));
      }
      if (init?.signal instanceof AbortSignal) {
        currentSessionSignals.push(init.signal);
      }
      return currentSession;
    };
    const stale = performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn);
    const current = performSsoExchange(
      NEXT_CODE,
      VERIFIER,
      "cloud.eliza.app",
      fn,
      () => true,
    );
    await vi.waitFor(() => expect(currentSessionSignals).toHaveLength(1));

    resolveStaleExchange(json(200, { ok: true, token: staleToken }));
    await expect(stale).resolves.toEqual({
      ok: false,
      error: "SSO exchange superseded",
    });
    expect(currentSessionSignals[0].aborted).toBe(false);

    resolveCurrentSession(stewardSessionResponse("current-user"));
    await expect(current).resolves.toEqual({ ok: true });
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(currentToken);
  });

  it("serializes cookie finalization so the newer generation is the only success", async () => {
    const firstToken = liveToken("first-user");
    const secondToken = liveToken("second-user");
    const calls: FetchCall[] = [];
    const sessionPostSignals: AbortSignal[] = [];
    const fn: SsoBridgeFetch = (input, init) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.includes("/sso-bridge/exchange")) {
        const body = JSON.parse(String(init?.body)) as { code: string };
        return Promise.resolve(
          json(200, {
            ok: true,
            token: body.code === CODE ? firstToken : secondToken,
          }),
        );
      }
      const body = JSON.parse(String(init?.body)) as { token: string };
      const signal = init?.signal;
      if (!(signal instanceof AbortSignal)) {
        return Promise.reject(new Error("missing cookie-sync abort signal"));
      }
      sessionPostSignals.push(signal);
      if (body.token === secondToken) {
        return Promise.resolve(stewardSessionResponse("second-user"));
      }
      // Deliberately ignore AbortSignal: the bridge's own deadline still has
      // to release cross-tab lock custody for the newer generation.
      return new Promise<Response>(() => {});
    };
    let firstIsCurrent = true;
    vi.useFakeTimers();

    try {
      const first = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
        () => firstIsCurrent,
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(sessionPostSignals).toHaveLength(1);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(firstToken);

      firstIsCurrent = false;
      const second = performSsoExchange(
        NEXT_CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
        () => true,
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(
        calls.filter(({ url }) => url.includes("/sso-bridge/exchange")),
      ).toHaveLength(2);
      expect(sessionPostSignals).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(10_000);
      expect(sessionPostSignals[0].aborted).toBe(true);
      expect(sessionPostSignals).toHaveLength(2);

      await expect(first).resolves.toEqual({
        ok: false,
        error: "SSO exchange superseded",
      });
      await expect(second).resolves.toEqual({ ok: true });
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(secondToken);
      expect(
        calls
          .filter(({ url }) => url.includes("/api/auth/steward-session"))
          .map(({ init }) => JSON.parse(String(init?.body))),
      ).toEqual([{ token: firstToken }, { token: secondToken }]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("fails closed when the latest-started generation becomes stale", async () => {
    markSsoBridgeAttempt();
    markSsoLoggedOut();
    const firstToken = liveToken("first-user");
    const secondToken = liveToken("second-user");
    let resolveFirstSession: (response: Response) => void = () => {};
    const firstSession = new Promise<Response>((resolve) => {
      resolveFirstSession = resolve;
    });
    const calls: FetchCall[] = [];
    const fn: SsoBridgeFetch = (input, init) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.includes("/sso-bridge/exchange")) {
        const body = JSON.parse(String(init?.body)) as { code: string };
        return Promise.resolve(
          json(200, {
            ok: true,
            token: body.code === CODE ? firstToken : secondToken,
          }),
        );
      }
      return firstSession;
    };
    let secondIsCurrent = true;
    const secondGuard = vi.fn(() => secondIsCurrent);
    const events: string[] = [];
    const listener = () => events.push("steward-token-sync");
    window.addEventListener("steward-token-sync", listener);

    try {
      const first = performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn);
      await vi.waitFor(() =>
        expect(
          calls.filter(({ url }) => url.includes("/api/auth/steward-session")),
        ).toHaveLength(1),
      );
      const second = performSsoExchange(
        NEXT_CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
        secondGuard,
      );
      await vi.waitFor(() => expect(secondGuard).toHaveBeenCalledTimes(1));
      secondIsCurrent = false;
      resolveFirstSession(stewardSessionResponse("first-user"));

      await expect(first).resolves.toEqual({
        ok: false,
        error: "SSO exchange superseded",
      });
      await expect(second).resolves.toEqual({
        ok: false,
        error: "SSO exchange superseded",
      });
    } finally {
      resolveFirstSession(stewardSessionResponse("first-user"));
      window.removeEventListener("steward-token-sync", listener);
    }

    expect(secondGuard).toHaveBeenCalledTimes(2);
    expect(
      calls.filter(({ url }) => url.includes("/api/auth/steward-session")),
    ).toHaveLength(1);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(events.length).toBeGreaterThan(0);
    expect(shouldAttemptSsoBridge()).toBe(false);
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("releases cookie finalization after a rejected POST", async () => {
    const firstToken = liveToken("first-user");
    const secondToken = liveToken("second-user");
    let rejectFirstPost: (error: Error) => void = () => {};
    const firstPost = new Promise<Response>((_resolve, reject) => {
      rejectFirstPost = reject;
    });
    let sessionPostCount = 0;
    const fn: SsoBridgeFetch = (input, init) => {
      const url = String(input);
      if (url.includes("/sso-bridge/exchange")) {
        const body = JSON.parse(String(init?.body)) as { code: string };
        return Promise.resolve(
          json(200, {
            ok: true,
            token: body.code === CODE ? firstToken : secondToken,
          }),
        );
      }
      sessionPostCount += 1;
      return sessionPostCount === 1
        ? firstPost
        : Promise.resolve(stewardSessionResponse("second-user"));
    };

    const first = performSsoExchange(CODE, VERIFIER, "cloud.eliza.app", fn);
    await vi.waitFor(() => expect(sessionPostCount).toBe(1));
    const second = performSsoExchange(
      NEXT_CODE,
      VERIFIER,
      "cloud.eliza.app",
      fn,
    );
    rejectFirstPost(new Error("cookie sync transport failed"));

    await expect(first).resolves.toEqual({
      ok: false,
      error: "SSO exchange superseded",
    });
    await expect(second).resolves.toEqual({ ok: true });
    expect(sessionPostCount).toBe(2);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(secondToken);
  });

  it("orders logout after an active cookie sync without clearing the logout marker", async () => {
    const token = liveToken();
    const sessionSignals: AbortSignal[] = [];
    const exchangeFetch: SsoBridgeFetch = (input, init) => {
      const url = String(input);
      if (url.includes("/sso-bridge/exchange")) {
        return Promise.resolve(json(200, { ok: true, token }));
      }
      const signal = init?.signal;
      if (!(signal instanceof AbortSignal)) {
        return Promise.reject(new Error("missing cookie-sync abort signal"));
      }
      sessionSignals.push(signal);
      return new Promise<Response>((_resolve, reject) => {
        const rejectAborted = () =>
          reject(new DOMException("cookie sync aborted", "AbortError"));
        if (signal.aborted) rejectAborted();
        else signal.addEventListener("abort", rejectAborted, { once: true });
      });
    };
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(json(200, { ok: true }))) as typeof fetch;
    const logout = fetchStub(logoutBarrierResponse);
    const eventTokens: Array<string | null> = [];
    const listener = () =>
      eventTokens.push(localStorage.getItem(STEWARD_TOKEN_KEY));
    window.addEventListener("steward-token-sync", listener);

    try {
      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        exchangeFetch,
      );
      await vi.waitFor(() => expect(sessionSignals).toHaveLength(1));
      const signOut = signOutFromSsoBridgedHost("cloud.eliza.app", logout.fn);

      await expect(exchange).resolves.toEqual({
        ok: false,
        error: "SSO exchange superseded",
      });
      await signOut;
    } finally {
      window.removeEventListener("steward-token-sync", listener);
      globalThis.fetch = realFetch;
    }

    expect(sessionSignals[0].aborted).toBe(true);
    expect(logout.calls).toHaveLength(1);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(isSsoLoggedOut()).toBe(true);
    expect(eventTokens.every((eventToken) => eventToken === null)).toBe(true);
  });

  it("finishes cookie DELETEs before a newer login can publish its cookie POST", async () => {
    const previousToken = liveToken("previous-user");
    const nextToken = liveToken("next-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, previousToken);
    const order: string[] = [];
    const releaseDeletes: Array<() => void> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = ((_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method !== "DELETE") {
        return Promise.reject(new Error("unexpected global request"));
      }
      order.push("cookie-delete-start");
      return new Promise<Response>((resolve) => {
        let released = false;
        releaseDeletes.push(() => {
          if (released) return;
          released = true;
          order.push("cookie-delete-finish");
          resolve(new Response(null, { status: 204 }));
        });
      });
    }) as typeof fetch;
    const logout = fetchStub(() => {
      order.push("server-logout");
      return logoutBarrierResponse();
    });
    const exchangeFetch: SsoBridgeFetch = (input) => {
      const url = String(input);
      if (url.includes("/sso-bridge/exchange")) {
        order.push("new-exchange");
        return Promise.resolve(json(200, { ok: true, token: nextToken }));
      }
      order.push("new-cookie-post");
      return Promise.resolve(stewardSessionResponse("next-user"));
    };

    try {
      const signOut = signOutFromSsoBridgedHost("cloud.eliza.app", logout.fn);
      await vi.waitFor(() => expect(releaseDeletes.length).toBeGreaterThan(0));

      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        exchangeFetch,
      );
      await vi.waitFor(() => expect(order).toContain("new-exchange"));
      expect(order).not.toContain("new-cookie-post");

      for (const release of releaseDeletes) release();
      await expect(signOut).rejects.toThrow(
        "sign-out was superseded by a newer session intent",
      );
      await expect(exchange).resolves.toEqual({ ok: true });
    } finally {
      for (const release of releaseDeletes) release();
      globalThis.fetch = realFetch;
    }

    expect(order.lastIndexOf("cookie-delete-finish")).toBeLessThan(
      order.indexOf("new-cookie-post"),
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(nextToken);
    expect(isSsoLoggedOut()).toBe(false);
  });

  it("does not start cookie sync when logout lands during token persistence", async () => {
    const token = liveToken();
    let releasePersistence: () => void = () => {};
    const persistence = new Promise<void>((resolve) => {
      releasePersistence = resolve;
    });
    let markPersistenceStarted: () => void = () => {};
    const persistenceStarted = new Promise<void>((resolve) => {
      markPersistenceStarted = resolve;
    });
    const unregister = registerStewardTokenPersistence(async (nextToken) => {
      markPersistenceStarted();
      await persistence;
      localStorage.setItem(STEWARD_TOKEN_KEY, nextToken);
    });
    const exchangeCalls: string[] = [];
    const exchangeFetch: SsoBridgeFetch = (input) => {
      const url = String(input);
      exchangeCalls.push(url);
      return Promise.resolve(
        url.includes("/sso-bridge/exchange")
          ? json(200, { ok: true, token })
          : stewardSessionResponse(),
      );
    };
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(json(200, { ok: true }))) as typeof fetch;
    const logout = fetchStub(logoutBarrierResponse);

    try {
      const exchange = performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        exchangeFetch,
      );
      await persistenceStarted;
      const signOut = signOutFromSsoBridgedHost("cloud.eliza.app", logout.fn);
      expect(isSsoLoggedOut()).toBe(true);
      releasePersistence();

      await expect(exchange).resolves.toEqual({
        ok: false,
        error: "SSO exchange superseded",
      });
      await signOut;
    } finally {
      releasePersistence();
      unregister();
      globalThis.fetch = realFetch;
    }

    expect(
      exchangeCalls.filter((url) => url.includes("/steward-session")),
    ).toEqual([]);
    expect(logout.calls).toHaveLength(1);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("refuses a malformed verifier without calling out", async () => {
    const { fn, calls } = fetchStub(() =>
      json(200, { ok: true, token: liveToken() }),
    );
    const result = await performSsoExchange(
      CODE,
      "junk",
      "cloud.eliza.app",
      fn,
    );
    expect(result.ok).toBe(false);
    expect(calls).toEqual([]);
  });

  it("rejects an expired or identity-less token without hydrating", async () => {
    const expired = jwt({
      userId: "u1",
      exp: Math.floor(Date.now() / 1000) - 10,
    });
    const noId = jwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    for (const token of [expired, noId]) {
      const { fn } = fetchStub(() => json(200, { ok: true, token }));
      const result = await performSsoExchange(
        CODE,
        VERIFIER,
        "cloud.eliza.app",
        fn,
      );
      expect(result.ok).toBe(false);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    }
  });

  it("maps an exchange denial to a failure without hydrating", async () => {
    const { fn } = fetchStub(() => json(401, { error: "invalid_code" }));
    const result = await performSsoExchange(
      CODE,
      VERIFIER,
      "cloud.eliza.app",
      fn,
    );
    expect(result.ok).toBe(false);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
  });
});

describe("burnSsoBridgeCode", () => {
  it("fires a keepalive destruction-only POST from either bridge origin", () => {
    const { fn, calls } = fetchStub(() => new Response(null, { status: 204 }));
    burnSsoBridgeCode(CODE, "eliza.app", fn);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://eliza.app/api/auth/sso-bridge/burn");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ code: CODE });
    expect(calls[0].init?.keepalive).toBe(true);
  });

  it("is inert for malformed codes and unmapped hosts", () => {
    const { fn, calls } = fetchStub(() => json(401, {}));
    burnSsoBridgeCode("not-a-code", "cloud.eliza.app", fn);
    burnSsoBridgeCode(CODE, "localhost", fn);
    expect(calls).toEqual([]);
  });
});

describe("signOutFromSsoBridgedHost", () => {
  it("fails closed when a logout intent cannot be persisted", async () => {
    const token = liveToken("uncoordinated-sign-out-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const entropyFailure = new Error("secure entropy unavailable");
    const entropy = vi
      .spyOn(globalThis.crypto, "getRandomValues")
      .mockImplementation(() => {
        throw entropyFailure;
      });
    const { fn, calls } = fetchStub(logoutBarrierResponse);

    try {
      await expect(
        signOutFromSsoBridgedHost("cloud.eliza.app", fn),
      ).rejects.toThrow("coordination is unavailable for sign-out");
    } finally {
      entropy.mockRestore();
    }

    expect(calls).toHaveLength(0);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
  });

  it("rejects a queued sign-out superseded by a newer session intent", async () => {
    const token = liveToken("superseded-sign-out-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const lockManager = new ManualSsoBridgeLockManager();
    const { fn, calls } = fetchStub(logoutBarrierResponse);

    const signOut = signOutFromSsoBridgedHost("cloud.eliza.app", fn, {
      lockManager,
    });
    expect(lockManager.pendingCount).toBe(1);
    markSsoLoggedOut();
    lockManager.releaseNext();

    await expect(signOut).rejects.toThrow(
      "sign-out was superseded by a newer session intent",
    );
    expect(calls).toHaveLength(0);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
  });

  it("reasserts a queued logout marker even when the server retry fails", async () => {
    const token = liveToken("queued-marker-retry-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const lockManager = new ManualSsoBridgeLockManager();
    const { fn } = fetchStub(() =>
      json(503, { error: "temporarily_unavailable" }),
    );

    const signOut = signOutFromSsoBridgedHost("cloud.eliza.app", fn, {
      lockManager,
    });
    expect(lockManager.pendingCount).toBe(1);
    // Models an older exchange clearing the synchronous marker after this
    // logout published its intent but before it obtained Web Lock custody.
    localStorage.removeItem(SSO_LOGGED_OUT_KEY);
    lockManager.releaseNext();

    await expect(signOut).rejects.toThrow(
      "could not end the browser session (503)",
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
  });

  it("marks logged-out synchronously, ends the server session, scrubs locally", async () => {
    const token = liveToken();
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    markStewardServerCookieSynced(
      token,
      "https://cloud.eliza.app/api/auth/steward-session",
    );
    // clearStaleStewardSession fires best-effort cookie DELETEs via the
    // global fetch; capture them so jsdom does not attempt real requests.
    const globalCalls: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      globalCalls.push(`${init?.method ?? "GET"} ${String(input)}`);
      return Promise.resolve(json(200, { ok: true }));
    }) as typeof fetch;
    try {
      let proofAtServerLogoutIssue: boolean | undefined;
      const { fn, calls } = fetchStub(() => {
        proofAtServerLogoutIssue = consumeStewardServerCookieSynced(
          token,
          "https://cloud.eliza.app/api/auth/steward-session",
        );
        return logoutBarrierResponse();
      });
      await signOutFromSsoBridgedHost("cloud.eliza.app", fn);
      expect(isSsoLoggedOut()).toBe(true);
      expect(calls[0].url).toBe("https://cloud.eliza.app/api/auth/logout");
      expect(calls[0].init).toMatchObject({
        method: "POST",
        credentials: "include",
      });
      expect(calls[0].init?.signal).toBeInstanceOf(AbortSignal);
      expect(new Headers(calls[0].init?.headers).get("content-type")).toBe(
        "application/json",
      );
      expect(new Headers(calls[0].init?.headers).get("authorization")).toBe(
        `Bearer ${token}`,
      );
      expect(proofAtServerLogoutIssue).toBe(false);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("rejects when the hosted session cannot be ended", async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    try {
      const { fn } = fetchStub(() =>
        json(403, { error: "csrf_marker_required" }),
      );
      await expect(
        signOutFromSsoBridgedHost("cloud.eliza.app", fn),
      ).rejects.toThrow("could not end the browser session (403)");
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("retains bearer authority for a failed logout retry and clears only after 200", async () => {
    const token = liveToken("logout-retry-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    let attempt = 0;
    const { fn, calls } = fetchStub(() => {
      attempt += 1;
      return attempt === 1
        ? json(503, { error: "temporarily_unavailable" })
        : logoutBarrierResponse();
    });

    try {
      await expect(
        signOutFromSsoBridgedHost("cloud.eliza.app", fn),
      ).rejects.toThrow("could not end the browser session (503)");
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);

      await signOutFromSsoBridgedHost("cloud.eliza.app", fn);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    } finally {
      globalThis.fetch = realFetch;
    }

    expect(calls).toHaveLength(2);
    expect(
      calls.map(({ init }) => new Headers(init?.headers).get("authorization")),
    ).toEqual([`Bearer ${token}`, `Bearer ${token}`]);
  });

  it("rejects when the hosted logout request cannot reach the server", async () => {
    const token = liveToken("logout-retry-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    try {
      const networkFailure = new TypeError("network unavailable");
      const fn = (() => Promise.reject(networkFailure)) as typeof fetch;
      await expect(
        signOutFromSsoBridgedHost("cloud.eliza.app", fn),
      ).rejects.toBe(networkFailure);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
      expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("propagates caller cancellation through lock custody and the logout request", async () => {
    const token = liveToken("cancelled-sign-out-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    let requestSignal: AbortSignal | null = null;
    const fn = ((_input: RequestInfo | URL, init?: RequestInit) => {
      requestSignal = init?.signal ?? null;
      return new Promise<Response>(() => {});
    }) as typeof fetch;
    const callerAbort = new AbortController();

    const signOut = signOutFromSsoBridgedHost("cloud.eliza.app", fn, {
      signal: callerAbort.signal,
    });
    await vi.waitFor(() => expect(requestSignal).toBeInstanceOf(AbortSignal));
    callerAbort.abort();

    await expect(signOut).rejects.toMatchObject({ name: "AbortError" });
    expect((requestSignal as AbortSignal | null)?.aborted).toBe(true);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
  });

  it("retains bearer authority when a 2xx response has an inconsistent logout proof", async () => {
    const token = liveToken("logout-unproven-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const { fn } = fetchStub(() =>
      json(200, {
        success: true,
        logoutProofVersion: 1,
        barrierState: "confirmed",
        barrierConfirmed: false,
        message: "No credential established the barrier",
      }),
    );

    await expect(
      signOutFromSsoBridgedHost("cloud.eliza.app", fn),
    ).rejects.toThrow("did not return a valid browser-session logout proof");
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("rejects the unversioned pre-proof logout response", async () => {
    const token = liveToken("logout-old-contract-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const { fn } = fetchStub(() =>
      json(200, {
        success: true,
        message: "Logged out successfully",
      }),
    );

    await expect(
      signOutFromSsoBridgedHost("cloud.eliza.app", fn),
    ).rejects.toThrow("did not return a valid browser-session logout proof");
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("accepts a versioned already-absent proof and omits an expired bearer", async () => {
    const expired = jwt({
      userId: "expired-logout-user",
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    localStorage.setItem(STEWARD_TOKEN_KEY, expired);
    const { fn, calls } = fetchStub(logoutAlreadyAbsentResponse);

    await expect(
      signOutFromSsoBridgedHost("cloud.eliza.app", fn),
    ).resolves.toBeUndefined();
    expect(calls[0]?.init?.headers).not.toMatchObject({
      Authorization: expect.any(String),
    });
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("retains bearer authority when a 2xx logout body is not JSON", async () => {
    const token = liveToken("logout-malformed-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const { fn } = fetchStub(
      () =>
        new Response("not-json", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );

    await expect(
      signOutFromSsoBridgedHost("cloud.eliza.app", fn),
    ).rejects.toThrow("did not return a valid browser-session logout proof");
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("reasserts the persistent logout marker before releasing custody", async () => {
    const token = liveToken("marker-race-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    let resolveLogout: (response: Response) => void = () => {};
    const logoutResponse = new Promise<Response>((resolve) => {
      resolveLogout = resolve;
    });
    const fn = (() => logoutResponse) as typeof fetch;

    try {
      const signOut = signOutFromSsoBridgedHost("cloud.eliza.app", fn);
      await Promise.resolve();
      localStorage.removeItem(SSO_LOGGED_OUT_KEY);
      resolveLogout(logoutBarrierResponse());
      await signOut;
    } finally {
      resolveLogout(logoutBarrierResponse());
      globalThis.fetch = realFetch;
    }

    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
  });

  it("bounds a logout adapter that ignores AbortSignal and releases custody", async () => {
    const token = liveToken("logout-timeout-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    const calls: FetchCall[] = [];
    const hangingFetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      return new Promise<Response>(() => {});
    }) as typeof fetch;
    vi.useFakeTimers();

    try {
      const signOut = signOutFromSsoBridgedHost(
        "cloud.eliza.app",
        hangingFetch,
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(calls).toHaveLength(1);
      const signal = calls[0].init?.signal;
      expect(signal).toBeInstanceOf(AbortSignal);

      const rejection = expect(signOut).rejects.toMatchObject({
        name: "AbortError",
      });
      await vi.advanceTimersByTimeAsync(10_000);
      await rejection;
      expect(signal?.aborted).toBe(true);
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    } finally {
      vi.useRealTimers();
      globalThis.fetch = realFetch;
    }
  });
});

describe("prepareSsoAccountSwitch", () => {
  it("rejects a queued account switch superseded by a newer session intent", async () => {
    const token = liveToken("superseded-account-switch-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const lockManager = new ManualSsoBridgeLockManager();
    const { fn, calls } = fetchStub(logoutBarrierResponse);

    const prepare = prepareSsoAccountSwitch("eliza.app", fn, {
      lockManager,
    });
    expect(lockManager.pendingCount).toBe(1);
    markSsoLoggedOut();
    lockManager.releaseNext();

    await expect(prepare).rejects.toThrow(
      "account switch was superseded by a newer session intent",
    );
    expect(calls).toHaveLength(0);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
  });

  it("fails closed when the previous hosted session cannot be ended", async () => {
    const token = liveToken();
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(json(200, { ok: true }))) as typeof fetch;
    try {
      const { fn } = fetchStub(() => json(503, { success: false }));
      await expect(prepareSsoAccountSwitch("eliza.app", fn)).rejects.toThrow(
        "could not end the previous browser session (503)",
      );
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
      expect(isSsoLoggedOut()).toBe(true);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("propagates caller cancellation to account-switch logout", async () => {
    const token = liveToken("cancelled-account-switch-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    let requestSignal: AbortSignal | null = null;
    const fn = ((_input: RequestInfo | URL, init?: RequestInit) => {
      requestSignal = init?.signal ?? null;
      return new Promise<Response>(() => {});
    }) as typeof fetch;
    const callerAbort = new AbortController();

    const prepare = prepareSsoAccountSwitch("eliza.app", fn, {
      signal: callerAbort.signal,
    });
    await vi.waitFor(() => expect(requestSignal).toBeInstanceOf(AbortSignal));
    callerAbort.abort();

    await expect(prepare).rejects.toMatchObject({ name: "AbortError" });
    expect((requestSignal as AbortSignal | null)?.aborted).toBe(true);
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(localStorage.getItem(SSO_LOGGED_OUT_KEY)).toBe("1");
  });

  it("authorizes the non-simple account-switch logout request", async () => {
    const token = liveToken();
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    try {
      const { fn, calls } = fetchStub(logoutBarrierResponse);
      await prepareSsoAccountSwitch("eliza.app", fn);
      expect(calls[0].init).toMatchObject({
        method: "POST",
        credentials: "include",
      });
      expect(calls[0].init?.signal).toBeInstanceOf(AbortSignal);
      expect(new Headers(calls[0].init?.headers).get("content-type")).toBe(
        "application/json",
      );
      expect(new Headers(calls[0].init?.headers).get("authorization")).toBe(
        `Bearer ${token}`,
      );
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("fails closed when a 2xx response omits explicit barrier proof", async () => {
    const token = liveToken("account-switch-unproven-user");
    localStorage.setItem(STEWARD_TOKEN_KEY, token);
    const { fn } = fetchStub(() =>
      json(200, { success: true, message: "Ambiguous logout" }),
    );

    await expect(prepareSsoAccountSwitch("eliza.app", fn)).rejects.toThrow(
      "did not return a valid previous-session logout proof",
    );
    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe(token);
    expect(isSsoLoggedOut()).toBe(true);
  });

  it("accepts a versioned already-absent proof for an expired previous session", async () => {
    const expired = jwt({
      userId: "expired-account-switch-user",
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    localStorage.setItem(STEWARD_TOKEN_KEY, expired);
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    try {
      const { fn, calls } = fetchStub(logoutAlreadyAbsentResponse);
      await expect(
        prepareSsoAccountSwitch("eliza.app", fn),
      ).resolves.toBeUndefined();
      expect(new Headers(calls[0]?.init?.headers).has("authorization")).toBe(
        false,
      );
      expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
      expect(isSsoLoggedOut()).toBe(true);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
