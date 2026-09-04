/** Verifies Steward auth endpoint resolution through the package's configured test harness. */
// @vitest-environment jsdom

/**
 * Steward auth-endpoint resolution and token-expiry helpers: staging/prod UI
 * hosts route through their same-origin proxy so host-only cookies remain visible, unknown hosts
 * fall back to the same-origin relative path, and `tokenIsExpired` reads the
 * JWT `exp` claim.
 */

import {
  registerStewardTokenRemoval,
  STEWARD_REFRESH_TOKEN_KEY,
  STEWARD_TOKEN_KEY,
} from "@elizaos/shared/steward-session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  loadAgentProfileRegistry,
  saveAgentProfileRegistry,
} from "../../state/agent-profiles";
import {
  loadPersistedActiveServer,
  savePersistedActiveServer,
} from "../../state/persistence";
import {
  consumeStewardServerCookieSynced,
  invalidateStewardServerCookieSyncMarker,
  markStewardServerCookieSynced,
} from "../lib/steward-session-cookie-sync-marker";

import {
  clearServerStewardSessionCookies,
  clearStaleStewardSession,
  tokenIsExpired,
} from "./StewardProviderShared";

// The Steward auth endpoints are resolved per browser host: co-hosted cloud
// surfaces use their same-origin Pages/Worker proxy. The invariant under guard:
// staging and production never cross environments, even when a build-time API
// base is present; otherwise host-only cookies land on the API hostname and the
// SSO bridge cannot observe the browser session.

function setHostname(hostname: string): void {
  Object.defineProperty(window, "location", {
    configurable: true,
    value: {
      hostname,
      origin: `https://${hostname}`,
      href: `https://${hostname}/`,
    },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

async function loadEndpoints() {
  // Neutralize any configured API base so the host-based branch is exercised.
  vi.stubEnv("VITE_API_URL", "");
  vi.stubEnv("NEXT_PUBLIC_API_URL", "");
  vi.resetModules();
  return import("./StewardProviderShared");
}

describe("Steward auth endpoint resolution", () => {
  it("keeps canonical staging session cookies on the staging marketing host", async () => {
    setHostname("staging.eliza.app");
    const { configuredSessionEndpoint, configuredRefreshEndpoint } =
      await loadEndpoints();

    expect(configuredSessionEndpoint()).toBe(
      "https://staging.eliza.app/api/auth/steward-session",
    );
    expect(configuredRefreshEndpoint()).toBe(
      "https://staging.eliza.app/api/auth/steward-refresh",
    );
  });

  it("keeps canonical staging session cookies on the managed app host", async () => {
    setHostname("cloud-staging.eliza.app");
    const { configuredSessionEndpoint, configuredRefreshEndpoint } =
      await loadEndpoints();

    expect(configuredSessionEndpoint()).toBe(
      "https://cloud-staging.eliza.app/api/auth/steward-session",
    );
    expect(configuredRefreshEndpoint()).toBe(
      "https://cloud-staging.eliza.app/api/auth/steward-refresh",
    );
  });

  it("keeps canonical production session cookies on eliza.app", async () => {
    setHostname("eliza.app");
    const { configuredSessionEndpoint, configuredRefreshEndpoint } =
      await loadEndpoints();

    expect(configuredSessionEndpoint()).toBe(
      "https://eliza.app/api/auth/steward-session",
    );
    expect(configuredRefreshEndpoint()).toBe(
      "https://eliza.app/api/auth/steward-refresh",
    );
  });

  it("keeps canonical production session cookies on cloud.eliza.app", async () => {
    setHostname("cloud.eliza.app");
    const { configuredSessionEndpoint, configuredRefreshEndpoint } =
      await loadEndpoints();

    expect(configuredSessionEndpoint()).toBe(
      "https://cloud.eliza.app/api/auth/steward-session",
    );
    expect(configuredRefreshEndpoint()).toBe(
      "https://cloud.eliza.app/api/auth/steward-refresh",
    );
  });

  it("falls back to the same-origin relative path on an unknown host", async () => {
    setHostname("localhost");
    const { configuredSessionEndpoint, configuredRefreshEndpoint } =
      await loadEndpoints();

    expect(configuredSessionEndpoint()).toBe("/api/auth/steward-session");
    expect(configuredRefreshEndpoint()).toBe("/api/auth/steward-refresh");
  });
});

function makeJwt(payload: Record<string, unknown>): string {
  const b64url = (value: object) =>
    btoa(JSON.stringify(value))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(payload)}.sig`;
}

function cookieClearAcknowledgement(): Response {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("clearStaleStewardSession", () => {
  beforeEach(() => {
    localStorage.clear();
    invalidateStewardServerCookieSyncMarker();
  });

  it("drops a shared Cloud agent selection so the next account resolves its own agent", async () => {
    savePersistedActiveServer({
      id: "cloud:old-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: "https://api.eliza.app/api/v1/eliza/agents/old-agent",
      accessToken: "expired-steward-token",
    });

    await clearStaleStewardSession();

    expect(loadPersistedActiveServer()).toBeNull();
  });

  it("preserves a dedicated target selection while scrubbing its rejected bearer", async () => {
    savePersistedActiveServer({
      id: "cloud:dedicated-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: "https://dedicated-agent.eliza.app",
      accessToken: "rejected-agent-token",
    });

    await clearStaleStewardSession();

    expect(loadPersistedActiveServer()).toEqual({
      id: "cloud:dedicated-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: "https://dedicated-agent.eliza.app",
    });
  });

  it("finishes credential teardown before rethrowing obsolete refresh-key cleanup failure", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "expired-steward-token");
    localStorage.setItem(STEWARD_REFRESH_TOKEN_KEY, "obsolete-refresh-token");
    savePersistedActiveServer({
      id: "cloud:dedicated-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: "https://dedicated-agent.eliza.app",
      accessToken: "active-server-mirror",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "profile-1",
      profiles: [
        {
          id: "profile-1",
          label: "Remote agent",
          kind: "remote",
          apiBase: "https://remote.example.test",
          accessToken: "profile-mirror",
          createdAt: "2026-08-13T00:00:00.000Z",
        },
      ],
    });
    const storageFailure = new Error("legacy refresh storage unavailable");
    const storage = window.localStorage;
    const originalRemoveItem = storage.removeItem.bind(storage);
    // jsdom implements Storage methods on the prototype, while the Node ≥25
    // fallback in vitest.setup owns them directly. Spy on the actual method
    // owner so this regression injects the same failure on every supported
    // test host instead of passing only with one storage implementation.
    const removeItemOwner = Object.hasOwn(storage, "removeItem")
      ? storage
      : (Object.getPrototypeOf(storage) as Storage);
    const removeItem = vi
      .spyOn(removeItemOwner, "removeItem")
      .mockImplementation((key: string) => {
        if (key === STEWARD_REFRESH_TOKEN_KEY) throw storageFailure;
        return originalRemoveItem(key);
      });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));

    try {
      await expect(clearStaleStewardSession()).rejects.toThrow(storageFailure);
    } finally {
      removeItem.mockRestore();
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBeNull();
    expect(loadPersistedActiveServer()?.accessToken).toBeUndefined();
    expect(loadAgentProfileRegistry().profiles[0]?.accessToken).toBeUndefined();
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ method: "DELETE", credentials: "include" }),
    );
  });

  it("retains logical account state when canonical protected removal fails", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "still-durable-token");
    savePersistedActiveServer({
      id: "cloud:old-agent",
      kind: "cloud",
      label: "Eliza Cloud",
      apiBase: "https://api.eliza.app/api/v1/eliza/agents/old-agent",
      accessToken: "still-durable-token",
    });
    const deletionFailure = new Error("native secure deletion denied");
    markStewardServerCookieSynced(
      "still-durable-token",
      "/api/auth/steward-session",
    );
    const unregister = registerStewardTokenRemoval(async () => {
      throw deletionFailure;
    });

    try {
      await expect(clearStaleStewardSession()).rejects.toMatchObject({
        name: "StewardTokenRemovalError",
        message: deletionFailure.message,
        cause: deletionFailure,
      });
    } finally {
      unregister();
    }

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("still-durable-token");
    expect(loadPersistedActiveServer()?.accessToken).toBe(
      "still-durable-token",
    );
    expect(
      consumeStewardServerCookieSynced(
        "still-durable-token",
        "/api/auth/steward-session",
      ),
    ).toBe(false);
  });

  it("does not apply a delayed token-A teardown to canonical account B", async () => {
    localStorage.setItem(STEWARD_TOKEN_KEY, "account-b-token");
    savePersistedActiveServer({
      id: "cloud:account-b-agent",
      kind: "cloud",
      label: "Account B",
      apiBase: "https://account-b-agent.eliza.app",
      accessToken: "account-b-token",
    });
    saveAgentProfileRegistry({
      version: 1,
      activeProfileId: "account-b-profile",
      profiles: [
        {
          id: "account-b-profile",
          label: "Account B",
          kind: "cloud",
          apiBase: "https://account-b-agent.eliza.app",
          accessToken: "account-b-token",
          createdAt: "2026-09-05T00:00:00.000Z",
        },
      ],
    });
    markStewardServerCookieSynced(
      "account-b-token",
      "/api/auth/steward-session",
    );
    await clearStaleStewardSession({ expectedToken: "account-a-token" });

    expect(localStorage.getItem(STEWARD_TOKEN_KEY)).toBe("account-b-token");
    expect(loadPersistedActiveServer()?.accessToken).toBe("account-b-token");
    expect(loadAgentProfileRegistry().profiles[0]?.accessToken).toBe(
      "account-b-token",
    );
    expect(
      consumeStewardServerCookieSynced(
        "account-b-token",
        "/api/auth/steward-session",
      ),
    ).toBe(true);
  });
});

describe("clearServerStewardSessionCookies", () => {
  it("deduplicates relative and absolute forms of a canonical host route", async () => {
    setHostname("eliza.app");
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => cookieClearAcknowledgement());

    await expect(clearServerStewardSessionCookies()).resolves.toEqual({
      ok: true,
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe(
      "/api/auth/steward-session",
    );
  });

  it("marks every cookie-clearing DELETE as a non-simple request", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => cookieClearAcknowledgement());

    await expect(clearServerStewardSessionCookies()).resolves.toEqual({
      ok: true,
    });

    expect(fetchSpy).toHaveBeenCalled();
    for (const [url, init] of fetchSpy.mock.calls) {
      expect(String(url)).toContain("/api/auth/steward-session");
      expect(init).toMatchObject({
        method: "DELETE",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
      });
    }
  });

  it("bounds and aborts every cookie DELETE even when fetch never settles", async () => {
    const signals: AbortSignal[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      if (init?.signal instanceof AbortSignal) signals.push(init.signal);
      return new Promise<Response>(() => {});
    });
    vi.useFakeTimers();

    try {
      const cleanup = clearServerStewardSessionCookies({ timeoutMs: 25 });
      await vi.advanceTimersByTimeAsync(0);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals.every((signal) => !signal.aborted)).toBe(true);

      await vi.advanceTimersByTimeAsync(25);
      await expect(cleanup).resolves.toEqual({ ok: false });
      expect(signals.every((signal) => signal.aborted)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("bounds an unresolved DELETE response body before reporting success", async () => {
    const signals: AbortSignal[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      if (init?.signal instanceof AbortSignal) signals.push(init.signal);
      const response = cookieClearAcknowledgement();
      vi.spyOn(response, "json").mockImplementation(
        () => new Promise<never>(() => {}),
      );
      return response;
    });
    vi.useFakeTimers();

    try {
      const cleanup = clearServerStewardSessionCookies({ timeoutMs: 25 });
      await vi.advanceTimersByTimeAsync(0);
      expect(signals.length).toBeGreaterThan(0);

      await vi.advanceTimersByTimeAsync(25);
      await expect(cleanup).resolves.toEqual({ ok: false });
      expect(signals.every((signal) => signal.aborted)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("forwards caller cancellation to every in-flight cookie DELETE", async () => {
    const requestSignals: AbortSignal[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      if (init?.signal instanceof AbortSignal) {
        requestSignals.push(init.signal);
      }
      return new Promise<Response>(() => {});
    });
    const callerAbort = new AbortController();

    const cleanup = clearServerStewardSessionCookies({
      signal: callerAbort.signal,
    });
    expect(requestSignals.length).toBeGreaterThan(0);
    callerAbort.abort();

    await expect(cleanup).resolves.toEqual({ ok: false });
    expect(requestSignals.every((signal) => signal.aborted)).toBe(true);
  });

  it("reports non-2xx DELETE responses even when the body claims success", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }),
    );

    await expect(clearServerStewardSessionCookies()).resolves.toEqual({
      ok: false,
    });
  });

  it.each([
    ["non-JSON", new Response("not-json", { status: 200 })],
    ["wrong discriminant", new Response(JSON.stringify({ ok: false }))],
    [
      "non-exact envelope",
      new Response(JSON.stringify({ ok: true, ignored: "field" })),
    ],
  ])(
    "reports a 2xx %s DELETE body as unconfirmed",
    async (_label, response) => {
      vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
        response.clone(),
      );

      await expect(clearServerStewardSessionCookies()).resolves.toEqual({
        ok: false,
      });
    },
  );

  it("reports a DELETE transport failure as unconfirmed", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(
      new TypeError("network unavailable"),
    );

    await expect(clearServerStewardSessionCookies()).resolves.toEqual({
      ok: false,
    });
  });

  it("rejects awaited stale-session cleanup when DELETE is unconfirmed", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 503 }),
    );

    await expect(
      clearStaleStewardSession({ awaitCookieClear: true }),
    ).rejects.toThrow("session-cookie cleanup was not acknowledged");
  });
});

describe("tokenIsExpired", () => {
  it("keeps a token with a future exp", () => {
    expect(
      tokenIsExpired(makeJwt({ exp: Math.floor(Date.now() / 1000) + 600 })),
    ).toBe(false);
  });

  it("treats a past exp as expired", () => {
    expect(
      tokenIsExpired(makeJwt({ exp: Math.floor(Date.now() / 1000) - 600 })),
    ).toBe(true);
  });

  it("treats a token WITHOUT exp as expired — the 401 handlers keep any non-expired token, so an exp-less one would otherwise be uncloseable", () => {
    expect(tokenIsExpired(makeJwt({ sub: "u1" }))).toBe(true);
  });

  it("treats a token with a non-numeric exp as expired", () => {
    expect(tokenIsExpired(makeJwt({ sub: "u1", exp: "soon" }))).toBe(true);
  });

  it("treats an undecodable token as expired", () => {
    expect(tokenIsExpired("not-a-jwt")).toBe(true);
  });
});
