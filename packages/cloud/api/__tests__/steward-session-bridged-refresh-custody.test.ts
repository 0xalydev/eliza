/**
 * Bridge-issued Steward session synchronization keeps refresh authority on the
 * origin that performed the real login. The deterministic route harness proves
 * that a bridged access token deletes any older host refresh cookie and ignores
 * a caller-supplied refresh token, while an ordinary login may still install
 * its paired refresh cookie.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import { Hono } from "hono";

const emitAudit = mock(async () => undefined);
const verifyStewardTokenCached = mock(async (_env: unknown, token: string) => {
  const base = {
    userId: "steward-user-1",
    email: "person@example.test",
    expiration: Math.floor(Date.now() / 1000) + 900,
    issuedAt: Math.floor(Date.now() / 1000) - 60,
  };
  if (token === "bridged-token") return { ...base, bridged: true };
  if (token === "plain-token") return base;
  return null;
});
const syncUserFromSteward = mock(async () => ({
  id: "cloud-user-1",
  organization_id: "org-1",
  initialCreditsGranted: false,
  initialFreeCreditsUsd: "0.00",
  welcomeBonusWithheld: false,
  welcomeBonusWithheldReason: undefined,
  welcomeBonusWithheldMessage: undefined,
}));
class MockStewardPhoneAccountConflictError extends Error {}
class MockStewardTelegramAccountClaimError extends Error {}
const isBlockedBySsoBridgeLogout = mock(async () => false);

mock.module("@/api-app/services/audit-dispatcher-singleton", () => ({
  getAuditDispatcher: () => ({ emit: emitAudit }),
}));

mock.module("@/lib/auth/steward-client", () => ({
  verifyStewardTokenCached,
}));

mock.module("@/lib/steward-sync", () => ({
  describeSyncError: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
  StewardPhoneAccountConflictError: MockStewardPhoneAccountConflictError,
  StewardTelegramAccountClaimError: MockStewardTelegramAccountClaimError,
  syncUserFromSteward,
}));

mock.module("@/lib/services/sso-bridge-codes", () => ({
  isBlockedBySsoBridgeLogout,
}));

mock.module("@/lib/utils/logger", () => ({
  logger: {
    debug: mock(() => undefined),
    error: mock(() => undefined),
    info: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { default: stewardSessionRoute } = await import(
  "../auth/steward-session/route"
);

const ENV = {
  ENVIRONMENT: "staging",
  NODE_ENV: "production",
  STEWARD_SESSION_SECRET: "test-secret",
};

let ipCounter = 0;

function postStewardSession(token: string, refreshToken: string) {
  ipCounter += 1;
  const app = new Hono();
  app.route("/api/auth/steward-session", stewardSessionRoute);
  return app.fetch(
    new Request("https://api-staging.elizacloud.ai/api/auth/steward-session", {
      method: "POST",
      headers: {
        "cf-connecting-ip": `203.0.113.${ipCounter}`,
        "content-type": "application/json",
        origin: "https://staging.elizacloud.ai",
      },
      body: JSON.stringify({ token, refreshToken }),
    }),
    ENV,
  );
}

beforeEach(() => {
  emitAudit.mockClear();
  verifyStewardTokenCached.mockClear();
  syncUserFromSteward.mockClear();
  isBlockedBySsoBridgeLogout.mockClear();
});

describe("POST /api/auth/steward-session — bridged refresh custody", () => {
  test("rechecks logout authority after user sync before committing cookies", async () => {
    let releaseSync: (
      user: Awaited<ReturnType<typeof syncUserFromSteward>>,
    ) => void = () => {};
    const syncGate = new Promise<
      Awaited<ReturnType<typeof syncUserFromSteward>>
    >((resolve) => {
      releaseSync = resolve;
    });
    syncUserFromSteward.mockImplementationOnce(async () => await syncGate);
    isBlockedBySsoBridgeLogout
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);

    const response = postStewardSession("bridged-token", "stale-refresh");
    while (syncUserFromSteward.mock.calls.length === 0) {
      await Promise.resolve();
    }
    releaseSync({
      id: "cloud-user-1",
      organization_id: "org-1",
      initialCreditsGranted: false,
      initialFreeCreditsUsd: "0.00",
      welcomeBonusWithheld: false,
      welcomeBonusWithheldReason: undefined,
      welcomeBonusWithheldMessage: undefined,
    });

    const res = await response;
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ code: "session_ended" });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(isBlockedBySsoBridgeLogout).toHaveBeenCalledTimes(2);
  });

  test("deletes stale host refresh authority and ignores a supplied refresh token", async () => {
    const res = await postStewardSession(
      "bridged-token",
      "refresh-from-account-a",
    );

    expect(res.status).toBe(200);
    const setCookies = res.headers.getSetCookie();
    const cookies = setCookies.join("\n");
    const refreshCookies = setCookies.filter((cookie) =>
      cookie.startsWith("steward-refresh-token-staging="),
    );
    const authedCookie = setCookies.find((cookie) =>
      cookie.startsWith("steward-authed-staging=1"),
    );
    expect(cookies).toContain("steward-token-staging=bridged-token");
    expect(refreshCookies).toHaveLength(1);
    expect(refreshCookies[0]).toMatch(/Max-Age=0/i);
    expect(refreshCookies[0]).not.toContain("refresh-from-account-a");
    expect(refreshCookies[0]).not.toContain("Max-Age=2592000");
    expect(authedCookie).toBeDefined();
    expect(authedCookie).not.toContain("Max-Age=2592000");
    const authedMaxAge = Number(
      authedCookie?.match(/Max-Age=(\d+)/i)?.[1] ?? Number.NaN,
    );
    expect(authedMaxAge).toBeGreaterThan(0);
    expect(authedMaxAge).toBeLessThanOrEqual(900);
  });

  test("an ordinary login still installs its paired refresh cookie", async () => {
    const res = await postStewardSession("plain-token", "ordinary-refresh");

    expect(res.status).toBe(200);
    const cookies = res.headers.getSetCookie().join("\n");
    expect(cookies).toContain("steward-refresh-token-staging=ordinary-refresh");
    expect(cookies).toContain("Max-Age=2592000");
  });
});
