/**
 * Logout enforces the Steward mutation origin policy while keeping production
 * and staging cookie names isolated. The harness mocks teardown collaborators
 * but exercises the real route and cookie headers.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";

const getCurrentUserMock = mock(
  async (
    _context?: unknown,
    _stewardTokenOverride?: string,
  ): Promise<{ id: string; organization_id: string } | null> => null,
);
const endAllUserSessionsMock = mock(async () => undefined);
const invalidateSessionCachesMock = mock(async (_token: string) => undefined);
type StewardVerificationResult =
  | {
      kind: "valid";
      claims: { userId: string; issuedAt: number };
    }
  | { kind: "invalid" }
  | { kind: "unavailable"; error: unknown };
const verifyStewardTokenWithResultMock = mock(
  async (
    _env: unknown,
    _token: string,
  ): Promise<StewardVerificationResult> => ({
    kind: "valid",
    claims: {
      userId: "steward-1",
      issuedAt: 100,
    },
  }),
);
const revokeInferenceSessionsThroughMock = mock(async () => undefined);
const markSsoBridgeLogoutMock = mock(async () => undefined);

mock.module("@/lib/auth", () => ({
  invalidateSessionCaches: invalidateSessionCachesMock,
}));

mock.module("@/lib/auth/workers-hono-auth", () => ({
  getCurrentUser: getCurrentUserMock,
}));
mock.module("@/lib/auth/steward-client", () => ({
  verifyStewardTokenWithResult: verifyStewardTokenWithResultMock,
}));

mock.module("@/lib/middleware/rate-limit-hono-cloudflare", () => ({
  getRequestIp: () => undefined,
  RateLimitPresets: { STANDARD: {} },
  rateLimit: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));

mock.module("@/lib/services/user-sessions", () => ({
  userSessionsService: {
    endAllUserSessions: endAllUserSessionsMock,
  },
}));
mock.module("@/lib/services/inference-credential-revocation", () => ({
  isInferenceStrongRevocationEnabled: (env: Record<string, unknown>) =>
    env.INFERENCE_STRONG_REVOCATION_ENABLED === "true",
  revokeInferenceSessionsThrough: revokeInferenceSessionsThroughMock,
}));
mock.module("@/lib/services/sso-bridge-codes", () => ({
  markSsoBridgeLogout: markSsoBridgeLogoutMock,
}));

mock.module("@/api-app/services/audit-dispatcher-singleton", () => ({
  getAuditDispatcher: () => ({
    emit: mock(async () => undefined),
  }),
}));

mock.module("@/lib/utils/logger", () => ({
  logger: {
    debug: mock(() => undefined),
    error: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { default: app } = await import("./route");

function deletedCookieNames(res: Response): string[] {
  return res.headers
    .getSetCookie()
    .filter((cookie) => /Max-Age=0/i.test(cookie))
    .map((cookie) => cookie.split("=")[0]);
}

beforeEach(() => {
  getCurrentUserMock.mockResolvedValue(null);
  invalidateSessionCachesMock.mockClear();
  invalidateSessionCachesMock.mockResolvedValue(undefined);
  verifyStewardTokenWithResultMock.mockClear();
  verifyStewardTokenWithResultMock.mockResolvedValue({
    kind: "valid",
    claims: {
      userId: "steward-1",
      issuedAt: 100,
    },
  });
  revokeInferenceSessionsThroughMock.mockResolvedValue(undefined);
  markSsoBridgeLogoutMock.mockClear();
  markSsoBridgeLogoutMock.mockResolvedValue(undefined);
});

describe("POST /api/auth/logout cookie clearing", () => {
  test("stamps logout authority for a bearer-authenticated hosted session", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://cloud-staging.eliza.app",
          authorization: "Bearer header.payload.signature",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    expect((await res.json()) as unknown).toEqual({
      success: true,
      logoutProofVersion: 1,
      barrierState: "confirmed",
      barrierConfirmed: true,
      message: "Logged out successfully",
    });
    expect(verifyStewardTokenWithResultMock).toHaveBeenCalledWith(
      expect.anything(),
      "header.payload.signature",
      { skipDistributedCache: true },
    );
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledWith("steward-1");
  });

  test("strong rollout commits the session cutoff before reporting logout success", async () => {
    getCurrentUserMock.mockResolvedValue({
      id: "user-1",
      organization_id: "org-1",
    });
    revokeInferenceSessionsThroughMock.mockResolvedValue(undefined);
    revokeInferenceSessionsThroughMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-token=prod-token",
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(200);
    expect(revokeInferenceSessionsThroughMock).toHaveBeenCalledWith(
      "org-1",
      "user-1",
      100,
    );
  });

  test("strong rollout preserves retry credentials when the cutoff is unconfirmed", async () => {
    getCurrentUserMock.mockResolvedValue({
      id: "user-1",
      organization_id: "org-1",
    });
    revokeInferenceSessionsThroughMock.mockRejectedValueOnce(
      new Error("boundary unavailable"),
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-token=prod-token",
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(503);
    expect(deletedCookieNames(res)).toEqual([]);
    expect((await res.json()) as unknown).toEqual({
      error: "Logout revocation is temporarily unavailable",
      code: "logout_revocation_unavailable",
    });
  });

  test("preserves retry credentials when the cross-host logout marker is unconfirmed", async () => {
    markSsoBridgeLogoutMock.mockRejectedValue(new Error("marker unavailable"));

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-token=prod-token",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledTimes(2);
    expect(deletedCookieNames(res)).toEqual([]);
    expect((await res.json()) as unknown).toEqual({
      error: "Logout revocation is temporarily unavailable",
      code: "logout_revocation_unavailable",
    });
  });

  test("preserves retry authority when token verification is unavailable", async () => {
    verifyStewardTokenWithResultMock.mockResolvedValue({
      kind: "unavailable",
      error: new Error("verifier unavailable"),
    });

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-token=prod-token",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("preserves all authority when one of two credential verifications is unavailable", async () => {
    verifyStewardTokenWithResultMock.mockImplementation(
      async (
        _env: unknown,
        token: string,
      ): Promise<StewardVerificationResult> =>
        token === "valid.bearer.jwt"
          ? {
              kind: "valid",
              claims: { userId: "same-user", issuedAt: 100 },
            }
          : {
              kind: "unavailable",
              error: new Error("cookie verifier unavailable"),
            },
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          authorization: "Bearer valid.bearer.jwt",
          cookie: "steward-token=cookie-token",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("never claims a cross-host barrier for an invalid credential", async () => {
    verifyStewardTokenWithResultMock.mockResolvedValue({ kind: "invalid" });

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-token=invalid-token",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    expect((await res.json()) as unknown).toEqual({
      success: true,
      logoutProofVersion: 1,
      barrierState: "already_absent",
      barrierConfirmed: false,
      message: "Logged out successfully",
    });
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toContain("steward-token");
  });

  test("preserves a refresh-only session instead of falsely proving it absent", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie: "steward-refresh-token=live-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect((await res.json()) as unknown).toEqual({
      error: "Logout revocation is temporarily unavailable",
      code: "logout_revocation_unavailable",
    });
    expect(verifyStewardTokenWithResultMock).not.toHaveBeenCalled();
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("preserves a staging-scoped refresh-only session", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          cookie: "steward-refresh-token-staging=live-staging-refresh",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(verifyStewardTokenWithResultMock).not.toHaveBeenCalled();
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("preserves refresh authority when the accompanying access token is invalid", async () => {
    verifyStewardTokenWithResultMock.mockResolvedValue({ kind: "invalid" });

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie:
            "steward-token=expired-token; steward-refresh-token=live-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("a valid bearer cannot prove the lineage of a refresh-only cookie", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          authorization: "Bearer valid.bearer.jwt",
          cookie: "steward-refresh-token=unknown-lineage-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("a valid bearer cannot mask an invalid access cookie beside refresh authority", async () => {
    verifyStewardTokenWithResultMock.mockImplementation(
      async (
        _env: unknown,
        token: string,
      ): Promise<StewardVerificationResult> =>
        token === "valid.bearer.jwt"
          ? {
              kind: "valid",
              claims: { userId: "bearer-user", issuedAt: 200 },
            }
          : { kind: "invalid" },
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          authorization: "Bearer valid.bearer.jwt",
          cookie:
            "steward-token=expired-cookie-token; steward-refresh-token=unknown-lineage-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(invalidateSessionCachesMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("a stale bearer cannot mask a valid scoped access cookie", async () => {
    getCurrentUserMock.mockResolvedValue({
      id: "user-cookie",
      organization_id: "org-cookie",
    });
    revokeInferenceSessionsThroughMock.mockClear();
    verifyStewardTokenWithResultMock.mockImplementation(
      async (
        _env: unknown,
        token: string,
      ): Promise<StewardVerificationResult> =>
        token === "stale.bearer.jwt"
          ? { kind: "invalid" }
          : {
              kind: "valid",
              claims: { userId: "cookie-user", issuedAt: 200 },
            },
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          authorization: "Bearer stale.bearer.jwt",
          cookie: "steward-token=valid-cookie-token",
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(200);
    expect(getCurrentUserMock).toHaveBeenCalledWith(
      expect.anything(),
      "valid-cookie-token",
    );
    expect(revokeInferenceSessionsThroughMock).toHaveBeenCalledWith(
      "org-cookie",
      "user-cookie",
      200,
    );
    expect(markSsoBridgeLogoutMock).toHaveBeenCalledWith("cookie-user");
    expect(deletedCookieNames(res)).toContain("steward-token");
  });

  test("conflicting valid bearer and cookie identities fail closed", async () => {
    verifyStewardTokenWithResultMock.mockImplementation(
      async (
        _env: unknown,
        token: string,
      ): Promise<StewardVerificationResult> => ({
        kind: "valid",
        claims: {
          userId: token === "first.bearer.jwt" ? "bearer-user" : "cookie-user",
          issuedAt: 200,
        },
      }),
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          authorization: "Bearer first.bearer.jwt",
          cookie: "steward-token=valid-cookie-token",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(503);
    expect(markSsoBridgeLogoutMock).not.toHaveBeenCalled();
    expect(deletedCookieNames(res)).toEqual([]);
  });

  test("verifies a duplicated bearer and cookie token only once", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          authorization: "Bearer same.token.jwt",
          cookie: "steward-token=same.token.jwt",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    expect(verifyStewardTokenWithResultMock).toHaveBeenCalledTimes(1);
    expect(invalidateSessionCachesMock).toHaveBeenCalledTimes(1);
    expect(invalidateSessionCachesMock).toHaveBeenCalledWith("same.token.jwt");
  });

  test("uses the newest same-user credential and drains both token caches", async () => {
    getCurrentUserMock.mockResolvedValue({
      id: "user-1",
      organization_id: "org-1",
    });
    verifyStewardTokenWithResultMock.mockImplementation(
      async (
        _env: unknown,
        token: string,
      ): Promise<StewardVerificationResult> => ({
        kind: "valid",
        claims: {
          userId: "same-user",
          issuedAt: token === "older.bearer.jwt" ? 100 : 200,
        },
      }),
    );

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          authorization: "Bearer older.bearer.jwt",
          cookie: "steward-token=newer-cookie-token",
        },
      },
      {
        ENVIRONMENT: "production",
        NODE_ENV: "production",
        INFERENCE_STRONG_REVOCATION_ENABLED: "true",
      },
    );

    expect(res.status).toBe(200);
    expect(getCurrentUserMock).toHaveBeenCalledWith(
      expect.anything(),
      "newer-cookie-token",
    );
    expect(revokeInferenceSessionsThroughMock).toHaveBeenCalledWith(
      "org-1",
      "user-1",
      200,
    );
    expect(invalidateSessionCachesMock).toHaveBeenCalledTimes(2);
    expect(invalidateSessionCachesMock).toHaveBeenCalledWith(
      "older.bearer.jwt",
    );
    expect(invalidateSessionCachesMock).toHaveBeenCalledWith(
      "newer-cookie-token",
    );
  });

  test("staging legacy-only logout does not end production user sessions", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    expect((await res.json()) as unknown).toEqual({
      success: true,
      logoutProofVersion: 1,
      barrierState: "already_absent",
      barrierConfirmed: false,
      message: "Logged out successfully",
    });
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("steward-token-staging");
    expect(cleared).toContain("steward-refresh-token-staging");
    expect(cleared).toContain("steward-authed-staging");
    expect(cleared).not.toContain("steward-token");
    expect(cleared).not.toContain("steward-refresh-token");
    expect(cleared).not.toContain("steward-authed");
    expect(getCurrentUserMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });

  test("staging logout does not delete production's unsuffixed steward cookies", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api-staging.elizacloud.ai",
          origin: "https://staging.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh; steward-token-staging=staging-token; steward-refresh-token-staging=staging-refresh",
        },
      },
      { ENVIRONMENT: "staging", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("steward-token-staging");
    expect(cleared).toContain("steward-refresh-token-staging");
    expect(cleared).toContain("steward-authed-staging");
    expect(cleared).not.toContain("steward-token");
    expect(cleared).not.toContain("steward-refresh-token");
    expect(cleared).not.toContain("steward-authed");
  });

  test("production logout still clears the historical steward cookies", async () => {
    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.elizacloud.ai",
          origin: "https://eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(200);
    const cleared = deletedCookieNames(res);
    expect(cleared).toContain("steward-token");
    expect(cleared).toContain("steward-refresh-token");
    expect(cleared).toContain("steward-authed");
  });

  test("same-site user-content origin cannot force a production logout", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.eliza.app",
          origin: "https://attacker.cloud.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(403);
    expect((await res.json()) as unknown).toEqual({
      error: "Forbidden",
      code: "forbidden_origin",
    });
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(getCurrentUserMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });

  test("missing browser origin cannot mutate the session", async () => {
    getCurrentUserMock.mockClear();
    endAllUserSessionsMock.mockClear();

    const res = await app.request(
      "/",
      {
        method: "POST",
        headers: {
          host: "api.eliza.app",
          cookie:
            "steward-token=prod-token; steward-refresh-token=prod-refresh",
        },
      },
      { ENVIRONMENT: "production", NODE_ENV: "production" },
    );

    expect(res.status).toBe(403);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(getCurrentUserMock).not.toHaveBeenCalled();
    expect(endAllUserSessionsMock).not.toHaveBeenCalled();
  });
});
