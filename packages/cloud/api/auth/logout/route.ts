/**
 * POST /api/auth/logout
 * Establishes the available browser-session logout barriers, then clears the
 * host cookies and drains session/cache state. Steward refresh-family
 * revocation remains an upstream session-lineage contract.
 */

import {
  STEWARD_LOGOUT_PROOF_VERSION,
  type StewardLogoutResponse,
} from "@elizaos/shared/steward-session-client";
import { Hono } from "hono";
import { deleteCookie } from "hono/cookie";
import { getAuditDispatcher } from "@/api-app/services/audit-dispatcher-singleton";
import { invalidateSessionCaches } from "@/lib/auth";
import { checkElizaMutatingRequestOrigin } from "@/lib/auth/browser-origin-policy";
import { cookieDomainForHost } from "@/lib/auth/cookie-domain";
import {
  type StewardTokenClaims,
  verifyStewardTokenWithResult,
} from "@/lib/auth/steward-client";
import { stewardCookieNames } from "@/lib/auth/steward-cookies";
import {
  getCurrentUser,
  readStewardSessionToken,
} from "@/lib/auth/workers-hono-auth";
import {
  getRequestIp,
  RateLimitPresets,
  rateLimit,
} from "@/lib/middleware/rate-limit-hono-cloudflare";
import {
  isInferenceStrongRevocationEnabled,
  revokeInferenceSessionsThrough,
} from "@/lib/services/inference-credential-revocation";
import { markSsoBridgeLogout } from "@/lib/services/sso-bridge-codes";
import { userSessionsService } from "@/lib/services/user-sessions";
import { logger } from "@/lib/utils/logger";
import type { AppEnv } from "@/types/cloud-worker-env";

const app = new Hono<AppEnv>();

app.use("*", rateLimit(RateLimitPresets.STANDARD));

app.post("/", async (c) => {
  const originCheck = checkElizaMutatingRequestOrigin(
    c.req,
    c.env.NODE_ENV === "production",
  );
  if (!originCheck.ok) {
    logger.warn("[Logout] Rejected cross-origin POST", {
      detail: originCheck.reason,
    });
    return c.json(
      { error: "Forbidden", code: "forbidden_origin" as const },
      403,
    );
  }

  const cookieNames = stewardCookieNames(c.env.ENVIRONMENT);
  // Hosted SPAs authenticate with a localStorage JWT in Authorization, while
  // auth-origin pages may use the environment-scoped cookie. Resolve both
  // through the same JWT-only selection used by getCurrentUser; API-key
  // bearers are deliberately excluded from browser-session teardown.
  const stewardToken = readStewardSessionToken(c);

  let verifiedClaims: StewardTokenClaims | null = null;
  if (stewardToken) {
    const verification = await verifyStewardTokenWithResult(
      c.env,
      stewardToken,
      { skipDistributedCache: true },
    );
    if (verification.kind === "unavailable") {
      // error-policy:J1 do not destroy the credential needed to retry a
      // security boundary whose verifier could not establish token authority.
      logger.error("[Logout] Steward token verification unavailable", {
        error:
          verification.error instanceof Error
            ? verification.error.message
            : String(verification.error),
      });
      return c.json(
        {
          error: "Logout revocation is temporarily unavailable",
          code: "logout_revocation_unavailable" as const,
        },
        503,
      );
    }
    if (verification.kind === "valid") {
      verifiedClaims = verification.claims;
    }
  }

  let strongRevocationFailed = false;
  let ssoLogoutBarrierFailed = false;
  if (verifiedClaims && isInferenceStrongRevocationEnabled(c.env)) {
    try {
      const user = await getCurrentUser(c);
      if (!user?.organization_id) {
        throw new Error("logout credential identity could not be resolved");
      }
      await revokeInferenceSessionsThrough(
        user.organization_id,
        user.id,
        verifiedClaims.issuedAt,
      );
    } catch (error) {
      // error-policy:J1 preserve retry credentials and never claim a globally
      // complete logout until the strong inference boundary confirms that the
      // presented session generation is denied.
      logger.error("[Logout] Strong inference-session revocation failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      strongRevocationFailed = true;
    }
  }

  // Stamp the cross-host SSO logout marker FIRST and in its own guarded block:
  // the sso-bridge legs and the cookie-planting session-sync endpoint refuse
  // tokens issued before this moment, so an explicit logout cannot be silently
  // undone by the paired host bridging or re-syncing the other origin's
  // still-unexpired session back in. The marker lives in Postgres (same store
  // the bridge reads), so a store outage that loses this stamp also disables
  // the bridge itself — but a TRANSIENT stamp failure would leave a bridgeable
  // window once the store recovers, hence one retry and an error-level log
  // (never a silent downgrade to debug) when the stamp is unconfirmed. The
  // response then fails closed before credentials are destroyed.
  if (verifiedClaims) {
    try {
      try {
        await markSsoBridgeLogout(verifiedClaims.userId);
      } catch {
        // error-policy:J6 single bounded retry; the definitive failure is
        // handled (loudly) by the outer fail-closed boundary.
        await markSsoBridgeLogout(verifiedClaims.userId);
      }
      logger.debug("[Logout] Stamped SSO bridge logout marker");
    } catch (error) {
      // error-policy:J1 the server must not report a globally complete logout
      // when its cross-host barrier did not land. The 503 below tells account-
      // switch callers not to bridge a new identity across an unconfirmed
      // old-session boundary and leaves the original credential retryable.
      logger.error(
        "[Logout] FAILED to stamp SSO bridge logout marker — cross-host logout barrier not persisted",
        {
          error: error instanceof Error ? error.message : String(error),
        },
      );
      ssoLogoutBarrierFailed = true;
    }
  }

  if (strongRevocationFailed || ssoLogoutBarrierFailed) {
    // The browser keeps both cookie and Bearer authority so the exact same
    // validated session can retry after the transient barrier outage.
    return c.json(
      {
        error: "Logout revocation is temporarily unavailable",
        code: "logout_revocation_unavailable" as const,
      },
      503,
    );
  }

  // Critical revocation boundaries are now confirmed. Clear browser cookies
  // before best-effort session-record/cache teardown, which must never restore
  // authority or turn a completed logout into a false failure.
  const domain = cookieDomainForHost(c.req.header("host"));
  const stewardOpts = domain ? { path: "/", domain } : { path: "/" };
  // Non-production clears only its suffixed pair. The unsuffixed legacy names
  // are production's live cookies on the shared parent domain; deleting them
  // from staging/dev signs the user out of production.
  // In production the scoped names already ARE the historical unsuffixed names,
  // so a single set of deleteCookie calls covers both eras. The separate legacy
  // clear block was redundant (#14130).
  deleteCookie(c, cookieNames.token, stewardOpts);
  deleteCookie(c, cookieNames.refreshToken, stewardOpts);
  deleteCookie(c, cookieNames.authed, stewardOpts);
  deleteCookie(c, "eliza-anon-session", { path: "/" });

  try {
    // Only tear down caches/sessions when the request presented a Steward JWT
    // through this environment's scoped cookie or Authorization header.
    if (stewardToken) {
      await invalidateSessionCaches(stewardToken);
      logger.debug("[Logout] Invalidated session caches for token");
    }

    if (stewardToken) {
      const user = await getCurrentUser(c);
      if (user) {
        await userSessionsService.endAllUserSessions(user.id);
        await getAuditDispatcher()
          .emit({
            actor: { type: "user", id: user.id },
            action: "auth.logout",
            result: "success",
            resource: null,
            org_id: user.organization_id ?? undefined,
            ip: getRequestIp(c),
            user_agent: c.req.header("user-agent") ?? undefined,
            request_id: c.get("requestId"),
            metadata: { method: "steward_session" },
          })
          // error-policy:J7 audit write is diagnostic; logout already succeeded via
          // the cookie clear above, so a dropped audit event is logged, not fatal.
          .catch((err: unknown) => {
            logger.warn("[Logout] audit emit failed", {
              error: err instanceof Error ? err.message : String(err),
            });
          });
      }
    }
  } catch (error) {
    // error-policy:J6 best-effort teardown — cookies are already cleared, so the
    // user is logged out client-side; a failed server-side session teardown must
    // not turn logout into a 500 that strands stale cookies. Caches expire on TTL.
    logger.warn(
      "[Logout] server-side teardown failed (cookies already cleared)",
      {
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  const proof: StewardLogoutResponse = verifiedClaims
    ? {
        success: true,
        logoutProofVersion: STEWARD_LOGOUT_PROOF_VERSION,
        barrierState: "confirmed",
        barrierConfirmed: true,
        message: "Logged out successfully",
      }
    : {
        success: true,
        logoutProofVersion: STEWARD_LOGOUT_PROOF_VERSION,
        barrierState: "already_absent",
        barrierConfirmed: false,
        message: "Logged out successfully",
      };
  return c.json(proof);
});

export default app;
