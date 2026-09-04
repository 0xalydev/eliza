/**
 * Shared Steward session plumbing for the cloud shell: token storage keys and the
 * session/refresh endpoints the Steward auth provider uses.
 */
import {
  clearStoredStewardToken,
  clearStoredStewardTokenIfCurrent,
  readStoredStewardToken,
  STEWARD_REFRESH_ENDPOINT,
  STEWARD_SESSION_ENDPOINT,
  StewardTokenRemovalError,
} from "@elizaos/shared/steward-session-client";
import { createContext } from "react";
import { client } from "../../api";
import {
  removeManagedSharedCloudAgentProfiles,
  scrubPersistedAgentProfileTokens,
} from "../../state/agent-profiles";
import { scrubPersistedActiveServerToken } from "../../state/persistence";
import { clearSharedCloudAccountBinding } from "../../state/shared-cloud-account-binding";
import { clearElizaApiToken } from "../../utils/eliza-globals";
import { decodeJwtPayload } from "../lib/jwt";
import {
  invalidateStewardServerCookieSyncMarker,
  invalidateStewardServerCookieSyncMarkerIfOwned,
} from "../lib/steward-session-cookie-sync-marker";
import { ELIZA_CLOUD_DIRECT_API_BY_HOST } from "./steward-url";

export function isPlaceholderValue(value: string | undefined): boolean {
  if (!value) return true;
  const normalized = value.trim().toLowerCase();
  return (
    normalized.length === 0 ||
    normalized.includes("your_steward_") ||
    normalized.includes("your-steward-") ||
    normalized.includes("replace_with") ||
    normalized.includes("placeholder")
  );
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

// On canonical Eliza UI hosts, session-sync and refresh stay same-origin via
// the Pages/Worker proxy. Steward cookies are host-only, so sending these calls
// directly to api.eliza.app would plant cookies on the API host and make them
// invisible to eliza.app/cloud.eliza.app. The host map is environment-aware;
// unknown/native origins may still use an explicit API base below.
function directCloudApiBase(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return ELIZA_CLOUD_DIRECT_API_BY_HOST[window.location.hostname.toLowerCase()];
}

function directStewardSessionEndpoint(): string | undefined {
  const base = directCloudApiBase();
  return base ? `${base}${STEWARD_SESSION_ENDPOINT}` : undefined;
}

function directStewardRefreshEndpoint(): string | undefined {
  const base = directCloudApiBase();
  return base ? `${base}${STEWARD_REFRESH_ENDPOINT}` : undefined;
}

export type LocalStewardAuthValue = {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: {
    id: string;
    email?: string | null;
    walletAddress?: string;
    wallet_address?: string;
  } | null;
  session: unknown;
  signOut: () => unknown;
  getToken: () => unknown;
  verifyEmailCallback: (
    token: string,
    email: string,
  ) => Promise<{ token: string; refreshToken?: string }>;
};

export const LocalStewardAuthContext =
  createContext<LocalStewardAuthValue | null>(null);

function configuredApiBase(): string | undefined {
  return (
    import.meta.env?.VITE_API_URL ||
    import.meta.env?.NEXT_PUBLIC_API_URL ||
    (typeof process !== "undefined"
      ? process.env.NEXT_PUBLIC_API_URL
      : undefined)
  );
}

export function configuredSessionEndpoint(): string {
  const direct = directStewardSessionEndpoint();
  if (direct) {
    return direct;
  }
  const apiBase = configuredApiBase();
  if (apiBase && !isPlaceholderValue(apiBase)) {
    return `${trimTrailingSlash(apiBase)}${STEWARD_SESSION_ENDPOINT}`;
  }
  return STEWARD_SESSION_ENDPOINT;
}

export function configuredRefreshEndpoint(): string {
  const direct = directStewardRefreshEndpoint();
  if (direct) {
    return direct;
  }
  const apiBase = configuredApiBase();
  if (apiBase && !isPlaceholderValue(apiBase)) {
    return `${trimTrailingSlash(apiBase)}${STEWARD_REFRESH_ENDPOINT}`;
  }
  return STEWARD_REFRESH_ENDPOINT;
}

function stewardSessionClearUrls(): string[] {
  if (typeof window === "undefined") return [configuredSessionEndpoint()];
  const candidates = [STEWARD_SESSION_ENDPOINT, configuredSessionEndpoint()];
  const direct = directStewardSessionEndpoint();
  if (direct) {
    candidates.push(direct);
  }
  const seen = new Set<string>();
  return candidates.filter((url) => {
    // Relative and absolute forms can name the exact same same-origin route
    // (for example `/api/...` and `https://eliza.app/api/...`). One transient
    // duplicate failure must not negate an already-acknowledged deletion.
    let identity = url;
    try {
      identity = new URL(url, window.location.origin).href;
    } catch {
      // error-policy:J4 retain an unparseable configured target as its own
      // request; the DELETE will fail closed through the normal fetch result.
    }
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

const STEWARD_SESSION_COOKIE_CLEAR_TIMEOUT_MS = 10_000;

export interface StewardSessionCookieClearOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export type StewardSessionCookieClearResult = { ok: true } | { ok: false };

export interface StaleStewardSessionClearOptions
  extends StewardSessionCookieClearOptions {
  /** Preserve legacy fire-and-forget cleanup unless a custody lock owns it. */
  awaitCookieClear?: boolean;
  /** Ignore a delayed response once a newer canonical bearer owns the app. */
  expectedToken?: string;
}

function clearServerStewardSessionCookie(
  url: string,
  {
    signal,
    timeoutMs = STEWARD_SESSION_COOKIE_CLEAR_TIMEOUT_MS,
  }: StewardSessionCookieClearOptions,
): Promise<boolean> {
  const abortController = new AbortController();
  const forwardAbort = (): void => abortController.abort();
  signal?.addEventListener("abort", forwardAbort, { once: true });

  return new Promise<boolean>((resolve) => {
    let settled = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const finish = (acknowledged: boolean): void => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) globalThis.clearTimeout(timeout);
      abortController.signal.removeEventListener("abort", fail);
      signal?.removeEventListener("abort", forwardAbort);
      resolve(acknowledged);
    };
    const fail = (): void => finish(false);
    abortController.signal.addEventListener("abort", fail, { once: true });
    timeout = globalThis.setTimeout(() => abortController.abort(), timeoutMs);
    if (signal?.aborted) {
      abortController.abort();
      return;
    }

    try {
      void fetch(url, {
        method: "DELETE",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        signal: abortController.signal,
      }).then((response) => {
        if (!response.ok) {
          finish(false);
          return;
        }
        try {
          void response.json().then((body: unknown) => {
            if (!body || typeof body !== "object" || Array.isArray(body)) {
              finish(false);
              return;
            }
            const keys = Object.keys(body);
            finish(
              keys.length === 1 &&
                keys[0] === "ok" &&
                (body as { ok?: unknown }).ok === true,
            );
          }, fail);
        } catch {
          // error-policy:J3 a synchronously throwing/injected body parser
          // cannot prove that the cookie deletion completed.
          fail();
        }
      }, fail);
    } catch {
      // error-policy:J3 an injected fetch may throw synchronously. This is an
      // explicit unconfirmed teardown result, never fabricated success.
      fail();
    }
  });
}

export async function clearServerStewardSessionCookies(
  options: StewardSessionCookieClearOptions = {},
): Promise<StewardSessionCookieClearResult> {
  // Invalidate before issuing any best-effort DELETE: a rejected request must
  // never leave a proof that can suppress a later session-establishing POST.
  invalidateStewardServerCookieSyncMarker();
  // Every attempt settles on an acknowledged exact `{ ok: true }` response or
  // an explicit unconfirmed result (non-2xx, malformed body, transport error,
  // cancellation, or deadline). Awaiting this promise under the cross-tab
  // custody lock prevents a late DELETE response from racing a newer
  // session-establishing POST while still letting legacy fire-and-forget
  // callers ignore a resolved result without creating unhandled rejections.
  const acknowledgements = await Promise.all(
    stewardSessionClearUrls().map((url) =>
      clearServerStewardSessionCookie(url, options),
    ),
  );
  return acknowledgements.every(Boolean) ? { ok: true } : { ok: false };
}

export function readStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return readStoredStewardToken();
  } catch {
    // error-policy:J3 storage unavailable reads as signed-out (fail-closed).
    return null;
  }
}

export function tokenIsExpired(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload) return true;
  // No exp claim ⇒ treat as expired. Steward always mints exp; an exp-less
  // token is foreign/malformed, and since the 401 handlers keep any
  // NON-expired token, an exp-less one would otherwise be uncloseable — no
  // 401 could ever clear it and it never ages out on its own.
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
    return true;
  }
  return payload.exp * 1000 < Date.now();
}

export function tokenSecsRemaining(token: string): number | null {
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return null;
  return payload.exp - Date.now() / 1000;
}

export async function clearStaleStewardSession(
  options: StaleStewardSessionClearOptions = {},
): Promise<boolean> {
  if (typeof window === "undefined") return false;
  // This is deliberately before protected-storage removal. That operation can
  // reject and abort the rest of teardown, but an attempted session clear must
  // still retire any unconsumed proof from the previous authority epoch.
  if (options.expectedToken === undefined) {
    invalidateStewardServerCookieSyncMarker();
  } else {
    invalidateStewardServerCookieSyncMarkerIfOwned(options.expectedToken);
  }
  let storedTokenClearError: unknown;
  try {
    if (options.expectedToken !== undefined) {
      const cleared = await clearStoredStewardTokenIfCurrent(
        options.expectedToken,
      );
      if (!cleared) return false;
      // The guarded removal and a newer login are serialized. If that newer
      // login already published before this continuation runs, preserve all of
      // its mirrors instead of applying A's delayed destructive cleanup to B.
      if (readStoredStewardToken() !== null) return false;
    } else {
      await clearStoredStewardToken();
    }
  } catch (error) {
    if (error instanceof StewardTokenRemovalError) throw error;
    // Canonical A removal can publish `cleared` before obsolete refresh-key
    // cleanup throws. Another realm or re-entrant storage boundary may publish
    // account B while this awaited removal unwinds, so repeat the authority
    // check before applying A's destructive mirror/cookie scrub.
    if (
      options.expectedToken !== undefined &&
      readStoredStewardToken() !== null
    ) {
      return false;
    }
    // error-policy:J2 canonical invalidation may already have succeeded before
    // obsolete refresh-key cleanup failed. Finish every credential teardown,
    // then rethrow the original storage error with its stack intact.
    storedTokenClearError = error;
  }
  // `ElizaClient` mirrors its live bearer into boot config, while native and
  // desktop hosts can independently inject the same owner key through the
  // window-scoped API token. Both are canonical request-authority sources and
  // must end in the same teardown transaction as the Steward JWT. Clearing
  // only persisted profiles would leave the running renderer authenticated
  // until reload (and native Cloud calls could keep using the injected key).
  client.setToken(null);
  clearElizaApiToken();
  // Every shared-agent profile belongs to the ending Steward account, even
  // when a dedicated or self-hosted target happens to be active at sign-out.
  removeManagedSharedCloudAgentProfiles();
  // SECURITY: also scrub the persisted accessToken mirrors so the secondary
  // sign-out / 401-self-heal paths that route through here (native apps-studio
  // signOut, the authorize-content edge, StewardProviderRuntime 401 clears) don't
  // leave a usable cloud bearer/API-key at rest in localStorage.
  if (clearSharedCloudAccountBinding()) {
    // Shared runtime authorization is the Steward account itself. Once that
    // account session ends, retaining its selected agent id can bind the next
    // login to an agent outside the newly authenticated organization. Remove
    // the selection so the normal post-login flow resolves the current
    // account's organization-scoped agent list before mounting chat.
  } else {
    // Dedicated/self-hosted targets have an independent agent-local recovery
    // path, so preserve their selection while removing the rejected bearer.
    scrubPersistedActiveServerToken();
  }
  scrubPersistedAgentProfileTokens();
  const cookieClear = clearServerStewardSessionCookies(options);
  let cookieClearError: Error | undefined;
  if (options.awaitCookieClear && !(await cookieClear).ok) {
    cookieClearError = new Error(
      "Eliza Cloud session-cookie cleanup was not acknowledged.",
    );
  }
  try {
    window.dispatchEvent(new CustomEvent("steward-token-sync"));
  } catch {
    // error-policy:J6 best-effort sync notification after credentials are scrubbed.
  }
  if (storedTokenClearError !== undefined) throw storedTokenClearError;
  if (cookieClearError) throw cookieClearError;
  return true;
}
