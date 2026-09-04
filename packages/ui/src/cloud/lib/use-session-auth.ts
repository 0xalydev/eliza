/**
 * Canonical "is the user logged in" hook for every app-hosted cloud domain.
 *
 * Reads the Steward auth context the cloud shell exposes
 * (`LocalStewardAuthContext` in `../shell/StewardProvider`). The shell only
 * mounts the heavy `@stwd/*` runtime on demand, so this hook also falls back to
 * reading the JWT directly from `localStorage` (decoded, expiry-checked) when
 * the provider isn't mounted — keeping authed cloud views able to gate on
 * `{ ready, authenticated, user }` without forcing the runtime to load.
 *
 * Test builds (`VITE_PLAYWRIGHT_TEST_AUTH` / `NEXT_PUBLIC_PLAYWRIGHT_TEST_AUTH`)
 * also honor the Playwright `eliza-test-auth` marker cookie so browser-driven
 * suites can exercise authed surfaces against a mock stack.
 */

import { Capacitor } from "@capacitor/core";
import { getElizaApiToken } from "@elizaos/shared";
import {
  readStoredStewardToken,
  STEWARD_SESSION_CHANGE_EVENT,
  STEWARD_TOKEN_KEY,
  type StewardSessionChangeDetail,
} from "@elizaos/shared/steward-session-client";
import { useContext, useEffect, useState } from "react";
import { isElectrobunRuntime } from "../../bridge/electrobun-runtime";
import { getBootConfig } from "../../config/boot-config";
import {
  LocalStewardAuthContext,
  type LocalStewardAuthValue,
} from "../shell/StewardProvider";
import {
  isSsoLoggedOut,
  SSO_LOGOUT_STATE_EVENT,
  type SsoLogoutStateChangeDetail,
} from "../sso-bridge/sso-bridge";
import { normalizeCloudApiKeyToken } from "./cloud-api-key-token";
import { decodeJwtPayload } from "./jwt";

export type StewardSessionUser = {
  id: string;
  email: string;
  walletAddress?: string;
} | null;

const STEWARD_AUTH_FALLBACK: Pick<
  LocalStewardAuthValue,
  "isAuthenticated" | "isLoading" | "user"
> = {
  isAuthenticated: false,
  isLoading: false,
  user: null,
};

const PLAYWRIGHT_TEST_AUTH_MARKER_COOKIE = "eliza-test-auth";
const PLAYWRIGHT_TEST_USER_ID = "22222222-2222-4222-8222-222222222222";
const PLAYWRIGHT_TEST_USER_EMAIL = "local-live-test-user@agent.local";
const SSO_LOGGED_OUT_STORAGE_KEY = "eliza_sso_logged_out";
const SSO_LOGOUT_GENERATION_STORAGE_KEY = "eliza_sso_logout_generation";

/**
 * Read each env var by its literal name — Vite inlines custom `VITE_*` vars only
 * on literal property access; a dynamic lookup returns `undefined` in prod and
 * silently disables the Playwright test-auth bypass.
 */
function isPlaywrightTestAuthEnabled(): boolean {
  if (import.meta.env?.VITE_PLAYWRIGHT_TEST_AUTH === "true") return true;
  if (
    typeof process !== "undefined" &&
    process.env?.NEXT_PUBLIC_PLAYWRIGHT_TEST_AUTH === "true"
  ) {
    return true;
  }
  return false;
}

function hasCookie(name: string, value?: string): boolean {
  if (typeof document === "undefined") return false;
  const expected = value ? `${name}=${value}` : `${name}=`;
  return document.cookie
    .split(";")
    .some((part) => part.trim().startsWith(expected));
}

function readPlaywrightTestSession(): StewardSessionUser {
  if (!isPlaywrightTestAuthEnabled()) return null;
  if (!hasCookie(PLAYWRIGHT_TEST_AUTH_MARKER_COOKIE, "1")) return null;
  return {
    id: PLAYWRIGHT_TEST_USER_ID,
    email: PLAYWRIGHT_TEST_USER_EMAIL,
  };
}

function isNativeCloudRuntime(): boolean {
  return Capacitor.isNativePlatform() || isElectrobunRuntime();
}

function nativeCloudApiKey(): string | null {
  if (!isNativeCloudRuntime()) return null;
  // Only a real cloud key (not the on-device agent bearer) counts as a native
  // cloud session.
  return (
    normalizeCloudApiKeyToken(getBootConfig().apiToken) ??
    normalizeCloudApiKeyToken(getElizaApiToken())
  );
}

function apiKeySessionId(token: string): string {
  let hash = 2166136261;
  for (let index = 0; index < token.length; index++) {
    hash ^= token.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `native-api-key:${(hash >>> 0).toString(36)}`;
}

function readNativeApiKeySession(): StewardSessionUser {
  const token = nativeCloudApiKey();
  if (!token) return null;
  return {
    id: apiKeySessionId(token),
    email: "",
  };
}

function decodeStewardToken(token: string): {
  id: string;
  email: string;
  walletAddress?: string;
  exp?: number;
} | null {
  const payload = decodeJwtPayload(token);
  if (!payload) return null;
  return {
    id: payload.userId ?? payload.sub ?? "",
    email: payload.email ?? "",
    walletAddress: payload.address ?? undefined,
    exp: payload.exp,
  };
}

/** Read a valid non-expired Steward session directly from localStorage. */
function readStewardSessionFromStorage(): StewardSessionUser {
  if (typeof window === "undefined") return null;
  try {
    const token = readStoredStewardToken();
    if (!token) return null;
    const decoded = decodeStewardToken(token);
    if (!decoded?.id) return null;
    if (decoded.exp && decoded.exp * 1000 < Date.now()) return null;
    return {
      id: decoded.id,
      email: decoded.email,
      walletAddress: decoded.walletAddress,
    };
  } catch {
    // error-policy:J3 unreadable storage or undecodable token reads as
    // signed-out (fail-closed) — never a fabricated session.
    return null;
  }
}

/**
 * Safe accessor for the cloud-shell Steward auth context. Returns a signed-out
 * fallback when the provider is not mounted (reads the context directly instead
 * of calling `useAuth()` in a try/catch, which would violate Rules of Hooks).
 */
function useStewardAuthContext(): Pick<
  LocalStewardAuthValue,
  "isAuthenticated" | "isLoading" | "user"
> {
  const ctx = useContext(LocalStewardAuthContext);
  return ctx ?? STEWARD_AUTH_FALLBACK;
}

export interface SessionAuthState {
  ready: boolean;
  authenticated: boolean;
  user: StewardSessionUser;
}

export function useSessionAuth(): SessionAuthState {
  const providerAuth = useStewardAuthContext();
  const [storageUser, setStorageUser] = useState<StewardSessionUser>(
    readStewardSessionFromStorage,
  );
  // The SDK context can remain authenticated briefly after another tab removes
  // the canonical token. Once a real authority transition says that token is
  // gone, never let the stale provider snapshot keep protected UI authenticated.
  // A later durable `present` transition (or token storage event) lifts the
  // override for the next session.
  const [stewardSessionInvalidated, setStewardSessionInvalidated] =
    useState(isSsoLoggedOut);
  const [apiKeyUser, setApiKeyUser] = useState<StewardSessionUser>(
    readNativeApiKeySession,
  );
  const [testUser, setTestUser] = useState<StewardSessionUser>(
    readPlaywrightTestSession,
  );

  useEffect(() => {
    const reread = ({
      invalidateWhenMissing = false,
      forceInvalidate = false,
      allowRevalidate = false,
    }: {
      invalidateWhenMissing?: boolean;
      forceInvalidate?: boolean;
      allowRevalidate?: boolean;
    } = {}) => {
      const nextStorageUser = readStewardSessionFromStorage();
      setStorageUser(nextStorageUser);
      setApiKeyUser(readNativeApiKeySession());
      setTestUser(readPlaywrightTestSession());
      if (forceInvalidate || isSsoLoggedOut()) {
        setStewardSessionInvalidated(true);
      } else if (allowRevalidate && nextStorageUser) {
        setStewardSessionInvalidated(false);
      } else if (invalidateWhenMissing) {
        setStewardSessionInvalidated(true);
      }
    };
    const storageHandler = (event: StorageEvent) => {
      // `key === null` is localStorage.clear(). The undefined case preserves
      // compatibility with browser/test shims that publish a plain Event.
      const tokenAuthorityChanged =
        event.key === STEWARD_TOKEN_KEY ||
        event.key === null ||
        typeof event.key === "undefined";
      const logoutAdvanced =
        event.key === SSO_LOGOUT_GENERATION_STORAGE_KEY ||
        (event.key === SSO_LOGGED_OUT_STORAGE_KEY && event.newValue === "1");
      reread({
        invalidateWhenMissing: tokenAuthorityChanged,
        forceInvalidate: logoutAdvanced,
        allowRevalidate: tokenAuthorityChanged && event.newValue !== null,
      });
    };
    const tokenSyncHandler = () =>
      reread({ invalidateWhenMissing: true, allowRevalidate: true });
    const sessionChangeHandler = (event: Event) => {
      const detail = (event as CustomEvent<StewardSessionChangeDetail>).detail;
      reread({
        invalidateWhenMissing: detail?.state === "cleared",
        forceInvalidate: detail?.state === "cleared",
        allowRevalidate: detail?.state === "present",
      });
    };
    const ssoLogoutStateHandler = (event: Event) => {
      const detail = (event as CustomEvent<SsoLogoutStateChangeDetail>).detail;
      reread({
        forceInvalidate: detail?.state === "logged_out",
        allowRevalidate: detail?.state === "cleared",
      });
    };
    reread({ allowRevalidate: true });
    window.addEventListener("storage", storageHandler);
    window.addEventListener("steward-token-sync", tokenSyncHandler);
    window.addEventListener(STEWARD_SESSION_CHANGE_EVENT, sessionChangeHandler);
    window.addEventListener(SSO_LOGOUT_STATE_EVENT, ssoLogoutStateHandler);
    const timer = setTimeout(() => reread({ allowRevalidate: true }), 250);
    return () => {
      window.removeEventListener("storage", storageHandler);
      window.removeEventListener("steward-token-sync", tokenSyncHandler);
      window.removeEventListener(
        STEWARD_SESSION_CHANGE_EVENT,
        sessionChangeHandler,
      );
      window.removeEventListener(SSO_LOGOUT_STATE_EVENT, ssoLogoutStateHandler);
      clearTimeout(timer);
    };
  }, []);

  const providerUser: StewardSessionUser =
    !stewardSessionInvalidated &&
    providerAuth.user &&
    (!storageUser || providerAuth.user.id === storageUser.id)
      ? {
          id: providerAuth.user.id,
          email: providerAuth.user.email ?? "",
          walletAddress: providerAuth.user.walletAddress,
        }
      : null;

  const activeStorageUser = stewardSessionInvalidated ? null : storageUser;
  const user = providerUser ?? activeStorageUser ?? apiKeyUser ?? testUser;
  const authenticated =
    (!stewardSessionInvalidated &&
      (providerAuth.isAuthenticated || storageUser !== null)) ||
    apiKeyUser !== null ||
    testUser !== null;
  const ready = !providerAuth.isLoading || isPlaywrightTestAuthEnabled();

  return { ready, authenticated, user };
}
