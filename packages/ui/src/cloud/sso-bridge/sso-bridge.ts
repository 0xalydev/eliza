/**
 * Client side of the eliza.app ↔ cloud.eliza.app SSO bridge — shared login
 * across the public/auth origin and the managed Eliza app origin without a
 * shared cookie.
 *
 * SECURITY MODEL (server rationale in
 * `packages/cloud/api/auth/sso-bridge/route.ts`): the Steward session JWT the
 * SPA runs on is per-origin localStorage. Mirroring it into a JS-readable
 * parent-domain cookie is rejected because user-controlled content is served
 * on sibling subdomains such as hosted apps, dedicated-agent web UIs, and
 * uploaded blobs. A parent-domain non-HttpOnly cookie would be readable by JS
 * on every one of them; cookies cannot scope to "apex + one subdomain only".
 * Instead the managed app redirects through the eliza.app auth origin, which
 * mints a 60-second single-use opaque code that the app origin exchanges for
 * the token over POST. The token never appears in a URL.
 *
 * The handshake is bound to the initiating app origin twice over:
 *  - a `state` nonce: created here, persisted in the app origin's
 *    sessionStorage (readable by no other origin), echoed through both
 *    redirect legs, and verified-and-consumed before any exchange call. A
 *    mismatch aborts to the app's own login — an attacker who mints a code
 *    for their own session cannot drive a victim's browser through the
 *    exchange leg (login CSRF / session fixation) — and BURNS the code
 *    server-side so the abandoned code cannot be redeemed later.
 *  - a PKCE-style `verifier`: also created here and held ONLY in this
 *    origin's sessionStorage; its sha256 (`challenge`) rides the mint leg and
 *    is stored with the code, and the raw verifier travels once, in the
 *    exchange POST body. Both handshake URLs carry only the code/challenge,
 *    so HTTP logs and browser history on either origin never contain enough
 *    to redeem a code.
 *
 * Hostname gating is a strict hardcoded allowlist: only the real app hosts
 * initiate/exchange, only their paired eliza.app auth hosts mint, and every other
 * hostname — localhost/dev (even with `VITE_FORCE_APP_MODE`), previews,
 * per-agent subdomains — resolves to role "none" and the bridge is inert.
 *
 * Logout stays logged out (both hosts): explicit sign-out on EITHER host
 * (`signOutFromSsoBridgedHost` — the unified app's account action uses it)
 * records a persistent local marker that suppresses auto-bridging until the
 * next real sign-in, and calls the server logout route, which stamps a
 * server-side Postgres logout marker for the access-token authority presented
 * by this flow. The mint/exchange endpoints refuse to bridge authority covered
 * by that marker, the cookie-planting session-sync endpoint reports
 * `session_ended` for covered pre-logout access tokens, and the explicit
 * app-origin marker prevents an automatic bounce. Revocation of a Steward
 * refresh family remains a Steward server contract rather than a guarantee of
 * this bridge client.
 */

import { ELIZA_DOMAIN_CONTRACTS } from "@elizaos/shared/elizacloud";
import {
  clearStoredStewardTokenIfCurrent,
  readStoredStewardToken,
  STEWARD_LOGOUT_PROOF_VERSION,
  type StewardLogoutBarrierState,
  type StewardLogoutResponse,
  type StewardSessionResponse,
  writeStoredStewardTokenIfCurrent,
} from "@elizaos/shared/steward-session-client";
import { shellLocalStorage } from "../../surface-realm-channel";
import { reportRendererDiagnostic } from "../../utils/renderer-diagnostics";
import { appModeNavigation } from "../app-mode/app-mode";
import { decodeJwtPayload } from "../lib/jwt";
import {
  invalidateStewardServerCookieSyncMarker,
  markStewardServerCookieSynced,
} from "../lib/steward-session-cookie-sync-marker";
import {
  clearServerStewardSessionCookies,
  clearStaleStewardSession,
  configuredSessionEndpoint,
} from "../shell/StewardProviderShared";
import { ELIZA_CLOUD_DIRECT_API_BY_HOST } from "../shell/steward-url";

/** Client route (registered on every host; role-switched by hostname). */
export const SSO_BRIDGE_PATH = "/auth/bridge";

/**
 * The two deployed origin pairs. Staging must bridge to staging — a staging
 * app host minting against the production auth origin would splice sessions
 * across environments. Origins are hardcoded canonical values, never derived
 * from request input.
 */
interface SsoBridgePair {
  mintHosts: readonly string[];
  mintOrigin: string;
  appHost: string;
  appOrigin: string;
}

const SSO_BRIDGE_PAIRS: readonly SsoBridgePair[] = [
  {
    mintHosts: ["eliza.app", "www.eliza.app"],
    mintOrigin: ELIZA_DOMAIN_CONTRACTS.production.marketingOrigin,
    appHost: "cloud.eliza.app",
    appOrigin: ELIZA_DOMAIN_CONTRACTS.production.cloudAppOrigin,
  },
  {
    mintHosts: ["staging.eliza.app"],
    mintOrigin: ELIZA_DOMAIN_CONTRACTS.staging.marketingOrigin,
    appHost: "cloud-staging.eliza.app",
    appOrigin: ELIZA_DOMAIN_CONTRACTS.staging.cloudAppOrigin,
  },
];

export type SsoBridgeRole = "mint" | "exchange" | "none";

function pairForHostname(hostname: string): SsoBridgePair | null {
  const host = hostname.toLowerCase();
  for (const pair of SSO_BRIDGE_PAIRS) {
    if (pair.appHost === host || pair.mintHosts.includes(host)) return pair;
  }
  return null;
}

/**
 * Which side of the handshake this hostname plays. Exact-match only:
 * `foo.elizacloud.ai`, `elizacloud.ai.evil.com`, `localhost`, previews, and
 * the dev app-mode flag all resolve to "none".
 */
export function ssoBridgeRoleForHostname(hostname: string): SsoBridgeRole {
  const host = hostname.toLowerCase();
  const pair = pairForHostname(host);
  if (!pair) return "none";
  return pair.appHost === host ? "exchange" : "mint";
}

/** Cloud API worker base for a bridge hostname; null off the deployed map. */
function apiBaseForHostname(hostname: string): string | null {
  return ELIZA_CLOUD_DIRECT_API_BY_HOST[hostname.toLowerCase()] ?? null;
}

/** The app origin paired with a MINT hostname; null for non-mint hosts. */
export function pairedAppOrigin(mintHostname: string): string | null {
  const pair = pairForHostname(mintHostname);
  if (!pair || pair.appHost === mintHostname.toLowerCase()) return null;
  return pair.appOrigin;
}

// ---------------------------------------------------------------------------
// returnTo sanitation
// ---------------------------------------------------------------------------

const RETURN_TO_MAX_LENGTH = 2000;

/**
 * returnTo travels through two cross-origin redirects, so it must stay a
 * same-origin path: absolute URLs, protocol-relative "//", "/\" (which
 * browsers normalize to "//"), any backslash, and the bridge path itself
 * (self-redirect loop) are all rejected to "/".
 */
export function sanitizeBridgeReturnTo(
  value: string | null | undefined,
): string {
  if (!value || value.length > RETURN_TO_MAX_LENGTH) return "/";
  if (!value.startsWith("/")) return "/";
  if (value.startsWith("//") || value.includes("\\")) return "/";
  const path = value.split(/[?#]/, 1)[0];
  if (path === SSO_BRIDGE_PATH) return "/";
  return value;
}

/**
 * Local recovery URL for an unexpected bridge failure. Keep the original
 * same-origin destination so retrying authentication does not discard a deep
 * link such as `/chat`, while applying the same open-redirect and loop guards
 * as the cross-origin handshake itself.
 */
export function buildSsoBridgeErrorUrl(
  reason: "auth_failed" | "sync_failed",
  returnTo: string,
): string {
  const params = new URLSearchParams({
    reason,
    returnTo: sanitizeBridgeReturnTo(returnTo),
  });
  return `/auth/error?${params.toString()}`;
}

/**
 * Recovery from a mint-host error must restart on the paired app host. A
 * same-origin `/login` on the marketing host cannot restore app-only paths
 * such as `/chat`: its authenticated catch-all intentionally hands users to
 * `/cloud` instead. The hostname is resolved only through the fixed bridge
 * pair allowlist, and the destination remains a sanitized app-local path.
 */
export function pairedAppLoginUrlForMintHost(
  hostname: string,
  returnTo: string,
): string | null {
  const appOrigin = pairedAppOrigin(hostname);
  if (!appOrigin) return null;
  return `${appOrigin}/login?returnTo=${encodeURIComponent(sanitizeBridgeReturnTo(returnTo))}`;
}

// ---------------------------------------------------------------------------
// State nonce + PKCE verifier (defect fix: handshake binding + code theft)
// ---------------------------------------------------------------------------

const SSO_STATE_KEY = "eliza_sso_bridge_state";
const SSO_VERIFIER_KEY = "eliza_sso_bridge_verifier";
const SSO_STATE_RE = /^[0-9a-f]{64}$/;

/** Both legs validate the echoed state's shape before using it in a URL. */
export function isWellFormedSsoState(
  value: string | null | undefined,
): value is string {
  return typeof value === "string" && SSO_STATE_RE.test(value);
}

/** Challenge/verifier share the state's 64-hex shape (32 random bytes). */
export function isWellFormedSsoChallenge(
  value: string | null | undefined,
): value is string {
  return isWellFormedSsoState(value);
}

function randomHex32(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buf = await globalThis.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Create the handshake secrets and persist them in THIS origin's
 * sessionStorage: the `state` nonce (echoed through both redirect URLs) and
 * the PKCE-style `verifier` (never leaves this origin until the exchange POST
 * body). Only the verifier's sha256 — the `challenge` — is returned for the
 * mint URL. Returns null when storage or crypto is unavailable (privacy
 * mode) — the caller must then fall back to the normal login flow instead of
 * bridging, because an unbound handshake is exactly the CSRF and code-theft
 * surface these two values exist to stop.
 */
export async function createSsoBridgeHandshake(): Promise<{
  state: string;
  challenge: string;
} | null> {
  try {
    const state = randomHex32();
    const verifier = randomHex32();
    const challenge = await sha256Hex(verifier);
    sessionStorage.setItem(SSO_STATE_KEY, state);
    sessionStorage.setItem(SSO_VERIFIER_KEY, verifier);
    return { state, challenge };
  } catch {
    // error-policy:J4 no storage/crypto → the bridge is disabled for this
    // visit (fail-closed to the ordinary login), never an unbound handshake.
    return null;
  }
}

/** Read AND delete the stored nonce — verification is strictly single-shot. */
export function consumeSsoBridgeState(): string | null {
  try {
    const state = sessionStorage.getItem(SSO_STATE_KEY);
    sessionStorage.removeItem(SSO_STATE_KEY);
    return state;
  } catch {
    // error-policy:J4 unreadable storage verifies as "no stored state" → the
    // exchange leg aborts to login (fail-closed).
    return null;
  }
}

/** Read AND delete the stored verifier — the exchange POST is single-shot. */
export function consumeSsoBridgeVerifier(): string | null {
  try {
    const verifier = sessionStorage.getItem(SSO_VERIFIER_KEY);
    sessionStorage.removeItem(SSO_VERIFIER_KEY);
    return verifier;
  } catch {
    // error-policy:J4 unreadable storage verifies as "no verifier" → the
    // exchange leg burns the code and aborts to login (fail-closed).
    return null;
  }
}

function discardSsoBridgeHandshakeIfCurrent(state: string): void {
  try {
    if (sessionStorage.getItem(SSO_STATE_KEY) !== state) return;
    sessionStorage.removeItem(SSO_STATE_KEY);
    sessionStorage.removeItem(SSO_VERIFIER_KEY);
  } catch {
    // error-policy:J6 abandoned secrets are tab-scoped and overwritten by the
    // next handshake; failure to clean them cannot authorize an exchange.
  }
}

// ---------------------------------------------------------------------------
// Redirect-loop guard
// ---------------------------------------------------------------------------

const SSO_ATTEMPT_KEY = "eliza_sso_bridge_attempted_at";
const SSO_ATTEMPT_WINDOW_MS = 5 * 60 * 1000;

/**
 * A failed handshake (no auth-origin session, expired code, cache down) must
 * fall back to the app origin's own /login instead of bouncing to the
 * auth origin again — otherwise an unauthenticated visitor ping-pongs between
 * the origins forever. The marker is set right before leaving for the
 * auth origin, cleared only by a successful exchange, and ages out on its own so
 * a later visit retries.
 */
export function shouldAttemptSsoBridge(now: number = Date.now()): boolean {
  try {
    const raw = sessionStorage.getItem(SSO_ATTEMPT_KEY);
    if (!raw) return true;
    const at = Number(raw);
    if (Number.isNaN(at)) return true;
    return now - at > SSO_ATTEMPT_WINDOW_MS;
  } catch {
    // error-policy:J4 no sessionStorage → no way to break a redirect loop, so
    // never auto-bounce; the user still has the normal login flow.
    return false;
  }
}

export function markSsoBridgeAttempt(now: number = Date.now()): void {
  try {
    sessionStorage.setItem(SSO_ATTEMPT_KEY, String(now));
  } catch {
    // error-policy:J6 best-effort marker; shouldAttemptSsoBridge already
    // fails closed when storage is unavailable.
  }
}

export function clearSsoBridgeAttempt(): void {
  try {
    sessionStorage.removeItem(SSO_ATTEMPT_KEY);
  } catch {
    // error-policy:J6 best-effort cleanup of an advisory marker.
  }
}

// ---------------------------------------------------------------------------
// Logged-out marker
// ---------------------------------------------------------------------------

const SSO_LOGGED_OUT_KEY = "eliza_sso_logged_out";
const SSO_LOGOUT_GENERATION_KEY = "eliza_sso_logout_generation";
const SSO_FINALIZATION_INTENT_KEY = "eliza_sso_finalization_intent";
let ssoLogoutEpoch = 0;
let activeSsoCookieSyncAbortController: AbortController | null = null;

type StoredGenerationSnapshot =
  | { readable: true; value: string | null }
  | { readable: false };

function readStoredGeneration(key: string): StoredGenerationSnapshot {
  try {
    return { readable: true, value: localStorage.getItem(key) };
  } catch {
    // error-policy:J4 persistent coordination storage is an authority input;
    // an unreadable value must never compare equal and authorize a commit.
    return { readable: false };
  }
}

function storedGenerationMatches(
  key: string,
  snapshot: StoredGenerationSnapshot,
): boolean {
  if (!snapshot.readable) return false;
  try {
    return localStorage.getItem(key) === snapshot.value;
  } catch {
    // error-policy:J4 a finalization that cannot re-read its cross-tab epoch
    // loses authority instead of publishing over a possible logout/login.
    return false;
  }
}

function publishFinalizationIntent(nonce: string): boolean {
  try {
    shellLocalStorage.setItem(SSO_FINALIZATION_INTENT_KEY, nonce);
    return localStorage.getItem(SSO_FINALIZATION_INTENT_KEY) === nonce;
  } catch {
    // error-policy:J4 latest-intent coordination must round-trip through the
    // shared origin store; otherwise this operation cannot safely finalize.
    return false;
  }
}

function createFinalizationIntent(): string | null {
  try {
    const nonce = randomHex32();
    return publishFinalizationIntent(nonce) ? nonce : null;
  } catch {
    // error-policy:J4 a non-unique intent cannot participate safely in the
    // cross-tab last-started-wins protocol.
    return null;
  }
}

function finalizationIntentMatches(nonce: string | null): boolean {
  if (!nonce) return false;
  try {
    return localStorage.getItem(SSO_FINALIZATION_INTENT_KEY) === nonce;
  } catch {
    // error-policy:J4 unreadable shared intent means authority is unknown.
    return false;
  }
}

function requireFinalizationIntent(
  nonce: string,
  operation: "account switch" | "sign-out",
): void {
  const current = readStoredGeneration(SSO_FINALIZATION_INTENT_KEY);
  if (!current.readable) {
    throw new Error(`SSO ${operation} coordination became unavailable.`);
  }
  if (current.value !== nonce) {
    throw new Error(
      `SSO ${operation} was superseded by a newer session intent.`,
    );
  }
}

function reassertSsoLoggedOutMarker(
  nonce: string,
  operation: "account switch" | "sign-out",
): void {
  requireFinalizationIntent(nonce, operation);
  try {
    shellLocalStorage.setItem(SSO_LOGGED_OUT_KEY, "1");
  } catch (error) {
    throw new Error(`SSO ${operation} could not persist its logout marker.`, {
      cause: error,
    });
  }
}

/**
 * Persistent (localStorage) "the user explicitly signed out here" marker. It
 * suppresses AUTO-bridging only — an explicit login is always available — and
 * is cleared by the next successful sign-in on this origin (any mechanism),
 * so logout cannot be silently undone by the other origin's surviving session.
 */
export function isSsoLoggedOut(): boolean {
  try {
    return localStorage.getItem(SSO_LOGGED_OUT_KEY) === "1";
  } catch {
    // error-policy:J4 unreadable storage reads as "logged out" so the bridge
    // never auto-runs somewhere it cannot honor a logout marker.
    return true;
  }
}

export function markSsoLoggedOut(): string | null {
  ssoLogoutEpoch += 1;
  activeSsoCookieSyncAbortController?.abort();
  let logoutIntent: string | null = null;
  try {
    const nonce = randomHex32();
    // Generation lands before the legacy marker so an exchange in another
    // realm observes revocation at its commit guard at the earliest possible
    // point. The same nonce is also this logout's latest-wins intent.
    shellLocalStorage.setItem(SSO_LOGOUT_GENERATION_KEY, nonce);
    logoutIntent = publishFinalizationIntent(nonce) ? nonce : null;
  } catch {
    // error-policy:J6 the legacy marker and in-realm epoch still make this
    // realm fail closed; cross-tab exchanges also require readable intent
    // coordination before they may commit.
  }
  try {
    // Reserved shell key: raw localStorage writes throw SurfaceRealmDeniedError
    // while a view scope is foreground (surface-realm-broker guard, #13452).
    shellLocalStorage.setItem(SSO_LOGGED_OUT_KEY, "1");
  } catch {
    // error-policy:J6 best-effort marker; isSsoLoggedOut fails closed when
    // storage is unavailable.
  }
  return logoutIntent;
}

export function clearSsoLoggedOut(): void {
  try {
    shellLocalStorage.removeItem(SSO_LOGGED_OUT_KEY);
  } catch {
    // error-policy:J6 best-effort cleanup; an over-persistent marker only
    // suppresses auto-bridge, never login itself.
  }
}

// ---------------------------------------------------------------------------
// Handshake URLs
// ---------------------------------------------------------------------------

/**
 * Dashboard-origin URL the app origin leaves for when it has no session.
 * Carries the state nonce and the CHALLENGE (sha256 of the verifier) — never
 * the verifier itself, so this URL grants nothing to whoever logs it.
 */
export function buildBridgeMintUrl(
  appHostname: string,
  state: string,
  challenge: string,
  returnTo: string,
): string | null {
  const pair = pairForHostname(appHostname);
  if (!pair || pair.appHost !== appHostname.toLowerCase()) return null;
  if (!isWellFormedSsoState(state)) return null;
  if (!isWellFormedSsoChallenge(challenge)) return null;
  const safe = sanitizeBridgeReturnTo(returnTo);
  return `${pair.mintOrigin}${SSO_BRIDGE_PATH}?state=${encodeURIComponent(state)}&challenge=${encodeURIComponent(challenge)}&returnTo=${encodeURIComponent(safe)}`;
}

/** Managed-app URL the auth origin redirects back to after minting a code. */
export function buildBridgeExchangeUrl(
  mintHostname: string,
  code: string,
  state: string,
  returnTo: string,
): string | null {
  const pair = pairForHostname(mintHostname);
  if (!pair || pair.appHost === mintHostname.toLowerCase()) return null;
  if (!isWellFormedSsoState(state)) return null;
  const safe = sanitizeBridgeReturnTo(returnTo);
  return `${pair.appOrigin}${SSO_BRIDGE_PATH}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}&returnTo=${encodeURIComponent(safe)}`;
}

// ---------------------------------------------------------------------------
// Entry decision + initiation (app host)
// ---------------------------------------------------------------------------

/**
 * Whether an unauthenticated app-mode visit should leave for the auth origin
 * bridge right now. True only on the real app hosts, when the user has not
 * explicitly signed out here, and while the loop guard is clear.
 *
 * Steward cookies are deliberately host-only, so the app origin cannot use an
 * auth-origin cookie as a preflight hint. The first bridge visit is therefore
 * also the signed-out login handoff: the mint route remembers the app-approved
 * state, sends the user through auth-origin login, then resumes the PKCE mint.
 * A failed attempt remains bounded to one bounce per tab per five minutes.
 */
export function shouldAutoBridgeToSso(
  hostname: string = window.location.hostname,
  now: number = Date.now(),
): boolean {
  if (ssoBridgeRoleForHostname(hostname) !== "exchange") return false;
  if (isSsoLoggedOut()) return false;
  return shouldAttemptSsoBridge(now);
}

/**
 * Leave for the auth-origin mint leg: create + store the state nonce and PKCE
 * verifier, mark the attempt, and replace the location (the gate page is
 * transient — Back must not re-enter it). Resolves false when the bridge
 * cannot start (no nonce storage / unknown host); the caller falls back to
 * the ordinary login.
 */
export async function redirectToSsoBridge(
  returnTo: string,
  hostname: string = window.location.hostname,
): Promise<boolean> {
  const logoutEpochAtStart = ssoLogoutEpoch;
  const logoutGenerationAtStart = readStoredGeneration(
    SSO_LOGOUT_GENERATION_KEY,
  );
  const finalizationIntentAtStart = readStoredGeneration(
    SSO_FINALIZATION_INTENT_KEY,
  );
  if (
    !logoutGenerationAtStart.readable ||
    !finalizationIntentAtStart.readable ||
    isSsoLoggedOut()
  ) {
    return false;
  }
  const initiationStillCurrent = (): boolean =>
    logoutEpochAtStart === ssoLogoutEpoch &&
    storedGenerationMatches(
      SSO_LOGOUT_GENERATION_KEY,
      logoutGenerationAtStart,
    ) &&
    storedGenerationMatches(
      SSO_FINALIZATION_INTENT_KEY,
      finalizationIntentAtStart,
    ) &&
    !isSsoLoggedOut();
  const handshake = await createSsoBridgeHandshake();
  if (!handshake) return false;
  if (!initiationStillCurrent()) {
    discardSsoBridgeHandshakeIfCurrent(handshake.state);
    return false;
  }
  const url = buildBridgeMintUrl(
    hostname,
    handshake.state,
    handshake.challenge,
    returnTo,
  );
  if (!url) return false;
  if (!initiationStillCurrent()) {
    discardSsoBridgeHandshakeIfCurrent(handshake.state);
    return false;
  }
  markSsoBridgeAttempt();
  if (!initiationStillCurrent()) {
    discardSsoBridgeHandshakeIfCurrent(handshake.state);
    return false;
  }
  try {
    appModeNavigation.replace(url);
    return true;
  } catch (error) {
    // error-policy:J4 only the expected browser navigation-policy rejection
    // degrades to local login; every other failure remains exceptional.
    if (!(error instanceof DOMException && error.name === "SecurityError")) {
      throw error;
    }
    reportRendererDiagnostic({
      scope: "steward.sso-bridge.start-navigation",
      error,
      severity: "warning",
    });
    return false;
  }
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

const SSO_CODE_RE = /^esso_[0-9a-f]{64}$/;

/** Both legs validate the code's shape before trusting it in a URL / POST. */
export function isWellFormedSsoCode(
  value: string | null | undefined,
): value is string {
  return typeof value === "string" && SSO_CODE_RE.test(value);
}

export type SsoMintResult =
  | { ok: true; code: string }
  | { ok: false; error: string };

/**
 * Dashboard side: trade the local session for a one-time code bound to the
 * app origin's PKCE challenge. The Bearer token comes from THIS origin's
 * localStorage — deliberately never from the parent-domain cookie, which JS
 * on user-content subdomains can plant (the server enforces the same rule).
 * No refresh token travels: bridge-issued app-origin sessions are deliberately
 * non-renewable, and cookie sync clears any stale refresh authority there.
 */
export async function mintSsoCode(
  hostname: string,
  challenge: string,
  fetchFn: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<SsoMintResult> {
  const base = apiBaseForHostname(hostname);
  if (!base) return { ok: false, error: "Host cannot mint SSO codes" };
  if (!isWellFormedSsoChallenge(challenge)) {
    return { ok: false, error: "Malformed code challenge" };
  }
  const token = readStoredStewardToken();
  if (!token) return { ok: false, error: "No local session" };
  const requestAbortController = new AbortController();
  const stopForwardingAbort = forwardAbort(signal, requestAbortController);
  let res: Response;
  try {
    res = await fetchWithDeadline(
      fetchFn,
      `${base}/api/auth/sso-bridge/mint`,
      {
        method: "POST",
        credentials: "include",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ codeChallenge: challenge }),
      },
      requestAbortController,
      SSO_BRIDGE_REQUEST_TIMEOUT_MS,
    );
  } catch (err) {
    // error-policy:J1 transport failure becomes the typed failure result the
    // bridge route turns into its fall-back-to-login redirect.
    stopForwardingAbort();
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
  if (!res.ok) {
    stopForwardingAbort();
    return { ok: false, error: `Mint failed (HTTP ${res.status})` };
  }
  let body: unknown;
  try {
    body = await readJsonWithDeadline(
      res,
      requestAbortController,
      SSO_BRIDGE_REQUEST_TIMEOUT_MS,
    );
  } catch {
    // error-policy:J3 a malformed upstream response is explicit invalid input,
    // never a fabricated empty success envelope.
    return { ok: false, error: "Mint returned no usable code" };
  } finally {
    stopForwardingAbort();
  }
  const code =
    body && typeof body === "object" && "code" in body
      ? typeof body.code === "string"
        ? body.code
        : null
      : null;
  if (!code || !isWellFormedSsoCode(code)) {
    return { ok: false, error: "Mint returned no usable code" };
  }
  return { ok: true, code };
}

export type SsoExchangeResult = { ok: true } | { ok: false; error: string };

/** Fetch call signature used by bridge wrappers without runtime statics. */
export type SsoBridgeFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface SsoBridgeLockManager {
  request<T>(
    name: string,
    options: { mode: "exclusive"; signal: AbortSignal },
    callback: () => T | PromiseLike<T>,
  ): Promise<T>;
}

export interface SsoBridgeCoordinationOptions {
  /** Test/native seam; `null` explicitly models an unavailable Web Locks API. */
  lockManager?: SsoBridgeLockManager | null;
  lockTimeoutMs?: number;
  /** Component lifetime cancellation for exchange, lock wait, and cookie sync. */
  signal?: AbortSignal;
}

const SSO_FINALIZATION_LOCK_NAME = "eliza-sso-bridge-finalization";
const SSO_FINALIZATION_LOCK_TIMEOUT_MS = 15_000;
const SSO_BRIDGE_REQUEST_TIMEOUT_MS = 10_000;
const SSO_COOKIE_SYNC_TIMEOUT_MS = 10_000;
const SSO_LOGOUT_TIMEOUT_MS = 10_000;

function resolveSsoBridgeLockManager(
  configured: SsoBridgeLockManager | null | undefined,
): SsoBridgeLockManager {
  if (configured !== undefined) {
    if (configured) return configured;
    throw new Error("Web Locks are unavailable for SSO coordination");
  }
  try {
    const browserLocks = navigator.locks;
    if (!browserLocks) {
      throw new Error("Web Locks are unavailable for SSO coordination");
    }
    return {
      request: (name, options, callback) =>
        browserLocks.request(name, options, callback),
    };
  } catch (error) {
    if (error instanceof Error) throw error;
    throw new Error("Web Locks are unavailable for SSO coordination", {
      cause: error,
    });
  }
}

/**
 * Serialize bearer + cookie authority across every tab on this origin. Lock
 * acquisition is bounded; an operation that cannot establish exclusive
 * custody fails before it can mutate either half of the session.
 */
async function withSsoFinalizationLock<T>(
  lockManager: SsoBridgeLockManager,
  operation: () => Promise<T>,
  timeoutMs: number = SSO_FINALIZATION_LOCK_TIMEOUT_MS,
  signal?: AbortSignal,
): Promise<T> {
  const abortController = new AbortController();
  const stopForwardingAbort = forwardAbort(signal, abortController);
  let acquired = false;
  const timeout = window.setTimeout(() => {
    if (!acquired) abortController.abort();
  }, timeoutMs);
  try {
    return await lockManager.request(
      SSO_FINALIZATION_LOCK_NAME,
      { mode: "exclusive", signal: abortController.signal },
      async () => {
        acquired = true;
        window.clearTimeout(timeout);
        return operation();
      },
    );
  } catch (error) {
    if (signal?.aborted && !acquired) {
      throw new DOMException(
        "The SSO session operation was aborted",
        "AbortError",
      );
    }
    if (abortController.signal.aborted && !acquired) {
      throw new Error("Timed out waiting for SSO session coordination", {
        cause: error,
      });
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    stopForwardingAbort();
  }
}

function forwardAbort(
  source: AbortSignal | undefined,
  target: AbortController,
): () => void {
  if (!source) return () => {};
  const abort = (): void => target.abort();
  source.addEventListener("abort", abort, { once: true });
  if (source.aborted) abort();
  return () => source.removeEventListener("abort", abort);
}

function runWithAbortDeadline<T>(
  operation: () => Promise<T>,
  abortController: AbortController,
  timeoutMs: number,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let timeout = 0;
    const resolveOnce = (value: T): void => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      abortController.signal.removeEventListener("abort", onAbort);
      resolve(value);
    };
    const rejectOnce = (error: unknown): void => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      abortController.signal.removeEventListener("abort", onAbort);
      reject(error);
    };
    const onAbort = (): void => {
      rejectOnce(
        new DOMException("The SSO session request was aborted", "AbortError"),
      );
    };
    timeout = window.setTimeout(() => abortController.abort(), timeoutMs);
    abortController.signal.addEventListener("abort", onAbort, { once: true });
    if (abortController.signal.aborted) {
      onAbort();
      return;
    }
    try {
      void operation().then(resolveOnce, rejectOnce);
    } catch (error) {
      rejectOnce(error);
    }
  });
}

/**
 * A fetch deadline that releases the Web Lock even when an injected adapter
 * ignores AbortSignal. The late request remains observed by the attached
 * handlers, while its result can no longer extend this operation's custody.
 */
function fetchWithDeadline(
  fetchFn: SsoBridgeFetch,
  input: RequestInfo | URL,
  init: RequestInit,
  abortController: AbortController,
  timeoutMs: number,
): Promise<Response> {
  return runWithAbortDeadline(
    () => fetchFn(input, { ...init, signal: abortController.signal }),
    abortController,
    timeoutMs,
  );
}

/** Response bodies are network work too and remain bounded while locked. */
function readJsonWithDeadline(
  response: Response,
  abortController: AbortController,
  timeoutMs: number,
): Promise<unknown> {
  return runWithAbortDeadline(
    () => response.json() as Promise<unknown>,
    abortController,
    timeoutMs,
  );
}

function tokenLooksHydratable(token: string): boolean {
  const claims = decodeJwtPayload(token);
  const id = claims?.userId ?? claims?.sub;
  if (typeof id !== "string" || id.trim().length === 0) return false;
  if (typeof claims?.exp !== "number") return false;
  return claims.exp * 1000 > Date.now();
}

type StewardSessionProof = Pick<
  StewardSessionResponse,
  "ok" | "stewardUserId" | "userId"
>;

function hasStewardSessionProof(value: unknown): value is StewardSessionProof {
  if (!value || typeof value !== "object") return false;
  const candidate = value as {
    ok?: unknown;
    stewardUserId?: unknown;
    userId?: unknown;
  };
  return (
    candidate.ok === true &&
    typeof candidate.userId === "string" &&
    candidate.userId.trim().length > 0 &&
    typeof candidate.stewardUserId === "string" &&
    candidate.stewardUserId.trim().length > 0
  );
}

function hasSsoLogoutBarrierProof(
  value: unknown,
): value is StewardLogoutResponse {
  if (!value || typeof value !== "object") return false;
  const candidate = value as {
    success?: unknown;
    logoutProofVersion?: unknown;
    barrierState?: unknown;
    barrierConfirmed?: unknown;
    message?: unknown;
  };
  return (
    candidate.success === true &&
    candidate.logoutProofVersion === STEWARD_LOGOUT_PROOF_VERSION &&
    ((candidate.barrierState === "confirmed" &&
      candidate.barrierConfirmed === true) ||
      (candidate.barrierState === "already_absent" &&
        candidate.barrierConfirmed === false)) &&
    typeof candidate.message === "string" &&
    candidate.message.trim().length > 0
  );
}

async function readSsoLogoutBarrierProof(
  response: Response,
  abortController: AbortController,
): Promise<StewardLogoutBarrierState | null> {
  try {
    const body = await readJsonWithDeadline(
      response,
      abortController,
      SSO_LOGOUT_TIMEOUT_MS,
    );
    return hasSsoLogoutBarrierProof(body) ? body.barrierState : null;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw error;
    return null;
  }
}

async function scrubPersistedExchangeTokenIfOwned(
  token: string,
): Promise<void> {
  invalidateStewardServerCookieSyncMarker();
  const cleared = await clearStoredStewardTokenIfCurrent(token);
  if (!cleared) return;
  // Do not forward the component-lifetime signal here: once this token was
  // durably published, its cookie POST may already have landed. Rollback must
  // survive route unmount; its own AbortController deadline still bounds lock
  // custody when the network is unavailable.
  await clearServerStewardSessionCookies({
    timeoutMs: SSO_COOKIE_SYNC_TIMEOUT_MS,
  });
  try {
    window.dispatchEvent(new CustomEvent("steward-token-sync"));
  } catch (error) {
    // error-policy:J7 canonical authority is already cleared; diagnostics are
    // sufficient if an optional renderer notification cannot be delivered.
    reportRendererDiagnostic({
      scope: "steward.sso-bridge.session-notification",
      error,
      severity: "warning",
    });
  }
}

/**
 * App side: consume the code (presenting the PKCE verifier that never left
 * this origin's sessionStorage) and hydrate this origin's localStorage
 * mirror. After this the app origin is indistinguishable from one the user
 * logged into directly: same storage key, same `steward-token-sync` event,
 * an explicit cookie-sync POST, and the existing AuthTokenSync loop available
 * for retries + refresh.
 *
 * The guard immediately before durable persistence is the commit point.
 * Supersession before it returns a typed failure without publishing; once the
 * write starts, it finishes, and any later queued generation wins in order.
 * Cookie sync is abortable and finalization is serialized, so generation B
 * cannot publish or POST until A has stopped and B remains the last authority
 * committed by this browser realm.
 */
export async function performSsoExchange(
  code: string,
  verifier: string,
  hostname: string,
  fetchFn: SsoBridgeFetch = fetch,
  isCurrent: () => boolean = () => true,
  coordination: SsoBridgeCoordinationOptions = {},
): Promise<SsoExchangeResult> {
  const base = apiBaseForHostname(hostname);
  if (!base) return { ok: false, error: "Host cannot exchange SSO codes" };
  if (!isWellFormedSsoChallenge(verifier)) {
    return { ok: false, error: "Malformed code verifier" };
  }
  const lockManager = resolveSsoBridgeLockManager(coordination.lockManager);
  const logoutEpochAtStart = ssoLogoutEpoch;
  const logoutGenerationAtStart = readStoredGeneration(
    SSO_LOGOUT_GENERATION_KEY,
  );
  const finalizationIntent = createFinalizationIntent();
  if (!logoutGenerationAtStart.readable || !finalizationIntent) {
    return { ok: false, error: "SSO session coordination unavailable" };
  }
  const stillOwnsAuthority = (): boolean =>
    logoutEpochAtStart === ssoLogoutEpoch &&
    storedGenerationMatches(
      SSO_LOGOUT_GENERATION_KEY,
      logoutGenerationAtStart,
    ) &&
    finalizationIntentMatches(finalizationIntent) &&
    isCurrent();
  const exchangeAbortController = new AbortController();
  const stopForwardingExchangeAbort = forwardAbort(
    coordination.signal,
    exchangeAbortController,
  );
  let res: Response;
  try {
    res = await fetchWithDeadline(
      fetchFn,
      `${base}/api/auth/sso-bridge/exchange`,
      {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, codeVerifier: verifier }),
      },
      exchangeAbortController,
      SSO_BRIDGE_REQUEST_TIMEOUT_MS,
    );
  } catch (err) {
    // error-policy:J1 transport failure becomes the typed failure result the
    // bridge route turns into its fall-back-to-login redirect.
    stopForwardingExchangeAbort();
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
  if (!res.ok) {
    stopForwardingExchangeAbort();
    return { ok: false, error: `Exchange failed (HTTP ${res.status})` };
  }
  let body: unknown;
  try {
    body = await readJsonWithDeadline(
      res,
      exchangeAbortController,
      SSO_BRIDGE_REQUEST_TIMEOUT_MS,
    );
  } catch {
    // error-policy:J3 a malformed upstream response is explicit invalid input,
    // never a fabricated empty success envelope.
    return { ok: false, error: "Exchange returned no usable session" };
  } finally {
    stopForwardingExchangeAbort();
  }
  const token =
    body && typeof body === "object" && "token" in body
      ? typeof body.token === "string"
        ? body.token
        : null
      : null;
  if (!token || !tokenLooksHydratable(token)) {
    return { ok: false, error: "Exchange returned no usable session" };
  }
  if (!stillOwnsAuthority()) {
    return { ok: false, error: "SSO exchange superseded" };
  }

  // Persistence/finalization errors are deliberately outside the transport
  // catch above. They reach the route boundary as unexpected failures instead
  // of being disguised as an ordinary expired/replayed-code login recovery.
  return await withSsoFinalizationLock(
    lockManager,
    async () => {
      const persisted = await writeStoredStewardTokenIfCurrent(
        token,
        // This callback is evaluated inside the canonical token mutation
        // queue, immediately before the durable write: both authority and JWT
        // lifetime are therefore revalidated at the actual commit point.
        () => stillOwnsAuthority() && tokenLooksHydratable(token),
      );
      if (!persisted) {
        return tokenLooksHydratable(token)
          ? { ok: false, error: "SSO exchange superseded" }
          : { ok: false, error: "SSO exchange session expired" };
      }
      if (!stillOwnsAuthority() || readStoredStewardToken() !== token) {
        await scrubPersistedExchangeTokenIfOwned(token);
        return { ok: false, error: "SSO exchange superseded" };
      }
      if (!tokenLooksHydratable(token)) {
        await scrubPersistedExchangeTokenIfOwned(token);
        return { ok: false, error: "SSO exchange session expired" };
      }

      const sessionEndpoint = configuredSessionEndpoint();
      const cookieSyncAbortController = new AbortController();
      const stopForwardingCookieSyncAbort = forwardAbort(
        coordination.signal,
        cookieSyncAbortController,
      );
      activeSsoCookieSyncAbortController = cookieSyncAbortController;
      let cookieSyncProven = false;
      let cookieSyncSessionEnded = false;
      try {
        const cookieSyncResponse = await fetchWithDeadline(
          fetchFn,
          sessionEndpoint,
          {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token }),
          },
          cookieSyncAbortController,
          SSO_COOKIE_SYNC_TIMEOUT_MS,
        );
        if (cookieSyncResponse.status === 401) {
          const errorBody = (await readJsonWithDeadline(
            cookieSyncResponse,
            cookieSyncAbortController,
            SSO_COOKIE_SYNC_TIMEOUT_MS,
          ).catch(() => {
            // error-policy:J3 a malformed error body cannot prove the typed
            // server revocation signal.
            return null;
          })) as { code?: unknown } | null;
          cookieSyncSessionEnded = errorBody?.code === "session_ended";
        } else if (cookieSyncResponse.ok) {
          const responseBody = await readJsonWithDeadline(
            cookieSyncResponse,
            cookieSyncAbortController,
            SSO_COOKIE_SYNC_TIMEOUT_MS,
          ).catch(() => {
            // error-policy:J3 a malformed success body cannot prove that the
            // server accepted cookie authority for this exact bearer.
            return null;
          });
          cookieSyncProven = hasStewardSessionProof(responseBody);
          if (!cookieSyncProven) {
            reportRendererDiagnostic({
              scope: "steward.sso-bridge.cookie-sync-response",
              error: new Error(
                "Cookie sync returned a malformed successful response",
              ),
              severity: "warning",
              context: { status: cookieSyncResponse.status },
            });
          }
        } else {
          reportRendererDiagnostic({
            scope: "steward.sso-bridge.cookie-sync-response",
            error: new Error("Cookie sync rejected the bridged session"),
            severity: "warning",
            context: { status: cookieSyncResponse.status },
          });
        }
      } catch (error) {
        // error-policy:J6 best-effort cookie sync; the committed local session
        // remains authoritative and AuthTokenSync retries on its own cadence.
        // Report the failed teardown/sync attempt instead of swallowing it.
        reportRendererDiagnostic({
          scope: "steward.sso-bridge.cookie-sync",
          error,
          severity: "warning",
        });
      } finally {
        stopForwardingCookieSyncAbort();
        if (activeSsoCookieSyncAbortController === cookieSyncAbortController) {
          activeSsoCookieSyncAbortController = null;
        }
      }

      const stillOwnsFinalization =
        stillOwnsAuthority() && readStoredStewardToken() === token;
      if (!stillOwnsFinalization) {
        await scrubPersistedExchangeTokenIfOwned(token);
        return { ok: false, error: "SSO exchange superseded" };
      }
      if (cookieSyncSessionEnded) {
        // The paired origin logged this account out after the bridge token was
        // issued. This distinct server code is a real revocation, not a generic
        // cookie-sync outage: keep auto-bridging suppressed and scrub every
        // local bearer before the exchange route can publish success.
        reportRendererDiagnostic({
          scope: "steward.sso-bridge.session-ended",
          error: new Error("Session was ended by an explicit logout"),
          severity: "warning",
        });
        markSsoLoggedOut();
        await clearStaleStewardSession({
          awaitCookieClear: true,
          signal: coordination.signal,
          timeoutMs: SSO_LOGOUT_TIMEOUT_MS,
        });
        return { ok: false, error: "Session was signed out" };
      }
      if (!cookieSyncProven) {
        // The server-side cookie boundary is part of the login commit, not an
        // optional mirror. In particular it is the post-exchange recheck that
        // can observe a paired-origin logout landing after the code exchange.
        // Never publish a local bearer over an unavailable, rejected, or
        // malformed proof; compensate any Set-Cookie that may already have
        // landed before the response/body failed validation.
        await scrubPersistedExchangeTokenIfOwned(token);
        return {
          ok: false,
          error: "Could not establish the Eliza Cloud browser session",
        };
      }
      // No awaited work follows this lifetime check. A token that expired
      // after durable persistence is removed before the route can publish
      // success or a cookie-sync proof.
      if (!tokenLooksHydratable(token)) {
        await scrubPersistedExchangeTokenIfOwned(token);
        return { ok: false, error: "SSO exchange session expired" };
      }
      markStewardServerCookieSynced(token, sessionEndpoint);
      clearSsoBridgeAttempt();
      clearSsoLoggedOut();
      try {
        window.dispatchEvent(new CustomEvent("steward-token-sync"));
      } catch (error) {
        // error-policy:J7 the durable token is already authoritative; report a
        // failed optional renderer notification without changing the result.
        reportRendererDiagnostic({
          scope: "steward.sso-bridge.session-notification",
          error,
          severity: "warning",
        });
      }
      return { ok: true };
    },
    coordination.lockTimeoutMs,
    coordination.signal,
  );
}

/**
 * Destroy a code this document refuses to hand off or exchange. The dedicated
 * endpoint accepts either exact bridge origin but can only consume: it never
 * returns a session. Keepalive lets the tiny fire-and-forget POST survive the
 * fallback navigation; failure leaves only the code's short server TTL.
 */
export function burnSsoBridgeCode(
  code: string,
  hostname: string = window.location.hostname,
  fetchFn: typeof fetch = fetch,
): void {
  const base = apiBaseForHostname(hostname);
  if (!base || !isWellFormedSsoCode(code)) return;
  try {
    void fetchFn(`${base}/api/auth/sso-bridge/burn`, {
      method: "POST",
      credentials: "include",
      keepalive: true,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }).catch((error) => {
      // error-policy:J6 best-effort destruction of an already-abandoned code;
      // report the failure while the code's 60s TTL remains the final boundary.
      reportRendererDiagnostic({
        scope: "steward.sso-bridge.code-burn",
        error,
        severity: "warning",
      });
    });
  } catch (error) {
    // error-policy:J6 a fetch adapter may reject synchronously during teardown;
    // report it and rely on the same short server-side expiry boundary.
    reportRendererDiagnostic({
      scope: "steward.sso-bridge.code-burn",
      error,
      severity: "warning",
    });
  }
}

// ---------------------------------------------------------------------------
// Sign-out
// ---------------------------------------------------------------------------

/**
 * Explicit sign-out on ANY host of a bridge pair. The unified app's account
 * action routes hosted and public-auth sessions here because a local-only
 * sign-out that never reaches `/api/auth/logout` stamps no server logout
 * marker, and the paired origin's surviving session would silently undo it
 * (re-planting the domain cookies via its background session sync). Order
 * matters: the local logged-out marker lands synchronously first (auto-bridge
 * is suppressed even if the network never answers) and aborts an active
 * bridge cookie sync. The queued server logout then runs after that earlier
 * cookie mutation has settled, while the session cookies are still in the jar;
 * it ends the server-side sessions and stamps the marker for the presented
 * access-token authority. The local scrub shares that ordered teardown. On
 * hostnames outside the deployed map (local dev) the server call is skipped and
 * this degrades to the local scrub. A hosted non-success response or transport
 * failure rejects so explicit sign-out cannot claim success over a server
 * session that may still be live; refresh-family revocation remains owned by
 * Steward's server-side session contract.
 */
export async function signOutFromSsoBridgedHost(
  hostname: string = window.location.hostname,
  fetchFn: typeof fetch = fetch,
  coordination: SsoBridgeCoordinationOptions = {},
): Promise<void> {
  const stewardToken = readStoredStewardToken();
  const activeStewardToken =
    stewardToken && tokenLooksHydratable(stewardToken) ? stewardToken : null;
  // Invalidate before even issuing the server logout request: fetch adapters
  // may have synchronous hooks, and no re-entrant token publication may reuse
  // proof from the authority epoch being ended.
  invalidateStewardServerCookieSyncMarker();
  const logoutIntent = markSsoLoggedOut();
  if (!logoutIntent) {
    throw new Error("SSO session coordination is unavailable for sign-out.");
  }
  const base = apiBaseForHostname(hostname);
  const lockManager = resolveSsoBridgeLockManager(coordination.lockManager);
  await withSsoFinalizationLock(
    lockManager,
    async () => {
      // A newer login/logout intent owns the lock when it arrives; this older
      // logout must not tear down the session that intent is about to publish.
      // Reassert immediately: a stale exchange that passed its last authority
      // check just before this logout started may have removed the first marker
      // while we waited for custody. Network/storage failure below must still
      // leave auto-bridging suppressed for a safe retry.
      reassertSsoLoggedOutMarker(logoutIntent, "sign-out");
      const logoutAbortController = new AbortController();
      const stopForwardingLogoutAbort = forwardAbort(
        coordination.signal,
        logoutAbortController,
      );
      const serverLogout = base
        ? fetchWithDeadline(
            fetchFn,
            `${base}/api/auth/logout`,
            {
              method: "POST",
              credentials: "include",
              headers: {
                "Content-Type": "application/json",
                ...(activeStewardToken
                  ? { Authorization: `Bearer ${activeStewardToken}` }
                  : {}),
              },
            },
            logoutAbortController,
            SSO_LOGOUT_TIMEOUT_MS,
          )
        : // error-policy:J6 best-effort server teardown — the local marker is
          // already set and the local scrub below always runs.
          Promise.resolve(undefined);
      let response: Response | undefined;
      let barrierState: StewardLogoutBarrierState | null = null;
      try {
        response = await serverLogout;
        if (response?.ok) {
          barrierState = await readSsoLogoutBarrierProof(
            response,
            logoutAbortController,
          );
        }
      } finally {
        stopForwardingLogoutAbort();
      }
      if (response && !response.ok) {
        throw new Error(
          `Eliza Cloud could not end the browser session (${response.status}).`,
        );
      }
      if (response && !barrierState) {
        throw new Error(
          "Eliza Cloud did not return a valid browser-session logout proof.",
        );
      }
      // Retain the bearer needed to retry a failed hosted logout until the
      // server barrier has definitely accepted it. The synchronous marker
      // still suppresses auto-login throughout the attempt.
      await clearStaleStewardSession({
        awaitCookieClear: true,
        signal: coordination.signal,
        timeoutMs: SSO_LOGOUT_TIMEOUT_MS,
      });
      reassertSsoLoggedOutMarker(logoutIntent, "sign-out");
    },
    coordination.lockTimeoutMs,
    coordination.signal,
  );
}

/**
 * Ends the ambient hosted session before a native account-switch login.
 * Unlike ordinary sign-out, this boundary fails closed: rendering provider
 * choices over a still-live HttpOnly session would silently select the prior
 * account again.
 */
export async function prepareSsoAccountSwitch(
  hostname: string = window.location.hostname,
  fetchFn: typeof fetch = fetch,
  coordination: SsoBridgeCoordinationOptions = {},
): Promise<void> {
  const stewardToken = readStoredStewardToken();
  const activeStewardToken =
    stewardToken && tokenLooksHydratable(stewardToken) ? stewardToken : null;
  invalidateStewardServerCookieSyncMarker();
  const logoutIntent = markSsoLoggedOut();
  if (!logoutIntent) {
    throw new Error(
      "SSO session coordination is unavailable for account switching.",
    );
  }
  const base = apiBaseForHostname(hostname);
  if (!base) {
    throw new Error(
      "Eliza Cloud account switching is unavailable on this host.",
    );
  }
  const lockManager = resolveSsoBridgeLockManager(coordination.lockManager);
  await withSsoFinalizationLock(
    lockManager,
    async () => {
      reassertSsoLoggedOutMarker(logoutIntent, "account switch");
      const logoutAbortController = new AbortController();
      const stopForwardingLogoutAbort = forwardAbort(
        coordination.signal,
        logoutAbortController,
      );
      const serverLogout = fetchWithDeadline(
        fetchFn,
        `${base}/api/auth/logout`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            ...(activeStewardToken
              ? { Authorization: `Bearer ${activeStewardToken}` }
              : {}),
          },
        },
        logoutAbortController,
        SSO_LOGOUT_TIMEOUT_MS,
      );
      let response: Response;
      let barrierState: StewardLogoutBarrierState | null = null;
      try {
        response = await serverLogout;
        if (response.ok) {
          barrierState = await readSsoLogoutBarrierProof(
            response,
            logoutAbortController,
          );
        }
      } finally {
        stopForwardingLogoutAbort();
      }
      if (!response.ok) {
        throw new Error(
          `Eliza Cloud could not end the previous browser session (${response.status}).`,
        );
      }
      if (!barrierState) {
        throw new Error(
          "Eliza Cloud did not return a valid previous-session logout proof.",
        );
      }
      await clearStaleStewardSession({
        awaitCookieClear: true,
        signal: coordination.signal,
        timeoutMs: SSO_LOGOUT_TIMEOUT_MS,
      });
      reassertSsoLoggedOutMarker(logoutIntent, "account switch");
    },
    coordination.lockTimeoutMs,
    coordination.signal,
  );
}
