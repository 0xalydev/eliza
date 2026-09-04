/** Verifies /join exposes the server-owned Dedicated adoption quote before any mutating confirmation. */
// @vitest-environment jsdom

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DedicatedAdoptionConfirmationQuote } from "../../api/client-cloud";

const runJoinFlowMock = vi.hoisted(() => vi.fn());
const joinAuthState = vi.hoisted(() => ({
  authenticated: true,
  token: "steward-token" as string | null,
}));

vi.mock("react-router-dom", () => ({
  Navigate: ({ to }: { to: string }) => <div data-testid="navigate">{to}</div>,
}));
vi.mock("./lib/use-join-session", () => ({
  useJoinSessionAuth: () => ({
    ready: true,
    authenticated: joinAuthState.authenticated,
  }),
}));
vi.mock("./lib/run-join-flow", () => ({
  runJoinFlow: runJoinFlowMock,
}));
vi.mock("./lib/resolve-cloud-connection", () => ({
  resolveJoinAuthToken: () => joinAuthState.token,
  resolveJoinCloudApiBase: () => "https://api.eliza.app",
}));
vi.mock("../shell/CloudI18nProvider", () => ({
  useCloudT: () => (_key: string, options?: Record<string, unknown>) => {
    let text = String(options?.defaultValue ?? _key);
    for (const [name, value] of Object.entries(options ?? {})) {
      text = text.replaceAll(`{{${name}}}`, String(value));
    }
    return text;
  },
}));
vi.mock("./lib/apex-app-handoff", () => ({
  resolveApexJoinHandoff: () => null,
}));

import JoinPage from "./JoinPage";

const QUOTE: DedicatedAdoptionConfirmationQuote = {
  quoteId: "a".repeat(64),
  dedicatedAgentId: "00000000-0000-4000-8000-000000000099",
  adoptionState: "available",
  status: "error",
  startsCompute: true,
  hourlyRateUsd: 0.01,
  dailyRateUsd: 0.24,
  minimumBalanceUsd: 0.72,
  minimumRunwayDays: 3,
  balanceUsd: 115.54059,
  deficitUsd: 0,
  stateDisposition: "verified_backup_present",
  canAdopt: true,
  requiresCatalogRestore: false,
  requiresConfirmation: true,
  action: "adopt_existing_dedicated",
};

const CONNECTED = {
  personalElizaId: "personal:00000000-0000-5000-8000-000000000001",
  agentId: "personal:00000000-0000-5000-8000-000000000001",
  activeAgentId: QUOTE.dedicatedAgentId,
  agentName: "Eliza",
  apiBase: `https://${QUOTE.dedicatedAgentId}.cloud.eliza.app`,
  runtime: "dedicated" as const,
};

describe("JoinPage Dedicated adoption consent", () => {
  beforeEach(() => {
    runJoinFlowMock.mockReset();
    joinAuthState.authenticated = true;
    joinAuthState.token = "steward-token";
    window.localStorage.removeItem("eliza_sso_logged_out");
    window.localStorage.removeItem("eliza_sso_logout_generation");
  });

  afterEach(cleanup);

  it("renders changed server terms without private ids and submits only the exact confirmed quote", async () => {
    let submitted:
      | { action: "adopt_existing_dedicated"; quoteId: string }
      | null
      | undefined;
    runJoinFlowMock.mockImplementation(
      async ({ requestDedicatedAdoptionConfirmation, signal }) => {
        submitted = await requestDedicatedAdoptionConfirmation(QUOTE, {
          reason: "quote_changed",
          signal,
        });
        if (!submitted)
          throw new Error("Dedicated adoption was not confirmed.");
        return CONNECTED;
      },
    );

    render(<JoinPage />);

    expect(
      await screen.findByRole("heading", {
        name: "Bring this Dedicated Eliza online?",
      }),
    ).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toBe(
      "The Dedicated terms changed. Review the current quote before continuing.",
    );
    expect(
      screen.getByText(
        "This starts Dedicated hosting at $0.24/day ($0.01/hr).",
      ),
    ).toBeTruthy();
    expect(
      screen.getByText("Balance: $115.54 · Required: $0.72 (3 days of runway)"),
    ).toBeTruthy();
    expect(
      screen.getByText(
        "Cloud will restore its reviewed backup before switching.",
      ),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain(QUOTE.quoteId);
    expect(document.body.textContent).not.toContain(QUOTE.dedicatedAgentId);
    expect(submitted).toBeUndefined();

    await userEvent.click(
      screen.getByRole("button", { name: "Start Dedicated" }),
    );

    await waitFor(() =>
      expect(submitted).toEqual({
        action: "adopt_existing_dedicated",
        quoteId: QUOTE.quoteId,
      }),
    );
    expect((await screen.findByTestId("navigate")).textContent).toBe("/");
  });

  it("cancels fail closed and tells the user Shared remains unchanged", async () => {
    let submitted:
      | { action: "adopt_existing_dedicated"; quoteId: string }
      | null
      | undefined;
    runJoinFlowMock.mockImplementation(
      async ({ requestDedicatedAdoptionConfirmation, signal }) => {
        submitted = await requestDedicatedAdoptionConfirmation(QUOTE, {
          reason: "initial",
          signal,
        });
        if (!submitted)
          throw new Error("Dedicated adoption was not confirmed.");
        return CONNECTED;
      },
    );

    render(<JoinPage />);
    await screen.findByRole("button", { name: "Cancel setup" });

    await userEvent.click(screen.getByRole("button", { name: "Cancel setup" }));

    await waitFor(() => expect(submitted).toBeNull());
    expect(
      await screen.findByText(
        "Dedicated setup was not started. Your Shared Eliza is unchanged.",
      ),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
    expect(screen.queryByTestId("navigate")).toBeNull();
  });

  it("aborts a pending adoption quote when another tab advances logout generation", async () => {
    let submitted:
      | { action: "adopt_existing_dedicated"; quoteId: string }
      | null
      | undefined;
    let joinSignal: AbortSignal | undefined;
    runJoinFlowMock.mockImplementation(
      async ({ requestDedicatedAdoptionConfirmation, signal }) => {
        joinSignal = signal;
        submitted = await requestDedicatedAdoptionConfirmation(QUOTE, {
          reason: "initial",
          signal,
        });
        if (!submitted)
          throw new Error("Dedicated adoption was not confirmed.");
        return CONNECTED;
      },
    );

    render(<JoinPage />);
    await screen.findByRole("button", { name: "Start Dedicated" });

    window.localStorage.setItem(
      "eliza_sso_logout_generation",
      "another-tab-logout",
    );
    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: "eliza_sso_logout_generation",
          newValue: "another-tab-logout",
        }),
      );
    });

    await waitFor(() => expect(joinSignal?.aborted).toBe(true));
    expect(submitted).toBeNull();
    expect(screen.queryByTestId("dedicated-adoption-confirm")).toBeNull();
    expect(screen.queryByText("/")).toBeNull();
  });

  it("aborts a pending adoption quote when rendered auth is lost", async () => {
    let submitted:
      | { action: "adopt_existing_dedicated"; quoteId: string }
      | null
      | undefined;
    let joinSignal: AbortSignal | undefined;
    runJoinFlowMock.mockImplementation(
      async ({ requestDedicatedAdoptionConfirmation, signal }) => {
        joinSignal = signal;
        submitted = await requestDedicatedAdoptionConfirmation(QUOTE, {
          reason: "initial",
          signal,
        });
        if (!submitted)
          throw new Error("Dedicated adoption was not confirmed.");
        return CONNECTED;
      },
    );

    const view = render(<JoinPage />);
    await screen.findByRole("button", { name: "Start Dedicated" });

    joinAuthState.authenticated = false;
    view.rerender(<JoinPage />);

    await waitFor(() => expect(joinSignal?.aborted).toBe(true));
    expect(submitted).toBeNull();
    expect(screen.queryByTestId("dedicated-adoption-confirm")).toBeNull();
  });

  it("rechecks the canonical bearer before resolving adoption consent", async () => {
    let submitted:
      | { action: "adopt_existing_dedicated"; quoteId: string }
      | null
      | undefined;
    runJoinFlowMock.mockImplementation(
      async ({ requestDedicatedAdoptionConfirmation, signal }) => {
        submitted = await requestDedicatedAdoptionConfirmation(QUOTE, {
          reason: "initial",
          signal,
        });
        if (!submitted)
          throw new Error("Dedicated adoption was not confirmed.");
        return CONNECTED;
      },
    );

    render(<JoinPage />);
    const confirm = await screen.findByRole("button", {
      name: "Start Dedicated",
    });

    // The other tab's storage event may not have been delivered yet. The
    // click boundary still reads canonical authority synchronously, so the
    // already-captured bearer can never be submitted after its removal.
    joinAuthState.token = null;
    await userEvent.click(confirm);

    await waitFor(() => expect(submitted).toBeNull());
    expect(screen.queryByTestId("navigate")?.textContent).not.toBe("/");
  });
});
