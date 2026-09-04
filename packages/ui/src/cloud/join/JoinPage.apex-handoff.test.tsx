/**
 * Mounts the authenticated join page at the canonical production auth origin
 * and proves its app-host handoff preserves /join before identity resolution.
 */
// @vitest-environment jsdom
// @vitest-environment-options {"url": "https://eliza.app/join"}

import { STEWARD_TOKEN_KEY } from "@elizaos/shared/steward-session-client";
import { cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { appModeNavigation } from "../app-mode/app-mode";

const { runJoinFlowMock } = vi.hoisted(() => ({
  runJoinFlowMock: vi.fn(),
}));

vi.mock("./lib/use-join-session", () => ({
  useJoinSessionAuth: () => ({ ready: true, authenticated: true }),
}));

vi.mock("./lib/run-join-flow", () => ({
  runJoinFlow: runJoinFlowMock,
}));

vi.mock("react-router-dom", () => ({
  Navigate: ({ to }: { to: string }) => <div data-navigate-to={to} />,
}));

vi.mock("../shell/CloudI18nProvider", () => ({
  useCloudT: () => (_key: string, options?: { defaultValue?: string }) =>
    options?.defaultValue ?? "",
}));

import JoinPage from "./JoinPage";

const realReplace = appModeNavigation.replace;
let replacedUrls: string[];

function liveToken(): string {
  const encode = (value: object) =>
    btoa(JSON.stringify(value))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "none" })}.${encode({
    userId: "apex-user",
    exp: Math.floor(Date.now() / 1000) + 3600,
  })}.sig`;
}

beforeEach(() => {
  runJoinFlowMock.mockReset();
  replacedUrls = [];
  window.localStorage.setItem(STEWARD_TOKEN_KEY, liveToken());
  window.localStorage.removeItem("eliza_sso_logged_out");
  window.localStorage.removeItem("eliza_sso_logout_generation");
  appModeNavigation.replace = (url: string) => {
    replacedUrls.push(url);
  };
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  appModeNavigation.replace = realReplace;
});

describe("JoinPage apex app handoff", () => {
  it("replaces to the paired app origin before identity resolution", async () => {
    render(<JoinPage />);

    await waitFor(() => {
      expect(replacedUrls).toEqual(["https://cloud.eliza.app/join"]);
    });
    expect(window.location.hostname).toBe("eliza.app");
    expect(runJoinFlowMock).not.toHaveBeenCalled();
  });

  it("does not hand off when logout authority advanced before the effect", async () => {
    window.localStorage.setItem("eliza_sso_logged_out", "1");

    render(<JoinPage />);

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(replacedUrls).toEqual([]);
    expect(runJoinFlowMock).not.toHaveBeenCalled();
  });
});
