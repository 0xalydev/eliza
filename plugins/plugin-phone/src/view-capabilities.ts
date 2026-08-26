/** Defines the complete planner and human authority catalog for Phone view interactions. */

import type { ViewCapability } from "@elizaos/core";

export const PHONE_VIEW_CAPABILITIES = [
  {
    id: "phone-state",
    description: "Read Android phone status and recent calls.",
    authority: "agent",
    params: {
      number: {
        type: "string",
        description: "Optional phone-number filter.",
      },
    },
  },
  {
    id: "place-call",
    description: "Place an outbound phone call.",
    authority: "human",
    params: {
      number: {
        type: "string",
        description: "Phone number to call.",
        required: true,
        minLength: 1,
      },
    },
  },
  {
    id: "open-dialer",
    description: "Open the Android dialer, optionally with a number.",
    authority: "human",
    params: {
      number: {
        type: "string",
        description: "Optional phone number to prefill.",
      },
    },
  },
  {
    id: "save-call-transcript",
    description: "Persist an agent transcript and optional summary for a call.",
    authority: "human",
    params: {
      callId: {
        type: "string",
        description: "Call-log record identifier.",
        required: true,
        minLength: 1,
      },
      transcript: {
        type: "string",
        description: "Complete call transcript.",
        required: true,
        minLength: 1,
      },
      summary: {
        type: "string",
        description: "Optional call summary.",
      },
    },
  },
] as const satisfies readonly ViewCapability[];

export type PhoneViewCapabilityId =
  (typeof PHONE_VIEW_CAPABILITIES)[number]["id"];
