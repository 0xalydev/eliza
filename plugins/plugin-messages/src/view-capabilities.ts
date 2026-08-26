/** Defines the complete planner and human authority catalog for Messages view interactions. */

import type { ViewCapability } from "@elizaos/core";

export const MESSAGES_VIEW_CAPABILITIES = [
  {
    id: "list-threads",
    description:
      "List the complete Android SMS conversation-thread set and role state.",
    authority: "agent",
  },
  {
    id: "send-sms",
    description: "Send an SMS message through the Android Messages bridge.",
    authority: "human",
    params: {
      address: {
        type: "string",
        description: "Recipient phone number or SMS address.",
        required: true,
        minLength: 1,
      },
      body: {
        type: "string",
        description: "Message body.",
        required: true,
        minLength: 1,
      },
    },
  },
  {
    id: "request-sms-role",
    description: "Ask Android to make Eliza the default SMS role holder.",
    authority: "human",
  },
] as const satisfies readonly ViewCapability[];

export type MessagesViewCapabilityId =
  (typeof MESSAGES_VIEW_CAPABILITIES)[number]["id"];
