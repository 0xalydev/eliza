/** Defines the complete planner and human authority catalog for Contacts view interactions. */

import type { ViewCapability } from "@elizaos/core";

export const CONTACTS_VIEW_CAPABILITIES = [
  {
    id: "list-contacts",
    description: "List or search contacts from the Android address book.",
    authority: "agent",
    params: {
      query: {
        type: "string",
        description: "Optional name, phone number, or email search text.",
      },
      limit: {
        type: "number",
        description: "Maximum contacts to return.",
        minimum: 1,
        maximum: 500,
      },
    },
  },
  {
    id: "create-contact",
    description: "Create a contact in the Android address book.",
    authority: "human",
    params: {
      displayName: {
        type: "string",
        description: "Contact display name.",
        required: true,
        minLength: 1,
      },
      phoneNumber: {
        type: "string",
        description: "Optional phone number.",
      },
      emailAddress: {
        type: "string",
        description: "Optional email address.",
      },
    },
  },
  {
    id: "import-vcard",
    description: "Import one or more contacts from vCard text.",
    authority: "human",
    params: {
      vcardText: {
        type: "string",
        description: "Complete vCard document to import.",
        required: true,
        minLength: 1,
      },
    },
  },
] as const satisfies readonly ViewCapability[];

export type ContactsViewCapabilityId =
  (typeof CONTACTS_VIEW_CAPABILITIES)[number]["id"];
