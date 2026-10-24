// Connect-step base URL field of the templates that take one and are not governed types (those carry theirs in
// governed.ts). Pure, so `npm test` checks that every server template with a base_url config field gets an input.

export interface BaseUrlField { label: string; hint: string }

/** Keyed by template id. The SCIM application's hint is built from its vendor preset in the wizard. */
export const BASE_URL_FIELDS: Record<string, BaseUrlField> = {
  scim_app: { label: "SCIM base URL", hint: "HTTPS only." },
  salesforce: {
    label: "My Domain URL",
    hint: "https://yourcompany.my.salesforce.com (a sandbox: *.sandbox.my.salesforce.com). HTTPS host name only, no path. The login host is set in the credential (login_url) for a sandbox.",
  },
};
