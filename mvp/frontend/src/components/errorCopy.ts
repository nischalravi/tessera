import type { ErrorKind } from "../api";

/** What an error panel says for a failed load. No port, host or raw server body ever appears here. */
export interface ErrorCopy {
  text: string;
  /** Extra plain detail from the server (forbidden only), shown after the text. */
  detail?: string;
  /** Whether trying again can help: only when the API could not be reached or failed. */
  retry: boolean;
}

/** The plain-language copy for an error kind. `noun` names the thing that was being loaded. */
export function errorCopy(kind: ErrorKind, noun = "item", serverMessage?: string | null): ErrorCopy {
  switch (kind) {
    case "not_found":
      return { text: `This ${noun} no longer exists or the link is wrong.`, retry: false };
    case "validation":
      return { text: "That link isn't valid.", retry: false };
    case "forbidden":
      return { text: "You don't have access.", detail: serverMessage || undefined, retry: false };
    case "conflict":
      return { text: "That changed while you were looking. Reload and try again.", retry: false };
    case "network":
    case "server":
      return { text: "Tessera can't reach its API right now. Try again in a moment.", retry: true };
  }
}
