import { ReactNode, createContext, useContext, useMemo, useState } from "react";
import { IdentityRow, useApi } from "../api";
import { useOptionalSession } from "./auth";
import { store } from "./storage";

/**
 * A demo view switch: the persona decides what Home emphasises and which preview (mock)
 * items are "yours". It grants nothing and names no one to the API: the API takes the actor
 * of every action, and what you may do, from your signed-in session (see auth.tsx).
 */
export type Persona = "employee" | "manager" | "admin";

export const PERSONAS: { id: Persona; label: string; who: string; blurb: string }[] = [
  { id: "employee", label: "Employee", who: "Alice Okafor", blurb: "Requests access, sees what they have" },
  { id: "manager", label: "Manager", who: "Ingrid Lindqvist", blurb: "Approves for the team, runs reviews" },
  { id: "admin", label: "Admin & security", who: "Thandiwe Mokoena", blurb: "Owns risk, policy and lifecycle" },
];

interface PersonaCtx {
  persona: Persona;
  setPersona: (p: Persona) => void;
  /** The signed-in user's identity in this tenant, matched by email; null when there is none. */
  me: IdentityRow | null;
  /** True once the directory has loaded, so a null `me` means "no identity", not "still loading". */
  meResolved: boolean;
  /** Name the preview (mock) features record; real actions are attributed by the API. */
  actor: string;
}

const Ctx = createContext<PersonaCtx>({ persona: "admin", setPersona: () => {}, me: null, meResolved: false, actor: "Demo user" });
export const usePersona = () => useContext(Ctx);

export function PersonaProvider({ children }: { children: ReactNode }) {
  const [persona, setP] = useState<Persona>(() => store.get<Persona>("persona", "admin"));
  const { data } = useApi<IdentityRow[]>("/identities");
  const who = PERSONAS.find((p) => p.id === persona)!.who;
  const session = useOptionalSession()?.session ?? null;
  const email = session?.user.email?.toLowerCase() ?? null;
  // "My" pages show the signed-in user, never the demo persona: the persona only changes emphasis.
  const me = useMemo(() => (email ? data?.find((i) => i.email?.toLowerCase() === email) ?? null : null), [data, email]);
  const actor = session?.user.display_name ?? me?.name ?? who;
  const setPersona = (p: Persona) => {
    setP(p);
    store.set("persona", p);
  };
  return <Ctx.Provider value={{ persona, setPersona, me, meResolved: data !== null, actor }}>{children}</Ctx.Provider>;
}
