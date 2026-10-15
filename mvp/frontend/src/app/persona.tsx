import { ReactNode, createContext, useContext, useMemo, useState } from "react";
import { IdentityRow, useApi } from "../api";
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
  /** The demo identity behind the persona (resolved by name from the seeded directory). */
  me: IdentityRow | null;
  /** Name the preview (mock) features record; real actions are attributed by the API. */
  actor: string;
}

const Ctx = createContext<PersonaCtx>({ persona: "admin", setPersona: () => {}, me: null, actor: "Demo user" });
export const usePersona = () => useContext(Ctx);

export function PersonaProvider({ children }: { children: ReactNode }) {
  const [persona, setP] = useState<Persona>(() => store.get<Persona>("persona", "admin"));
  const { data } = useApi<IdentityRow[]>("/identities");
  const who = PERSONAS.find((p) => p.id === persona)!.who;
  const me = useMemo(() => data?.find((i) => i.name === who) ?? null, [data, who]);
  const actor = me?.name ?? who;
  const setPersona = (p: Persona) => {
    setP(p);
    store.set("persona", p);
  };
  return <Ctx.Provider value={{ persona, setPersona, me, actor }}>{children}</Ctx.Provider>;
}
