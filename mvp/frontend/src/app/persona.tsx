import { ReactNode, createContext, useContext, useMemo, useState } from "react";
import { IdentityRow, useApi } from "../api";
import { store } from "./storage";

/**
 * Demo stand-in for authentication (until Phase 0 auth lands): the persona decides what
 * Home emphasises and whose name is recorded on approvals. It grants no permissions;
 * the API has no authorization yet.
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
  /** Name recorded as the actor on approvals and decisions. */
  actor: string;
}

const Ctx = createContext<PersonaCtx>({ persona: "admin", setPersona: () => {}, me: null, actor: "Demo user" });
export const usePersona = () => useContext(Ctx);

export function PersonaProvider({ children }: { children: ReactNode }) {
  const [persona, setP] = useState<Persona>(() => store.get<Persona>("persona", "admin"));
  const { data } = useApi<IdentityRow[]>("/identities");
  const who = PERSONAS.find((p) => p.id === persona)!.who;
  const me = useMemo(() => data?.find((i) => i.name === who) ?? null, [data, who]);
  const setPersona = (p: Persona) => {
    setP(p);
    store.set("persona", p);
  };
  return <Ctx.Provider value={{ persona, setPersona, me, actor: me?.name ?? who }}>{children}</Ctx.Provider>;
}
