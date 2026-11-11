/**
 * Preview mock layer. Typed stand-ins for backend capabilities that do not exist yet:
 * admin settings.
 *
 * Nothing here calls the API, and nothing here invents API routes.
 */
import { ADMIN_SECTIONS } from "./data";

export * from "./types";
export { ADMIN_SECTIONS };

export const ADMIN_BY_ID = Object.fromEntries(ADMIN_SECTIONS.map((s) => [s.id, s]));
