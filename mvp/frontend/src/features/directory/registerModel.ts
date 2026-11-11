/** Registering a machine identity files a service-account request (issue #915); the server gates it on `requests.create`. */
export const REGISTER_PATH = "/access/request/service-account";
export const REGISTER_PERMISSION = "requests.create";

/** Where `?new=1` on Machine identities goes: the request form for who may file one, nowhere for anyone else. */
export function registerRedirect(search: string, can: (p: string) => boolean): string | null {
  return new URLSearchParams(search).get("new") === "1" && can(REGISTER_PERMISSION) ? REGISTER_PATH : null;
}

/** Whether the Register command is shown. */
export const canRegister = (can: (p: string) => boolean) => can(REGISTER_PERMISSION);

/** Drops the browser-side preview store the old object form wrote (key `tessera.mock.v1`). Never throws. */
export function purgeStaleMock(storage: Pick<Storage, "removeItem"> | undefined = typeof localStorage === "undefined" ? undefined : localStorage) {
  try {
    storage?.removeItem("tessera.mock.v1");
  } catch {
    /* storage unavailable; nothing to clean */
  }
}
