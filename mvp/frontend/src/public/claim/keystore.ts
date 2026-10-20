import { generateKey } from "./proof";

/**
 * Where the page keeps its key between the page loads of one claim (the redirect to the sign-in
 * service and back). A CryptoKey is stored in IndexedDB by structured clone: it stays
 * non-extractable. The nonce is not a secret (a proof needs the key as well) and lives in
 * sessionStorage. Both are keyed by tenant, and both are removed when the claim ends.
 */

const DB = "tessera-claim";
const STORE = "keys";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const r = fn(db.transaction(STORE, mode).objectStore(STORE));
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  } finally {
    db.close();
  }
}

export const loadKey = (slug: string) => tx<CryptoKeyPair | undefined>("readonly", (s) => s.get(slug));
export const saveKey = (slug: string, pair: CryptoKeyPair) => tx("readwrite", (s) => s.put(pair, slug)).then(() => undefined);
export const dropKey = (slug: string) => tx("readwrite", (s) => s.delete(slug)).then(() => undefined);

/** A fresh key for a new claim (an old one for the tenant is replaced). */
export async function newKey(slug: string): Promise<CryptoKeyPair> {
  const pair = await generateKey();
  await saveKey(slug, pair);
  return pair;
}

const nonceKey = (slug: string) => `tessera.claim.nonce.${slug}`;
export const saveNonce = (slug: string, nonce: string) => sessionStorage.setItem(nonceKey(slug), nonce);
export const loadNonce = (slug: string) => sessionStorage.getItem(nonceKey(slug));
export const dropNonce = (slug: string) => sessionStorage.removeItem(nonceKey(slug));
