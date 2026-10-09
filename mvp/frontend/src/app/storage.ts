/** localStorage wrapper for per-browser UI conveniences (theme, persona, saved views, drafts). */
const NS = "tessera.";

export const store = {
  get<T>(key: string, fallback: T): T {
    try {
      const raw = localStorage.getItem(NS + key);
      return raw === null ? fallback : (JSON.parse(raw) as T);
    } catch {
      return fallback;
    }
  },
  set(key: string, value: unknown) {
    try {
      localStorage.setItem(NS + key, JSON.stringify(value));
    } catch {
      /* storage unavailable (private mode); the UI still works for this session */
    }
  },
};
