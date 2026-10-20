import { useCallback, useEffect, useRef, useState } from "react";
import { CHANGED } from "../../../api";

/**
 * Load something through a `groups.*` call. It reloads when `key` changes and after any successful write
 * anywhere (the API client broadcasts), so counts and statuses stay consistent. `null` skips the load.
 */
export function useLoad<T>(load: (() => Promise<T>) | null, key: string) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const fn = useRef(load);
  fn.current = load;
  const run = useCallback(() => {
    const f = fn.current;
    if (!f) return undefined;
    let alive = true;
    setLoading(true);
    f()
      .then((d) => alive && (setData(d), setError(null)))
      .catch((e) => alive && setError(String(e?.message ?? e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  useEffect(() => {
    setData(null);
    return run();
  }, [run]);
  useEffect(() => {
    let stop: (() => void) | undefined;
    const on = () => {
      stop?.();
      stop = run();
    };
    window.addEventListener(CHANGED, on);
    return () => {
      window.removeEventListener(CHANGED, on);
      stop?.();
    };
  }, [run]);
  return { data, error, loading, reload: run };
}

/** A message from an error thrown by the API client. */
export const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));
