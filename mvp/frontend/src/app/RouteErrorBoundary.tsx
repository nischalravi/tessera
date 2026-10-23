import { Component, ReactNode } from "react";
import { useLocation } from "react-router-dom";

/**
 * Catches a page that throws while rendering, so one broken page shows an error card inside the
 * shell (top bar and left rail still work) instead of unmounting the whole app to a blank screen.
 * Keyed by path: moving to another page clears the error.
 */
class Boundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("page crashed", error);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const stale = isChunkLoadError(error);
    return (
      <div className="card stack-sm" role="alert" style={{ maxWidth: 720 }}>
        <h1>{stale ? "Tessera was updated" : "This page couldn't be shown"}</h1>
        <p className="small" style={{ margin: 0 }}>
          {stale
            ? "A newer version is available. Reload to get it; nothing you saved is lost."
            : "Something on this page failed to render. The rest of Tessera still works: use the menu, or reload to try again."}
        </p>
        {!stale && <pre className="xs faint" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{error.message}</pre>}
        <div className="row">
          <button type="button" className="btn primary" onClick={() => window.location.reload()}>Reload page</button>
        </div>
      </div>
    );
  }
}

/** A lazy route chunk that no longer exists (the app was rebuilt or redeployed since this tab loaded). */
export function isChunkLoadError(e: unknown): boolean {
  const m = e instanceof Error ? e.message : String(e);
  return /Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module|ChunkLoadError/i.test(m);
}

export function RouteErrorBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return <Boundary key={pathname}>{children}</Boundary>;
}
