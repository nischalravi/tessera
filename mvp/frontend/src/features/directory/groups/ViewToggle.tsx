import { useSearchParams } from "react-router-dom";
import { Segmented } from "../../../components";

export type GroupsView = "managed" | "connected";

/** `?view=connected` shows the groups of connected systems; anything else (and the default) the managed, native groups. */
export function useGroupsView(): [GroupsView, (v: GroupsView) => void] {
  const [params, setParams] = useSearchParams();
  const view: GroupsView = params.get("view") === "connected" ? "connected" : "managed";
  // the selection, folder and filters belong to one view, so switching starts clean
  const set = (v: GroupsView) => setParams(v === "connected" ? { view: "connected" } : {});
  return [view, set];
}

/** The Managed / Connected switch of Directory → Groups. */
export function ViewToggle() {
  const [view, setView] = useGroupsView();
  return (
    <Segmented<GroupsView>
      label="Which groups"
      value={view}
      onChange={setView}
      options={[["managed", "Managed groups"], ["connected", "Connected groups"]]}
    />
  );
}
