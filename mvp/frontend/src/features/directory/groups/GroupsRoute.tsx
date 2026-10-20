import { Suspense, lazy } from "react";
import { PageSkeleton } from "../../../components";
import { useGroupsView } from "./ViewToggle";

// each view is its own chunk: the managed groups' screens load only when they are used
const ManagedGroups = lazy(() => import("./ManagedGroups").then((m) => ({ default: m.ManagedGroups })));
const ConnectedGroups = lazy(() => import("../Lists").then((m) => ({ default: m.ConnectedGroups })));

/** Directory → Groups: Managed groups (native, with folders) or Connected groups (from systems). */
export function GroupsRoute() {
  const [view] = useGroupsView();
  return <Suspense fallback={<PageSkeleton />}>{view === "connected" ? <ConnectedGroups /> : <ManagedGroups />}</Suspense>;
}
