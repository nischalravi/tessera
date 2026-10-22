package admin

import (
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeGroupFolderDelete deletes a folder and everything in it (its subfolders,
// groups and attribute definitions) after a second admin approved it. The route
// files it when the tree holds more than model.RecursiveApprovalGroups groups or
// any group with members; a smaller, empty tree is deleted at once (same
// workflow as the SQL loader, GRP-6311). The payload carries the counts the
// requester saw, so the second person approves exactly what will be applied:
// a folder that grew since fails instead of being deleted.
const TypeGroupFolderDelete = "groups.folder.delete_recursive"

type folderDeletePayload struct {
	FolderID string `json:"folder_id"`
	Name     string `json:"name"`
	Folders  int    `json:"folders"`
	Groups   int    `json:"groups"`
	Members  int    `json:"memberships"`
}

func init() {
	changeTypes[TypeGroupFolderDelete] = typed(TypeGroupFolderDelete, nil, planFolderDelete, applyFolderDelete,
		func(_ *env, v *folderDeletePayload) string {
			return fmt.Sprintf("Delete folder %q and everything in it (%d subfolders, %d groups, %d memberships)",
				v.Name, v.Folders, v.Groups, v.Members)
		})
}

func (e *env) groupsModel() model.Env {
	by := e.by.String()
	return model.Env{Tx: e.tx, Now: e.now, By: &by}
}

func planFolderDelete(e *env, v *folderDeletePayload) (plan, error) {
	if err := grpID(v.FolderID); err != nil {
		return plan{}, err
	}
	p, err := e.groupsModel().PlanFolderDelete(store.FolderID(v.FolderID))
	if err != nil {
		return plan{}, loaderErr(err)
	}
	if len(p.Blockers) > 0 {
		return plan{}, loaderErr(p.BlockedError())
	}
	if p.Folders != v.Folders || p.TotalGroups() != v.Groups || p.Memberships != v.Members {
		return plan{}, conflict("folder_changed", "the folder changed since the request was made (%d subfolders, %d groups, %d memberships now): ask again",
			p.Folders, p.TotalGroups(), p.Memberships)
	}
	return plan{twoPerson: true, target: v.FolderID}, nil
}

func applyFolderDelete(e *env, _ *store.AdminChange, v *folderDeletePayload) error {
	if _, err := planFolderDelete(e, v); err != nil {
		return err
	}
	_, _, err := e.groupsModel().DeleteFolderRecursive(store.FolderID(v.FolderID))
	return loaderErr(err)
}

func grpID(id string) error {
	if len(id) == 0 || len(id) > 64 {
		return invalid("folder_id is required")
	}
	for _, c := range id {
		if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return invalid("folder_id is not a folder id")
		}
	}
	return nil
}
