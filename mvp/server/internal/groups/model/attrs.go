package model

import (
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The attribute framework (GR-7, internal/groups/attrs) reaches the folder and
// group service in three places: a folder and a direct membership take their
// attribute assignments with them when they are deleted, a folder with
// attribute definitions is not empty, and the built-in object types definition
// needs the etc folder, which only this layer can create.

// Attrs is the same operation context for the attribute framework.
func (e Env) Attrs() attrs.Env {
	return attrs.Env{Tx: e.Tx, Now: e.Now, By: e.By, ByIdentity: e.ByIdentity, TenantAdmin: e.TenantAdmin}
}

// EnsureObjectTypes creates the built-in object types definition (and the etc
// folder that holds it) on first use. It is idempotent. The system owns what it
// creates: no creator privileges go to the acting user.
func (e Env) EnsureObjectTypes() error {
	sys := e
	sys.ByIdentity = nil
	if d, n, err := attrs.Builtin(e.Tx); err != nil {
		return err
	} else if d != nil && n != nil {
		return nil
	}
	f, err := e.Tx.GrpFolderByName(attrs.ObjectTypesFolder)
	if errors.Is(err, store.ErrNotFound) {
		f, err = sys.CreateFolder(CreateFolderInput{Extension: attrs.ObjectTypesFolder,
			Description: "Built-in definitions (object types)"})
	}
	if err != nil {
		return err
	}
	_, _, err = attrs.CreateBuiltin(sys.Attrs(), f.ID)
	return err
}

// copyObjectTypes gives a copy the object types of its source (a copied group or
// folder keeps its badges). Nothing happens while the source has none.
func (e Env) copyObjectTypes(src, dst attrs.Owner) error {
	types, err := attrs.ObjectTypesOf(e.Tx, src)
	if err != nil || len(types) == 0 {
		return err
	}
	_, err = attrs.SetObjectTypes(e.Attrs(), dst, types)
	return err
}
