package policygroups

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Repository sync (design §8.5 step 3). A Source yields a snapshot of the policy
// repository: the commit and the files at it. How the snapshot is fetched (a git
// checkout by a CI job, a webhook, a poll) is the caller's; this package never
// makes an outbound call. Sync applies a snapshot as the whole repository.

// Source is a snapshot of the policy repository.
type Source interface {
	Snapshot() (commit string, files []SourceFile, err error)
}

// Sync applies the snapshot of src as one change: the repository's policy groups
// are the files of the snapshot, and the ones not in it are retired.
func (a *Applier) Sync(src Source) (*ApplyResult, error) {
	commit, files, err := src.Snapshot()
	if err != nil {
		return nil, err
	}
	return a.Apply(ApplyInput{Origin: "repo", Commit: commit, Files: files, Full: true})
}

// DirSource reads the *.cedar files under Root, which a CI job or an operator has
// checked out at Commit. Paths are relative to Root with '/' separators. It does
// not follow symbolic links, and it cannot read outside Root.
type DirSource struct {
	Root   string
	Commit string
}

// Snapshot implements Source.
func (d DirSource) Snapshot() (string, []SourceFile, error) {
	files, err := ReadDir(d.Root)
	return d.Commit, files, err
}

// ReadDir reads the *.cedar files under root (see DirSource).
func ReadDir(root string) ([]SourceFile, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	fsys := r.FS()
	var out []SourceFile
	err = fs.WalkDir(fsys, ".", func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() || !strings.HasSuffix(path, ".cedar") || e.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if len(out) >= MaxFiles {
			return fmt.Errorf("more than %d policy files", MaxFiles)
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if info.Size() > MaxFileBytes {
			return fmt.Errorf("%s is larger than %d bytes", path, MaxFileBytes)
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		out = append(out, SourceFile{Path: path, Cedar: string(b)})
		return nil
	})
	return out, err
}
