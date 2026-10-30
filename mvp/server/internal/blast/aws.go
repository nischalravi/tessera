package blast

import (
	"context"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

// AWSBase is the collected estate an AWS change is replayed against: the snapshot, its index and the memo that the
// base and head queriers share, so the cells a change does not touch are decided once.
type AWSBase struct {
	Snap  *model.Snapshot
	Index *index.Index
	Memo  *index.Memo
}

// AWSRun is what the operations do to the estate.
type AWSRun struct {
	Head *model.Snapshot
	Diff *query.DiffResult
}

// ApplyAndDiff applies the operations to the base snapshot in memory (snapshot.Apply), indexes the result from the
// base's index (Refine, which reuses what the change leaves alone) and diffs the two with the same query options
// (query.Diff). maxExpand bounds the action and resource names listed per change; the counts are exact. A
// *snapshot.ChangeError names the operation that cannot be applied; an error wrapping query.ErrOptions is a request
// for options the engine refuses. Nothing is stored.
func ApplyAndDiff(ctx context.Context, base AWSBase, ops []Operation, apply snapshot.ApplyOptions, headConfig func(*model.Snapshot) index.Config,
	opts query.Options, maxExpand int) (*AWSRun, error) {
	head, err := snapshot.Apply(base.Snap, Changes(ops), apply)
	if err != nil {
		return nil, err
	}
	hix, err := base.Index.Refine(head, headConfig(head))
	if err != nil {
		return nil, err
	}
	bq, err := query.New(base.Index, base.Memo, opts)
	if err != nil {
		return nil, err
	}
	hq, err := query.New(hix, base.Memo, opts)
	if err != nil {
		return nil, err
	}
	res, err := query.Diff(ctx, bq, hq, query.DiffOptions{MaxExpand: maxExpand})
	if err != nil {
		return nil, err
	}
	return &AWSRun{Head: head, Diff: res}, nil
}
