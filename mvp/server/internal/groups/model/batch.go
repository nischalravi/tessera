package model

import (
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Batch membership changes (issue #48, GR-5; design §10.11). One request adds
// and removes up to MaxBatchOps members of one group. A batch is atomic by
// default: the first refused operation undoes the whole batch (the API answers
// with the operation's index). With atomic off every operation stands or falls
// by itself: a refused one is undone to a savepoint and reported in its result,
// the others are kept. Either way every operation writes its own domain event
// and the batch writes groups.member.batch, all in the caller's transaction.

// MaxBatchOps bounds the operations of one batch.
const MaxBatchOps = 1000

// Batch operation kinds and result statuses.
const (
	BatchAdd    = "add"
	BatchRemove = "remove"

	BatchCreated = "created"
	BatchUpdated = "updated"
	BatchRemoved = "removed"
	BatchFailed  = "failed"
)

// BatchOp is one operation. An add names an identity or a group (Group) and may
// carry dates and a reason; a remove names the member as the members routes do
// (an identity id or a group id).
type BatchOp struct {
	Kind        string
	Identity    *int64
	Group       store.GroupID
	Member      string // remove: an identity id (digits) or a group id (UUID)
	EnabledFrom *time.Time
	DisabledAt  *time.Time
	Reason      string
}

// BatchItem is the result of one operation, in request order.
type BatchItem struct {
	Index      int
	Kind       string
	MemberType store.MemberType // "" when the operation did not name a member
	Member     string
	Status     string // created, updated, removed or failed
	// Effective is "applied" or "pending" (a queued recompute, see Op); empty when failed.
	Effective string
	Op        *int64
	Err       error // set when Status is failed
}

// BatchResult is what a batch did.
type BatchResult struct {
	Group   *store.NativeGroup
	Items   []BatchItem
	Created int
	Updated int
	Removed int
	Failed  int
	// Ops are the operation ids of the queued recomputes (none when everything
	// was applied in the transaction).
	Ops []int64
}

// OpError says which operation of an atomic batch was refused, and why.
type OpError struct {
	Index int
	Err   error
}

func (e *OpError) Error() string { return fmt.Sprintf("operation %d: %v", e.Index, e.Err) }
func (e *OpError) Unwrap() error { return e.Err }

// perOp reports whether err is a refusal of the operation (reported in its
// result when the batch is not atomic) rather than a failure of the system
// (which aborts the request).
func perOp(err error) bool {
	var me *Error
	var de *privs.DeniedError
	return errors.As(err, &me) || errors.As(err, &de)
}

// ApplyBatch applies ops to the group. authorize, if set, is asked before each
// operation (the model does not check privileges; the API does).
func (e Env) ApplyBatch(id store.GroupID, ops []BatchOp, atomic bool, authorize func(i int, op BatchOp) error) (*BatchResult, error) {
	if len(ops) == 0 {
		return nil, invalid("empty_batch", "add or remove at least one member")
	}
	if len(ops) > MaxBatchOps {
		return nil, invalid("batch_too_large", "a batch has at most %d operations", MaxBatchOps)
	}
	g, err := e.writableGroup(id)
	if err != nil {
		return nil, err
	}
	res := &BatchResult{Items: make([]BatchItem, 0, len(ops))}
	for i, op := range ops {
		item := BatchItem{Index: i, Kind: op.Kind}
		err := error(nil)
		if authorize != nil {
			err = authorize(i, op)
		}
		if err == nil {
			err = e.batchOne(g.ID, op, atomic, &item)
		}
		if err != nil {
			if atomic {
				return nil, &OpError{Index: i, Err: err}
			}
			if !perOp(err) {
				return nil, err
			}
			item.Status, item.Effective, item.Op, item.Err = BatchFailed, "", nil, err
			res.Failed++
		} else {
			switch item.Status {
			case BatchCreated:
				res.Created++
			case BatchUpdated:
				res.Updated++
			case BatchRemoved:
				res.Removed++
			}
			if item.Op != nil {
				res.Ops = append(res.Ops, *item.Op)
			}
		}
		res.Items = append(res.Items, item)
	}
	if g, err = e.Group(g.ID); err != nil {
		return nil, err
	}
	res.Group = g
	detail := ojson.Object{{Key: "group_id", Value: string(g.ID)}, {Key: "name", Value: g.Name},
		{Key: "created", Value: int64(res.Created)}, {Key: "updated", Value: int64(res.Updated)},
		{Key: "removed", Value: int64(res.Removed)}, {Key: "failed", Value: int64(res.Failed)},
		{Key: "atomic", Value: atomic}, {Key: "queued", Value: int64(len(res.Ops))}}
	return res, e.audit("groups.member.batch", "group", string(g.ID), detail)
}

// batchOne applies one operation, to a savepoint of its own unless the batch is
// atomic (its failure undoes everything anyway).
func (e Env) batchOne(g store.GroupID, op BatchOp, atomic bool, item *BatchItem) (err error) {
	var sp *store.Savepoint
	if !atomic {
		if sp, err = e.Tx.Savepoint(); err != nil {
			return err
		}
		defer func() {
			switch {
			case err == nil:
				err = sp.Release()
			case perOp(err):
				if rerr := sp.Rollback(); rerr != nil {
					err = rerr
				}
			default:
				_ = sp.Rollback() // the request aborts; the original error stands
			}
		}()
	}
	switch op.Kind {
	case BatchAdd:
		in := MemberInput{Identity: op.Identity, Group: op.Group, EnabledFrom: op.EnabledFrom, DisabledAt: op.DisabledAt, Reason: op.Reason}
		switch {
		case op.Identity != nil:
			item.MemberType, item.Member = store.MemberIdentity, fmt.Sprint(*op.Identity)
		case op.Group != "":
			item.MemberType, item.Member = store.MemberGroup, string(op.Group)
		}
		r, err := e.AddMember(g, in)
		if err != nil {
			return err
		}
		item.Status = BatchUpdated
		if r.Created {
			item.Status = BatchCreated
		}
		item.setOutcome(r.Outcome)
	case BatchRemove:
		item.Member = op.Member
		if typ, _, ok := ParseMember(op.Member); ok {
			item.MemberType = typ
		}
		out, err := e.RemoveMember(g, op.Member)
		if err != nil {
			return err
		}
		item.Status = BatchRemoved
		item.setOutcome(out)
	default:
		return invalid("invalid_operation", "an operation is add or remove")
	}
	return nil
}

func (it *BatchItem) setOutcome(out Outcome) {
	it.Effective = "applied"
	if out.Queued {
		op := out.Op
		it.Effective, it.Op = "pending", &op
	}
}
