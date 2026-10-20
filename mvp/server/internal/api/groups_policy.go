package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/policygroups"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Policy groups as code (issue #52, GR-9; design docs/design/groups-grouper-parity.md
// §8). A policy group is defined by a Cedar file of the restricted fragment of
// §8.2; the compiler turns it into composite groups the membership engine already
// evaluates.
//
//	POST /api/groups/policy/validate   {files:[{path, cedar}]}                       check, write nothing
//	POST /api/groups/policy/diff       {files, full}                                 who would join and leave
//	POST /api/groups/policy/apply      {origin: repo|ui, commit, files, full}        apply as one change
//	POST /api/groups/policy/reindex                                                  bring attribute groups current
//	GET  /api/groups/{id}/policy                                                     the source of a policy group
//
// Privileges (on top of groups.read / groups.write): read on every group a
// policy refers to; apply also needs create on the folder of a new policy group
// and admin on one that exists (and on each group a full sync would retire);
// diff needs read on the policy groups it compares; reindex is groups.admin. A
// finding in a file is 422 {"error":"invalid_policy","diagnostics":[...]}; a
// cycle between policy groups is 409 cycle; a group the policy repository manages
// refuses the UI (and every other writer) with 409 policy_managed.
func (s *Server) registerGroupsPolicyRoutes() {
	G, P := http.MethodGet, http.MethodPost
	canRead, canWrite, admin := need(auth.PermGroupsRead), need(auth.PermGroupsWrite), need(auth.PermGroupsAdmin)
	s.handle(P, "/api/groups/policy/validate", read, canRead, s.rd(s.validateGrpPolicy))
	s.handle(P, "/api/groups/policy/diff", read, canRead, s.rd(s.diffGrpPolicy))
	s.handle(P, "/api/groups/policy/apply", write, canWrite, s.rd(s.applyGrpPolicy))
	s.handle(P, "/api/groups/policy/reindex", write, admin, s.rd(s.reindexGrpPolicy))
	s.handle(G, "/api/groups/{id}/policy", read, canRead, s.rd(s.getGrpPolicy))
}

type grpPolicyBody struct {
	Files  []policygroups.SourceFile `json:"files"`
	Origin string                    `json:"origin"`
	Commit string                    `json:"commit"`
	Full   bool                      `json:"full"`
}

// policyErr turns the findings of a refused change into the 422 answer.
func policyErr(err error) error {
	var ve *policygroups.ValidationError
	if errors.As(err, &ve) {
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_policy", Msg: ve.Error(),
			Extra: map[string]any{"diagnostics": ve.Diags}}
	}
	return err
}

func (s *Server) policyApplier(e model.Env) *policygroups.Applier {
	return &policygroups.Applier{Env: e, Schema: policygroups.DefaultSchema()}
}

// policyFiles decodes a body and parses its files. Findings are returned before
// any group is looked at, so a refusal never says which groups exist.
func policyFiles(r *http.Request) (*grpPolicyBody, []*policygroups.File, []policygroups.Diagnostic, error) {
	var in grpPolicyBody
	if err := decodeBody(r, &in, false); err != nil {
		return nil, nil, nil, err
	}
	fs, diags := policygroups.ParseAll(policygroups.DefaultSchema(), in.Files)
	return &in, fs, diags, nil
}

// groupHidden reports the groups the caller may not view. It fails closed: a
// group whose privilege cannot be checked counts as hidden.
func (s *Server) groupHidden(ck *privs.Checker) func(store.GroupID) bool {
	return func(id store.GroupID) bool {
		ok, err := ck.Has(privs.GroupObject(id), privs.View)
		return err != nil || !ok
	}
}

// requireOnDefined requires want on a group the files define. When the caller
// may not even view that group, the 403 leaves out its id (#387): the name was
// the caller's own input, and the group's UUID must not come back with it.
func (s *Server) requireOnDefined(ck *privs.Checker, id store.GroupID, want privs.Privilege) error {
	err := ck.Require(privs.GroupObject(id), want)
	if err == nil {
		return nil
	}
	var d *privs.DeniedError
	if errors.As(err, &d) && s.groupHidden(ck)(id) {
		return &readiness.Error{Status: http.StatusForbidden, Code: "privilege_required",
			Msg:   "the " + string(want) + " privilege is required on this group",
			Extra: map[string]any{"privilege": string(want), "object_type": string(d.Object.Type)}}
	}
	return grpErr(err)
}

// requireReadOnRefs requires read on every group the files refer to that exists,
// that the caller may view and that the change does not itself define. A group
// the caller may not view is skipped here and resolves as unknown (groupHidden),
// so neither the 403 nor its object_id tells that the name exists.
func (s *Server) requireReadOnRefs(r *http.Request, ck *privs.Checker, fs []*policygroups.File) error {
	tx := store.TxFrom(r.Context())
	batch := map[string]bool{}
	for _, f := range fs {
		batch[strings.ToLower(f.Group)] = true
	}
	var ids []store.GroupID
	for _, f := range fs {
		names, _ := f.Groups()
		for _, n := range names {
			if batch[n] {
				continue
			}
			id, ok, err := policygroups.FindGroup(tx, n)
			if err != nil {
				return err
			}
			if ok && !s.groupHidden(ck)(id) {
				ids = append(ids, id)
			}
		}
	}
	return s.requireReadOn(r, ck, ids)
}

func (s *Server) validateGrpPolicy(r *http.Request, _ *params) (int, any, error) {
	in, fs, diags, err := policyFiles(r)
	if err != nil {
		return 0, nil, err
	}
	if len(diags) > 0 {
		return http.StatusOK, policygroups.Validation{Groups: []string{}, References: []string{}, Diagnostics: diags}, nil
	}
	if err := s.requireReadOnRefs(r, s.grpChecker(r), fs); err != nil {
		return 0, nil, err
	}
	env := s.grpRead(r)
	env.GroupHidden = s.groupHidden(s.grpChecker(r))
	v, _, err := policygroups.Validate(env, policygroups.DefaultSchema(), in.Files)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, v, nil
}

func (s *Server) diffGrpPolicy(r *http.Request, _ *params) (int, any, error) {
	in, fs, diags, err := policyFiles(r)
	if err != nil {
		return 0, nil, err
	}
	if len(diags) > 0 {
		return 0, nil, policyErr(&policygroups.ValidationError{Diags: diags})
	}
	ck := s.grpChecker(r)
	tx := store.TxFrom(r.Context())
	for _, f := range fs { // the members of the groups compared are shown
		if g, err := tx.GrpGroupByName(f.Group); err == nil {
			if err := s.requireOnDefined(ck, g.ID, privs.Read); err != nil {
				return 0, nil, err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return 0, nil, err
		}
	}
	if err := s.requireReadOnRefs(r, ck, fs); err != nil {
		return 0, nil, err
	}
	if in.Full {
		if err := s.requireAdminOnRetired(r, ck, fs); err != nil {
			return 0, nil, err
		}
	}
	env := s.grpRead(r)
	env.GroupHidden = s.groupHidden(ck)
	d, err := s.policyApplier(env).Diff(in.Files, in.Full)
	if err != nil {
		return 0, nil, policyErr(err)
	}
	return http.StatusOK, d, nil
}

// requireAdminOnRetired requires read... on the repository's policy groups that a
// full change would retire: admin, as retiring a group is deleting it.
func (s *Server) requireAdminOnRetired(r *http.Request, ck *privs.Checker, fs []*policygroups.File) error {
	tx := store.TxFrom(r.Context())
	sources, err := tx.GrpPolicySources(store.PolicyOriginRepo)
	if err != nil {
		return err
	}
	for _, src := range sources {
		g, err := tx.GrpGroup(src.GroupID)
		if err != nil {
			return err
		}
		if g.Status == store.GroupDeleted || slices.ContainsFunc(fs, func(f *policygroups.File) bool { return naming.Equal(f.Group, g.Name) }) {
			continue
		}
		if err := ck.Require(privs.GroupObject(g.ID), privs.Admin); err != nil {
			return grpErr(err)
		}
	}
	return nil
}

// requireApply checks the privileges of an apply: create on the folder of each
// new policy group (the nearest folder that exists above it), admin on each that
// exists, then read on what the policies refer to.
func (s *Server) requireApply(r *http.Request, ck *privs.Checker, fs []*policygroups.File) error {
	tx := store.TxFrom(r.Context())
	for _, f := range fs {
		g, err := tx.GrpGroupByName(f.Group)
		switch {
		case err == nil:
			if err := s.requireOnDefined(ck, g.ID, privs.Admin); err != nil {
				return err
			}
			continue
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		parent := f.Group
		folder := ""
		for parent != "" {
			parent, _ = naming.Split(parent)
			if parent == "" {
				break
			}
			if fo, err := tx.GrpFolderByName(parent); err == nil {
				folder = string(fo.ID)
				break
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		if _, err := s.grpFolderOrRoot(r, ck, folder, privs.Create); err != nil {
			return err
		}
	}
	return s.requireReadOnRefs(r, ck, fs)
}

func (s *Server) applyGrpPolicy(r *http.Request, _ *params) (int, any, error) {
	in, fs, diags, err := policyFiles(r)
	if err != nil {
		return 0, nil, err
	}
	if len(diags) > 0 {
		return 0, nil, policyErr(&policygroups.ValidationError{Diags: diags})
	}
	if in.Origin == "" {
		in.Origin = store.PolicyOriginUI
	}
	ck := s.grpChecker(r)
	if err := s.requireApply(r, ck, fs); err != nil {
		return 0, nil, err
	}
	if in.Full {
		if err := s.requireAdminOnRetired(r, ck, fs); err != nil {
			return 0, nil, err
		}
	}
	var out *policygroups.ApplyResult
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		e.GroupHidden = s.groupHidden(ck)
		out, err = s.policyApplier(e).Apply(policygroups.ApplyInput{Origin: in.Origin, Commit: in.Commit, Files: in.Files, Full: in.Full})
		return err
	})
	if err != nil {
		return 0, nil, policyErr(err)
	}
	if out.Queued {
		return http.StatusAccepted, out, nil
	}
	return http.StatusOK, out, nil
}

func (s *Server) reindexGrpPolicy(r *http.Request, _ *params) (int, any, error) {
	var rep *policygroups.IndexReport
	err := s.grpWrite(r, func(e model.Env) error {
		e.System, e.Cause = true, store.CauseEngine
		var err error
		rep, err = policygroups.Indexer{Schema: policygroups.DefaultSchema()}.Reindex(e, nil)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, rep, nil
}

type grpPolicyView struct {
	GroupID        string  `json:"group_id"`
	Name           string  `json:"name"`
	Origin         string  `json:"origin"`
	Path           string  `json:"path"`
	Commit         string  `json:"commit"`
	Cedar          string  `json:"cedar"`
	CedarSHA256    string  `json:"cedar_sha256"`
	CompiledSHA256 string  `json:"compiled_sha256"`
	AppliedAt      string  `json:"applied_at"`
	AppliedBy      *string `json:"applied_by"`
}

func (s *Server) getGrpPolicy(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	g, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.Read)
	if err != nil {
		return 0, nil, err
	}
	src, err := store.TxFrom(r.Context()).GrpPolicySource(g.ID)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil, grpNotFound("policy")
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, grpPolicyView{GroupID: string(g.ID), Name: g.Name, Origin: src.Origin, Path: src.Path, Commit: src.CommitSHA,
		Cedar: src.Cedar, CedarSHA256: src.CedarSHA256, CompiledSHA256: src.CompiledSHA256, AppliedAt: store.RT(src.AppliedAt),
		AppliedBy: src.AppliedBy}, nil
}
