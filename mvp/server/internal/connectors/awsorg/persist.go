package awsorg

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// PersistInput names where a collection came from.
type PersistInput struct {
	Source         string // store.AWSSource*
	ConnectorID    string
	CatalogVersion string
}

type orgMeta struct {
	ManagementAccountID string `json:"management_account_id"`
	SCPEnabled          bool   `json:"scp_enabled"`
	RCPEnabled          bool   `json:"rcp_enabled"`
}

// Persist writes a collection to the aws_* tables of tx's tenant (design
// §6.2): the snapshot header, its policy documents (content-addressed, verbatim
// bytes), attachments, organization nodes, the rest of the snapshot as JSON
// entities, and the findings. The snapshot id is the content hash, so
// persisting an unchanged estate again writes nothing and reports
// created = false. The caller commits the audit event in the same transaction.
func Persist(tx *store.TenantTx, col *Collection, in PersistInput) (created bool, err error) {
	s := col.Snapshot
	if s == nil || s.ID == "" {
		return false, fmt.Errorf("awsorg: collection has no snapshot id")
	}
	hdr := &store.AWSSnapshot{ID: s.ID, TakenAt: s.TakenAt, AccountIDs: col.AccountIDs, CatalogVersion: in.CatalogVersion,
		Source: in.Source, ConnectorID: in.ConnectorID}
	if s.Org != nil {
		hdr.OrgID = s.Org.OrgID
	}
	if created, err = tx.PutAWSSnapshot(hdr); err != nil || !created {
		return false, err
	}

	for _, id := range sortedKeys(s.Policies) {
		d := s.Policies[id]
		norm := *d
		norm.RawJSON = nil // the verbatim bytes have their own column
		nb, err := json.Marshal(&norm)
		if err != nil {
			return false, fmt.Errorf("awsorg: policy %s: %w", d.SourceARN, err)
		}
		if err := tx.PutAWSPolicyDocument(&store.AWSPolicyDocument{ID: d.ID, Kind: d.Kind.String(), SourceARN: d.SourceARN,
			VersionID: d.VersionID, RawJSON: d.RawJSON, Normalized: nb, FetchedAt: d.FetchedAt}); err != nil {
			return false, err
		}
	}
	for _, a := range s.Attachments {
		if err := tx.AddAWSAttachment(&store.AWSAttachment{SnapshotID: s.ID, PolicyID: a.PolicyID, TargetARN: a.TargetARN,
			AttachmentType: a.AttachmentType.String(), Via: a.Via}); err != nil {
			return false, err
		}
	}
	if s.Org != nil {
		for _, id := range sortedKeys(s.Org.Nodes) {
			n := s.Org.Nodes[id]
			if err := tx.AddAWSOrgNode(&store.AWSOrgNode{SnapshotID: s.ID, ID: n.ID, Kind: n.Kind.String(), ParentID: n.ParentID, Name: n.Name}); err != nil {
				return false, err
			}
		}
		if err := putEntity(tx, s.ID, store.AWSEntityOrg, s.Org.OrgID,
			orgMeta{s.Org.ManagementAccountID, s.Org.SCPEnabled, s.Org.RCPEnabled}); err != nil {
			return false, err
		}
	}
	if err := putEntities(tx, s.ID, store.AWSEntityPrincipal, s.Principals); err != nil {
		return false, err
	}
	if err := putEntities(tx, s.ID, store.AWSEntityResource, s.Resources); err != nil {
		return false, err
	}
	if err := putEntities(tx, s.ID, store.AWSEntityResourcePolicy, s.ResourcePolicies); err != nil {
		return false, err
	}
	if err := putEntities(tx, s.ID, store.AWSEntityKMSGrant, s.KMSGrants); err != nil {
		return false, err
	}
	if err := putEntities(tx, s.ID, store.AWSEntityS3Bucket, s.S3); err != nil {
		return false, err
	}
	if err := putEntities(tx, s.ID, store.AWSEntityVPCEPolicy, s.VPCEPolicies); err != nil {
		return false, err
	}
	if err := putEntities(tx, s.ID, store.AWSEntityCanonicalID, s.CanonicalIDs); err != nil {
		return false, err
	}
	for _, a := range col.IdentityCenter {
		if err := putEntity(tx, s.ID, store.AWSEntityIdentityCenter, a.AccountID+"|"+a.PermissionSetARN+"|"+a.PrincipalID, a); err != nil {
			return false, err
		}
	}
	rows, err := col.Findings.storeRows(s.ID)
	if err != nil {
		return false, err
	}
	for _, f := range rows {
		if err := tx.AddAWSFinding(f); err != nil {
			return false, err
		}
	}
	return true, nil
}

func putEntity(tx *store.TenantTx, snapshotID, kind, key string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.AddAWSEntity(&store.AWSEntity{SnapshotID: snapshotID, Kind: kind, Key: key, Body: body})
}

func putEntities[V any](tx *store.TenantTx, snapshotID, kind string, m map[string]V) error {
	for _, k := range sortedKeys(m) {
		if err := putEntity(tx, snapshotID, kind, k, m[k]); err != nil {
			return err
		}
	}
	return nil
}

func loadEntities[V any](tx *store.TenantTx, snapshotID, kind string, into map[string]V) error {
	es, err := tx.AWSEntities(snapshotID, kind)
	if err != nil {
		return err
	}
	for _, e := range es {
		var v V
		if err := json.Unmarshal(e.Body, &v); err != nil {
			return fmt.Errorf("awsorg: snapshot %s %s %s: %w", snapshotID, kind, e.Key, err)
		}
		into[e.Key] = v
	}
	return nil
}

// Load rebuilds a persisted collection. Policy documents are parsed again from
// their verbatim bytes, so what is evaluated is what AWS returned. The result
// has the stored snapshot id: Load(Persist(c)) has the content hash of c.
func Load(tx *store.TenantTx, snapshotID string) (*Collection, error) {
	hdr, err := tx.AWSSnapshot(snapshotID)
	if err != nil {
		return nil, err
	}
	b := newBuilder(hdr.TakenAt)
	s := b.snap
	s.ID, s.TakenAt = hdr.ID, hdr.TakenAt

	atts, err := tx.AWSAttachments(snapshotID)
	if err != nil {
		return nil, err
	}
	docIDs := map[string]bool{}
	for _, a := range atts {
		var typ model.AttachmentType
		if err := typ.UnmarshalText([]byte(a.AttachmentType)); err != nil {
			return nil, err
		}
		via := a.Via
		if len(via) == 0 {
			via = nil // the collector leaves an empty provenance path nil
		}
		s.Attachments = append(s.Attachments, model.PolicyAttachment{PolicyID: a.PolicyID, TargetARN: a.TargetARN, Via: via, AttachmentType: typ})
		docIDs[a.PolicyID] = true
	}
	// documents: those attached, and those only a snapshot entity names
	rps := map[string][]model.ResourcePolicy{}
	if err := loadEntities(tx, snapshotID, store.AWSEntityResourcePolicy, rps); err != nil {
		return nil, err
	}
	vpce := map[string]string{}
	if err := loadEntities(tx, snapshotID, store.AWSEntityVPCEPolicy, vpce); err != nil {
		return nil, err
	}
	pr := map[string]*model.Principal{}
	if err := loadEntities(tx, snapshotID, store.AWSEntityPrincipal, pr); err != nil {
		return nil, err
	}
	for _, v := range rps {
		for _, rp := range v {
			docIDs[rp.PolicyID] = true
		}
	}
	for _, id := range vpce {
		docIDs[id] = true
	}
	for _, p := range pr {
		for _, id := range append(slices.Clone(p.IdentityPolicyIDs), p.BoundaryPolicyID) {
			if id != "" {
				docIDs[id] = true
			}
		}
	}
	for _, id := range sortedKeys(docIDs) {
		d, err := tx.AWSPolicyDocument(id)
		if err != nil {
			return nil, fmt.Errorf("awsorg: snapshot %s: policy %s: %w", snapshotID, id, err)
		}
		var kind model.PolicyKind
		if err := kind.UnmarshalText([]byte(d.Kind)); err != nil {
			return nil, err
		}
		var meta struct {
			AWSManaged bool `json:"aws_managed"`
		}
		if err := json.Unmarshal(d.Normalized, &meta); err != nil {
			return nil, err
		}
		res, err := policy.Parse(d.RawJSON, policy.Options{Kind: kind, SourceARN: d.SourceARN, VersionID: d.VersionID,
			AWSManaged: meta.AWSManaged, FetchedAt: d.FetchedAt})
		if err != nil {
			return nil, fmt.Errorf("awsorg: stored policy %s no longer parses: %w", d.SourceARN, err)
		}
		if res.Doc.ID != d.ID {
			return nil, fmt.Errorf("awsorg: stored policy %s has id %s, its bytes hash to %s", d.SourceARN, d.ID, res.Doc.ID)
		}
		s.Policies[d.ID] = res.Doc
	}

	s.Principals, s.ResourcePolicies, s.VPCEPolicies = pr, rps, vpce
	if err := loadEntities(tx, snapshotID, store.AWSEntityResource, s.Resources); err != nil {
		return nil, err
	}
	if err := loadEntities(tx, snapshotID, store.AWSEntityKMSGrant, s.KMSGrants); err != nil {
		return nil, err
	}
	if err := loadEntities(tx, snapshotID, store.AWSEntityS3Bucket, s.S3); err != nil {
		return nil, err
	}
	if err := loadEntities(tx, snapshotID, store.AWSEntityCanonicalID, s.CanonicalIDs); err != nil {
		return nil, err
	}

	nodes, err := tx.AWSOrgNodes(snapshotID)
	if err != nil {
		return nil, err
	}
	if len(nodes) > 0 {
		meta := map[string]orgMeta{}
		if err := loadEntities(tx, snapshotID, store.AWSEntityOrg, meta); err != nil {
			return nil, err
		}
		org := &model.Organization{OrgID: hdr.OrgID, Nodes: map[string]*model.OrgNode{}}
		if m, ok := meta[hdr.OrgID]; ok {
			org.ManagementAccountID, org.SCPEnabled, org.RCPEnabled = m.ManagementAccountID, m.SCPEnabled, m.RCPEnabled
		}
		for _, n := range nodes {
			var kind model.OrgNodeKind
			if err := kind.UnmarshalText([]byte(n.Kind)); err != nil {
				return nil, err
			}
			org.Nodes[n.ID] = &model.OrgNode{ID: n.ID, Kind: kind, ParentID: n.ParentID, Name: n.Name}
		}
		for _, a := range s.Attachments {
			if n := org.Nodes[a.TargetARN]; n != nil {
				switch a.AttachmentType {
				case model.AttachSCP:
					n.SCPIDs = append(n.SCPIDs, a.PolicyID)
				case model.AttachRCP:
					n.RCPIDs = append(n.RCPIDs, a.PolicyID)
				}
			}
		}
		for _, n := range org.Nodes {
			slices.Sort(n.SCPIDs)
			slices.Sort(n.RCPIDs)
		}
		s.Org = org
	}

	col := &Collection{Snapshot: s, AccountIDs: hdr.AccountIDs}
	ic, err := tx.AWSEntities(snapshotID, store.AWSEntityIdentityCenter)
	if err != nil {
		return nil, err
	}
	for _, e := range ic {
		var a SSOAssignment
		if err := json.Unmarshal(e.Body, &a); err != nil {
			return nil, err
		}
		col.IdentityCenter = append(col.IdentityCenter, a)
	}
	fs, err := tx.AWSFindings(snapshotID)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		x := Finding{Kind: f.Kind, SourceARN: f.SourceARN, PolicyKind: f.PolicyKind, Code: f.Code, Detail: f.Detail}
		if err := json.Unmarshal(f.Scope, &x.Scope); err != nil {
			return nil, err
		}
		col.Findings = append(col.Findings, x)
	}
	return col, nil
}
