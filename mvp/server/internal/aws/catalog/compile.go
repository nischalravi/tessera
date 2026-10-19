package catalog

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// SchemaVersion is the compiled artifact format version.
const SchemaVersion = 1

// Limits on upstream and overlay data, which are untrusted (a snapshot is
// fetched from the network and reviewed by humans only as a diff).
const (
	maxServices         = 2000
	maxActionsPerSvc    = 20000
	maxKeysPerAction    = 1000
	maxResourcesPerSvc  = 5000
	maxNameLen          = 256
	maxFormatLen        = 1024
	maxOverlayBytes     = 1 << 20
	maxSnapshotFile     = 32 << 20
	maxCompiledBytes    = 64 << 20  // compressed
	maxCompiledExpanded = 256 << 20 // decompressed
)

// ---------------------------------------------------------------- overlays

// Overlays is the curated, reviewed data in catalog/aws/overlays/*.yaml. It is
// compiled into the artifact so the server needs only the compiled file.
type Overlays struct {
	RCP         RCPServices       `json:"rcp_services"`
	KMSXacct    KMSXacctOps       `json:"kms_xacct_ops"`
	GlobalKeys  GlobalKeys        `json:"global_keys"`
	S3ACL       S3ACLMap          `json:"s3_acl_map"`
	RBP         RBPRules          `json:"rbp_rules"`
	OptInRegion OptInRegions      `json:"opt_in_regions"`
	S3Public    S3PublicFixedKeys `json:"s3_public_fixed_keys"`
}

// RCPServices lists the service prefixes RCPs apply to (design §10.3).
type RCPServices struct {
	Source    string   `json:"source" yaml:"source"`
	FetchedOn string   `json:"fetched_on" yaml:"fetched_on"`
	Services  []string `json:"services" yaml:"services"`
}

// KMSXacctOps lists the KMS actions that work across accounts.
type KMSXacctOps struct {
	Source  string   `json:"source" yaml:"source"`
	Actions []string `json:"actions" yaml:"actions"`
}

// GlobalKey is one global condition key.
type GlobalKey struct {
	Name         string        `json:"name" yaml:"name"`
	Type         model.KeyType `json:"type" yaml:"type"`
	Multivalued  bool          `json:"multivalued,omitempty" yaml:"multivalued"`
	Availability string        `json:"availability" yaml:"availability"`
}

// GlobalKeys is the global-key availability table (§9.2).
type GlobalKeys struct {
	Source string      `json:"source" yaml:"source"`
	Keys   []GlobalKey `json:"keys" yaml:"keys"`
}

// S3ACLGroup is a predefined S3 ACL grantee group.
type S3ACLGroup struct {
	Name   string `json:"name" yaml:"name"`
	URI    string `json:"uri" yaml:"uri"`
	Public bool   `json:"public" yaml:"public"`
}

// S3ACLMap maps ACL permissions to the actions they grant.
type S3ACLMap struct {
	Source string              `json:"source" yaml:"source"`
	Bucket map[string][]string `json:"bucket" yaml:"bucket"`
	Object map[string][]string `json:"object" yaml:"object"`
	Groups []S3ACLGroup        `json:"groups" yaml:"groups"`
}

// RBPRule says a service's resource policy must explicitly allow even for a
// same-account principal (§7.4.3).
type RBPRule struct {
	Service               string `json:"service" yaml:"service"`
	Resource              string `json:"resource" yaml:"resource"`
	RequiresExplicitAllow bool   `json:"requires_explicit_allow" yaml:"requires_explicit_allow"`
	Verified              bool   `json:"verified" yaml:"verified"`
	Source                string `json:"source" yaml:"source"`
	Note                  string `json:"note,omitempty" yaml:"note"`
}

// RBPRules is the explicit-allow table.
type RBPRules struct {
	Default string    `json:"default" yaml:"default"`
	Rules   []RBPRule `json:"rules" yaml:"rules"`
}

// OptInRegion is an opt-in region.
type OptInRegion struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

// OptInRegions lists the regions whose service principals are regionalized.
type OptInRegions struct {
	Source          string        `json:"source" yaml:"source"`
	PrincipalFormat string        `json:"principal_format" yaml:"principal_format"`
	Regions         []OptInRegion `json:"regions" yaml:"regions"`
}

// S3PublicKey is a key that, pinned to a fixed value, makes a statement non-public.
type S3PublicKey struct {
	Name               string   `json:"name" yaml:"name"`
	Rule               string   `json:"rule" yaml:"rule"`
	ExceptPatterns     []string `json:"except_patterns,omitempty" yaml:"except_patterns"`
	IPv4MaxCIDRSize    int      `json:"ipv4_max_cidr_size,omitempty" yaml:"ipv4_max_cidr_size"`
	IPv6MaxCIDRSize    int      `json:"ipv6_max_cidr_size,omitempty" yaml:"ipv6_max_cidr_size"`
	BucketPoliciesOnly bool     `json:"bucket_policies_only,omitempty" yaml:"bucket_policies_only"`
}

// S3PublicFixedKeys is the S3 "public" fixed-value key list.
type S3PublicFixedKeys struct {
	Source string        `json:"source" yaml:"source"`
	Keys   []S3PublicKey `json:"keys" yaml:"keys"`
}

// overlay file names under <dir>/overlays.
const (
	fileRCP      = "rcp_services.yaml"
	fileKMS      = "kms_xacct_ops.yaml"
	fileGlobal   = "global_keys.yaml"
	fileS3ACL    = "s3_acl_map.yaml"
	fileRBP      = "rbp_rules.yaml"
	fileOptIn    = "opt_in_regions.yaml"
	fileS3Public = "s3_public_fixed_keys.yaml"
)

var availabilities = map[string]bool{
	"always": true, "principal": true, "session": true,
	"resource": true, "network": true, "conditional": true,
}

// LoadOverlays reads and validates the overlay files in dir (the overlays
// directory itself). Unknown fields are errors. Lists come back sorted.
func LoadOverlays(dir string) (*Overlays, error) {
	var o Overlays
	for _, f := range []struct {
		name string
		into any
	}{
		{fileRCP, &o.RCP}, {fileKMS, &o.KMSXacct}, {fileGlobal, &o.GlobalKeys}, {fileS3ACL, &o.S3ACL},
		{fileRBP, &o.RBP}, {fileOptIn, &o.OptInRegion}, {fileS3Public, &o.S3Public},
	} {
		raw, err := readCapped(filepath.Join(dir, f.name), maxOverlayBytes)
		if err != nil {
			return nil, fmt.Errorf("catalog: overlay %s: %w", f.name, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(f.into); err != nil {
			return nil, fmt.Errorf("catalog: overlay %s: %w", f.name, err)
		}
	}
	if err := o.normalize(); err != nil {
		return nil, err
	}
	return &o, nil
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path is built from the operator-supplied catalog directory and fixed names
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b, nil
}

func validPrefix(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validActionName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// validResourceName accepts the names AWS gives resource types, which are
// free text ("function alias", "loadbalancer/app/"): printable, no control
// characters, at most 128 bytes, valid UTF-8.
func validResourceName(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// validFullAction checks "<prefix>:<Action>".
func validFullAction(s string) bool {
	i := strings.IndexByte(s, ':')
	return i > 0 && validPrefix(s[:i]) && validActionName(s[i+1:])
}

func sortedUnique(in []string, check func(string) bool, what string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !check(s) {
			return nil, fmt.Errorf("catalog: invalid %s %q", what, s)
		}
		if seen[s] {
			return nil, fmt.Errorf("catalog: duplicate %s %q", what, s)
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func (o *Overlays) normalize() error {
	var err error
	if o.RCP.Services, err = sortedUnique(o.RCP.Services, validPrefix, "RCP service prefix"); err != nil {
		return err
	}
	if len(o.RCP.Services) == 0 {
		return errors.New("catalog: rcp_services overlay is empty")
	}
	if o.KMSXacct.Actions, err = sortedUnique(o.KMSXacct.Actions, validFullAction, "KMS action"); err != nil {
		return err
	}
	for _, a := range o.KMSXacct.Actions {
		if !strings.HasPrefix(a, "kms:") {
			return fmt.Errorf("catalog: kms_xacct_ops action %q is not a kms action", a)
		}
	}
	seen := map[string]bool{}
	for i, k := range o.GlobalKeys.Keys {
		n := normKey(k.Name)
		if k.Name == "" || !strings.HasPrefix(n, "aws:") || seen[n] {
			return fmt.Errorf("catalog: global_keys: bad or duplicate key %q", k.Name)
		}
		seen[n] = true
		if k.Type == 0 {
			return fmt.Errorf("catalog: global_keys: key %q has no type", k.Name)
		}
		if !availabilities[k.Availability] {
			return fmt.Errorf("catalog: global_keys: key %q has unknown availability %q", k.Name, k.Availability)
		}
		o.GlobalKeys.Keys[i] = k
	}
	sort.Slice(o.GlobalKeys.Keys, func(i, j int) bool {
		return normKey(o.GlobalKeys.Keys[i].Name) < normKey(o.GlobalKeys.Keys[j].Name)
	})
	for _, m := range []map[string][]string{o.S3ACL.Bucket, o.S3ACL.Object} {
		for perm, acts := range m {
			if acts, err = sortedUnique(acts, validFullAction, "S3 ACL action"); err != nil {
				return err
			}
			m[perm] = acts
		}
	}
	if len(o.S3ACL.Bucket) == 0 || len(o.S3ACL.Object) == 0 {
		return errors.New("catalog: s3_acl_map needs bucket and object permissions")
	}
	sort.Slice(o.S3ACL.Groups, func(i, j int) bool { return o.S3ACL.Groups[i].Name < o.S3ACL.Groups[j].Name })
	if o.RBP.Default != "union" {
		return fmt.Errorf("catalog: rbp_rules default must be %q, got %q", "union", o.RBP.Default)
	}
	seen = map[string]bool{}
	for _, r := range o.RBP.Rules {
		if !validPrefix(r.Service) || r.Resource == "" || r.Source == "" || seen[r.Service+"/"+r.Resource] {
			return fmt.Errorf("catalog: rbp_rules: bad or duplicate rule for %q (each rule needs a service, a resource and a source)", r.Service)
		}
		seen[r.Service+"/"+r.Resource] = true
	}
	sort.Slice(o.RBP.Rules, func(i, j int) bool {
		a, b := o.RBP.Rules[i], o.RBP.Rules[j]
		return a.Service < b.Service || (a.Service == b.Service && a.Resource < b.Resource)
	})
	if !strings.Contains(o.OptInRegion.PrincipalFormat, "{service}") || !strings.Contains(o.OptInRegion.PrincipalFormat, "{region}") {
		return errors.New("catalog: opt_in_regions principal_format needs {service} and {region}")
	}
	seen = map[string]bool{}
	for _, r := range o.OptInRegion.Regions {
		if !validPrefix(r.Name) || seen[r.Name] {
			return fmt.Errorf("catalog: opt_in_regions: bad or duplicate region %q", r.Name)
		}
		seen[r.Name] = true
	}
	sort.Slice(o.OptInRegion.Regions, func(i, j int) bool { return o.OptInRegion.Regions[i].Name < o.OptInRegion.Regions[j].Name })
	seen = map[string]bool{}
	for _, k := range o.S3Public.Keys {
		n := asciiLower(k.Name)
		if k.Name == "" || seen[n] || (k.Rule != "fixed_value" && k.Rule != "ip_range") {
			return fmt.Errorf("catalog: s3_public_fixed_keys: bad or duplicate key %q", k.Name)
		}
		seen[n] = true
	}
	sort.Slice(o.S3Public.Keys, func(i, j int) bool {
		return asciiLower(o.S3Public.Keys[i].Name) < asciiLower(o.S3Public.Keys[j].Name)
	})
	return nil
}

// ---------------------------------------------------------------- snapshot

// Manifest records the SHA-256 of every file of a snapshot. `catalog compile`
// verifies it, so a snapshot edited or damaged after the fetch is refused.
type Manifest struct {
	Snapshot string            `json:"snapshot"`
	Source   string            `json:"source"`
	Files    map[string]string `json:"files"`
}

// DatasetPin is the reviewed pin of the iam-dataset input (iam-dataset.lock).
type DatasetPin struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// DatasetAction is the part of iam-dataset the catalog uses for one action.
type DatasetAction struct {
	Action      string   `json:"action"`
	AccessLevel string   `json:"access_level,omitempty"`
	Dependent   []string `json:"dependent,omitempty"`
}

// DatasetExtract is the condensed iam-dataset input stored in a snapshot.
type DatasetExtract struct {
	Commit        string          `json:"commit"`
	UpstreamSHA   string          `json:"upstream_sha256"`
	Actions       []DatasetAction `json:"actions"`
	actionByLower map[string]*DatasetAction
}

// RCPScrape is the RCP service list as published on the Organizations page
// on the day of the fetch.
type RCPScrape struct {
	Source    string   `json:"source"`
	FetchedOn string   `json:"fetched_on"`
	Services  []string `json:"services"`
}

// Snapshot is a verified, in-memory snapshot.
type Snapshot struct {
	Date     string
	Index    []string          // service prefixes, sorted
	Services map[string][]byte // verbatim Service Reference files
	Dataset  *DatasetExtract   // nil if the snapshot has none
	RCPPage  *RCPScrape        // nil if the snapshot has none
}

// Snapshot file names (relative to snapshots/<date>/).
const (
	snapIndex    = "index.json"
	snapManifest = "MANIFEST.json"
	snapDataset  = "iam-dataset-extract.json"
	snapRCP      = "rcp_services.json"
	snapServices = "services"
)

func validDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, c := range []byte(s) {
		if i != 4 && i != 7 && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ReadSnapshot reads snapshots/<date> under dir and verifies it against its
// manifest: every listed file must match its digest, and no file may be
// present that the manifest does not list.
func ReadSnapshot(dir, date string) (*Snapshot, error) {
	if !validDate(date) {
		return nil, fmt.Errorf("catalog: invalid snapshot date %q (want YYYY-MM-DD)", date)
	}
	root := filepath.Join(dir, "snapshots", date)
	raw, err := readCapped(filepath.Join(root, snapManifest), maxSnapshotFile)
	if err != nil {
		return nil, fmt.Errorf("catalog: snapshot %s: %w", date, err)
	}
	var man Manifest
	if err := strictUnmarshal(raw, &man); err != nil {
		return nil, fmt.Errorf("catalog: snapshot %s manifest: %w", date, err)
	}
	if man.Snapshot != date {
		return nil, fmt.Errorf("catalog: snapshot %s manifest names snapshot %q", date, man.Snapshot)
	}
	// every file under the snapshot must be listed
	var found []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel != snapManifest {
			found = append(found, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("catalog: snapshot %s: %w", date, err)
	}
	sort.Strings(found)
	listed := make([]string, 0, len(man.Files))
	for f := range man.Files {
		listed = append(listed, f)
	}
	sort.Strings(listed)
	if !equalStrings(found, listed) {
		return nil, fmt.Errorf("catalog: snapshot %s: files on disk differ from the manifest", date)
	}
	files := make(map[string][]byte, len(listed))
	for _, f := range listed {
		if !safeRel(f) {
			return nil, fmt.Errorf("catalog: snapshot %s: unsafe path %q in manifest", date, f)
		}
		b, err := readCapped(filepath.Join(root, filepath.FromSlash(f)), maxSnapshotFile)
		if err != nil {
			return nil, fmt.Errorf("catalog: snapshot %s: %s: %w", date, f, err)
		}
		if sha256Hex(b) != man.Files[f] {
			return nil, fmt.Errorf("catalog: snapshot %s: %s does not match its manifest digest", date, f)
		}
		files[f] = b
	}
	s := &Snapshot{Date: date, Services: map[string][]byte{}}
	idx, ok := files[snapIndex]
	if !ok {
		return nil, fmt.Errorf("catalog: snapshot %s has no %s", date, snapIndex)
	}
	if s.Index, err = parseIndex(idx); err != nil {
		return nil, fmt.Errorf("catalog: snapshot %s: %w", date, err)
	}
	for _, svc := range s.Index {
		b, ok := files[snapServices+"/"+svc+".json"]
		if !ok {
			return nil, fmt.Errorf("catalog: snapshot %s: index lists %q but the file is missing", date, svc)
		}
		s.Services[svc] = b
	}
	if len(s.Services) != len(files)-countPresent(files, snapIndex, snapDataset, snapRCP) {
		return nil, fmt.Errorf("catalog: snapshot %s has service files the index does not list", date)
	}
	if b, ok := files[snapDataset]; ok {
		s.Dataset = &DatasetExtract{}
		if err := strictUnmarshal(b, s.Dataset); err != nil {
			return nil, fmt.Errorf("catalog: snapshot %s %s: %w", date, snapDataset, err)
		}
		s.Dataset.index()
	}
	if b, ok := files[snapRCP]; ok {
		s.RCPPage = &RCPScrape{}
		if err := strictUnmarshal(b, s.RCPPage); err != nil {
			return nil, fmt.Errorf("catalog: snapshot %s %s: %w", date, snapRCP, err)
		}
	}
	return s, nil
}

func countPresent(m map[string][]byte, names ...string) int {
	n := 0
	for _, k := range names {
		if _, ok := m[k]; ok {
			n++
		}
	}
	return n
}

func (d *DatasetExtract) index() {
	d.actionByLower = make(map[string]*DatasetAction, len(d.Actions))
	for i := range d.Actions {
		d.actionByLower[asciiLower(d.Actions[i].Action)] = &d.Actions[i]
	}
}

func safeRel(f string) bool {
	return f != "" && !strings.HasPrefix(f, "/") && !strings.Contains(f, "..") && !strings.Contains(f, "\\")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// strictUnmarshal decodes one JSON value, rejecting unknown fields and trailing data.
func strictUnmarshal(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

type indexEntry struct {
	Service string `json:"service"`
}

// parseIndex reads the Service Reference index and returns the sorted,
// de-duplicated service prefixes. Names that are not plain prefixes are an
// error: they become file names and URL parts.
func parseIndex(raw []byte) ([]string, error) {
	var entries []indexEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if len(entries) == 0 || len(entries) > maxServices {
		return nil, fmt.Errorf("index: %d services (want 1 to %d)", len(entries), maxServices)
	}
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !validPrefix(e.Service) {
			return nil, fmt.Errorf("index: invalid service name %q", e.Service)
		}
		if seen[e.Service] {
			continue
		}
		seen[e.Service] = true
		out = append(out, e.Service)
	}
	sort.Strings(out)
	return out, nil
}

// ---------------------------------------------------------------- Service Reference parsing

type srProps struct {
	IsList                 bool `json:"IsList"`
	IsPermissionManagement bool `json:"IsPermissionManagement"`
	IsTaggingOnly          bool `json:"IsTaggingOnly"`
	IsWrite                bool `json:"IsWrite"`
}

type srAction struct {
	Name                string   `json:"Name"`
	ActionConditionKeys []string `json:"ActionConditionKeys"`
	Annotations         *struct {
		Properties *srProps `json:"Properties"`
	} `json:"Annotations"`
	Resources []struct {
		Name string `json:"Name"`
	} `json:"Resources"`
}

type srKey struct {
	Name  string   `json:"Name"`
	Types []string `json:"Types"`
}

type srResource struct {
	Name          string   `json:"Name"`
	ARNFormats    []string `json:"ARNFormats"`
	ConditionKeys []string `json:"ConditionKeys"`
}

type srService struct {
	Name          string       `json:"Name"`
	Version       string       `json:"Version"`
	Actions       []srAction   `json:"Actions"`
	ConditionKeys []srKey      `json:"ConditionKeys"`
	Resources     []srResource `json:"Resources"`
}

// ---------------------------------------------------------------- compiled form

// Compiled is the catalog artifact. Everything in it is sorted, so its
// canonical JSON is a pure function of the inputs.
type Compiled struct {
	Schema           int        `json:"schema"`
	Snapshot         string     `json:"snapshot"`
	IAMDatasetCommit string     `json:"iam_dataset_commit,omitempty"`
	Version          string     `json:"catalog_version"`
	Services         []CService `json:"services"`
	Keys             []CKey     `json:"condition_keys"`
	Overlays         Overlays   `json:"overlays"`
}

// CService is one service's actions and resource types.
type CService struct {
	Prefix    string      `json:"prefix"`
	Version   string      `json:"version,omitempty"`
	Actions   []CAction   `json:"actions"`
	Resources []CResource `json:"resources,omitempty"`
}

// CAction is one action.
type CAction struct {
	Name      string      `json:"name"`
	Level     AccessLevel `json:"level"`
	Keys      []string    `json:"keys,omitempty"`
	Resources []string    `json:"resources,omitempty"`
	Dependent []string    `json:"dependent,omitempty"`
}

// CResource is one resource type of a service.
type CResource struct {
	Name       string   `json:"name"`
	ARNFormats []string `json:"arn_formats,omitempty"`
	Keys       []string `json:"keys,omitempty"`
}

// CKey is one condition key.
type CKey struct {
	Name        string        `json:"name"`
	Type        model.KeyType `json:"type"`
	Multivalued bool          `json:"multivalued,omitempty"`
}

// Result is what Compile returns besides the artifact.
type Result struct {
	Compiled *Compiled
	// Warnings lists upstream entries that were skipped or reconciled, sorted.
	Warnings []string
	// RCPDrift compares the overlay with the RCP page scraped into the snapshot.
	RCPDrift RCPDrift
}

// RCPDrift is the difference between the live RCP page and the overlay.
type RCPDrift struct {
	PageOnly    []string `json:"page_only"`    // on the page, not in the overlay
	OverlayOnly []string `json:"overlay_only"` // in the overlay, not on the page
}

// Compile builds the catalog from a verified snapshot and the overlays. It
// reads no clock and no environment: equal inputs give equal bytes.
func Compile(snap *Snapshot, ov *Overlays) (*Result, error) {
	if snap == nil || ov == nil {
		return nil, errors.New("catalog: Compile needs a snapshot and overlays")
	}
	var warns []string
	warn := func(f string, a ...any) { warns = append(warns, fmt.Sprintf(f, a...)) }

	c := &Compiled{Schema: SchemaVersion, Snapshot: snap.Date, Overlays: *ov}
	if snap.Dataset != nil {
		c.IAMDatasetCommit = snap.Dataset.Commit
	}
	type keySrc struct {
		k   CKey
		svc string
	}
	keys := map[string]keySrc{}
	// the order of the snapshot's index must not matter
	index := append([]string(nil), snap.Index...)
	sort.Strings(index)
	index = dedupe(index)
	for _, prefix := range index {
		var sr srService
		if err := json.Unmarshal(snap.Services[prefix], &sr); err != nil {
			return nil, fmt.Errorf("catalog: service %s: %w", prefix, err)
		}
		if sr.Name != "" && sr.Name != prefix {
			warn("service %s: file names itself %q", prefix, sr.Name)
		}
		if len(sr.Actions) > maxActionsPerSvc || len(sr.Resources) > maxResourcesPerSvc || len(sr.ConditionKeys) > maxActionsPerSvc {
			return nil, fmt.Errorf("catalog: service %s exceeds the size limits", prefix)
		}
		cs := CService{Prefix: prefix, Version: clip(sr.Version, 64)}
		for _, r := range sr.Resources {
			if !validResourceName(r.Name) {
				warn("service %s: skipped resource type %q", prefix, clip(r.Name, 64))
				continue
			}
			cr := CResource{Name: r.Name, Keys: cleanKeys(r.ConditionKeys)}
			for _, f := range r.ARNFormats {
				if len(f) > maxFormatLen || !strings.HasPrefix(f, "arn:") {
					warn("service %s: resource %s: skipped ARN format %q", prefix, r.Name, clip(f, 64))
					continue
				}
				cr.ARNFormats = append(cr.ARNFormats, f)
			}
			sort.Strings(cr.ARNFormats)
			cs.Resources = append(cs.Resources, cr)
		}
		sort.Slice(cs.Resources, func(i, j int) bool { return cs.Resources[i].Name < cs.Resources[j].Name })
		seenAct := map[string]bool{}
		for _, a := range sr.Actions {
			if !validActionName(a.Name) {
				warn("service %s: skipped action %q", prefix, clip(a.Name, 64))
				continue
			}
			full := prefix + ":" + a.Name
			low := asciiLower(full)
			if seenAct[low] {
				warn("service %s: duplicate action %s", prefix, a.Name)
				continue
			}
			seenAct[low] = true
			if len(a.ActionConditionKeys) > maxKeysPerAction {
				return nil, fmt.Errorf("catalog: action %s lists too many condition keys", full)
			}
			ca := CAction{Name: full, Keys: cleanKeys(a.ActionConditionKeys)}
			for _, r := range a.Resources {
				if validResourceName(r.Name) {
					ca.Resources = append(ca.Resources, r.Name)
				}
			}
			sort.Strings(ca.Resources)
			ca.Resources = dedupe(ca.Resources)
			var da *DatasetAction
			if snap.Dataset != nil {
				da = snap.Dataset.actionByLower[low]
			}
			ca.Level = levelOf(a, da)
			if da != nil {
				ca.Dependent = cleanDependent(da.Dependent)
			}
			cs.Actions = append(cs.Actions, ca)
		}
		sort.Slice(cs.Actions, func(i, j int) bool {
			return asciiLower(cs.Actions[i].Name) < asciiLower(cs.Actions[j].Name)
		})
		c.Services = append(c.Services, cs)
		for _, k := range sr.ConditionKeys {
			if k.Name == "" || len(k.Name) > maxNameLen {
				warn("service %s: skipped condition key %q", prefix, clip(k.Name, 64))
				continue
			}
			ck := keyFromSR(k, func(t string) { warn("service %s: key %s has unknown type %q", prefix, k.Name, clip(t, 32)) })
			n := normKey(k.Name)
			if prev, ok := keys[n]; ok {
				// within one service a key family ("apigateway:Request/<name>")
				// can hold keys of several types; the first one stands for it
				if prev.svc != prefix && (prev.k.Type != ck.Type || prev.k.Multivalued != ck.Multivalued) {
					warn("key %s is typed differently in %s and %s; keeping %s", n, prev.svc, prefix, prev.svc)
				}
				continue
			}
			keys[n] = keySrc{ck, prefix}
		}
	}
	// dependent actions must be real actions (iam-dataset lists a few
	// condition keys there)
	known := map[string]bool{}
	for _, s := range c.Services {
		for _, a := range s.Actions {
			known[asciiLower(a.Name)] = true
		}
	}
	for i := range c.Services {
		for j := range c.Services[i].Actions {
			a := &c.Services[i].Actions[j]
			kept := a.Dependent[:0]
			for _, d := range a.Dependent {
				if known[asciiLower(d)] {
					kept = append(kept, d)
				}
			}
			if len(kept) == 0 {
				kept = nil
			}
			a.Dependent = kept
		}
	}
	// the curated global-key table wins over the per-service files
	for _, g := range ov.GlobalKeys.Keys {
		n := normKey(g.Name)
		if prev, ok := keys[n]; ok && (prev.k.Type != g.Type || prev.k.Multivalued != g.Multivalued) {
			warn("global key %s: overlay says %s/%v, %s says %s/%v; keeping the overlay",
				g.Name, g.Type, g.Multivalued, prev.svc, prev.k.Type, prev.k.Multivalued)
		}
		keys[n] = keySrc{CKey{Name: g.Name, Type: g.Type, Multivalued: g.Multivalued}, "overlay"}
	}
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c.Keys = append(c.Keys, keys[n].k)
	}
	if err := seal(c); err != nil {
		return nil, err
	}
	res := &Result{Compiled: c}
	if snap.RCPPage != nil {
		res.RCPDrift = compareRCP(snap.RCPPage.Services, ov.RCP.Services)
	}
	sort.Strings(warns)
	res.Warnings = warns
	return res, nil
}

func compareRCP(page, overlay []string) RCPDrift {
	d := RCPDrift{PageOnly: []string{}, OverlayOnly: []string{}}
	in := func(list []string) map[string]bool {
		m := make(map[string]bool, len(list))
		for _, s := range list {
			m[s] = true
		}
		return m
	}
	p, o := in(page), in(overlay)
	for s := range p {
		if !o[s] {
			d.PageOnly = append(d.PageOnly, s)
		}
	}
	for s := range o {
		if !p[s] {
			d.OverlayOnly = append(d.OverlayOnly, s)
		}
	}
	sort.Strings(d.PageOnly)
	sort.Strings(d.OverlayOnly)
	return d
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// cleanKeys sorts, de-duplicates and drops empty or oversized key names.
func cleanKeys(in []string) []string {
	var out []string
	for _, k := range in {
		if k != "" && len(k) <= maxNameLen {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	out = dedupe(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func cleanDependent(in []string) []string {
	var out []string
	for _, d := range in {
		if validFullAction(d) {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	out = dedupe(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// levelOf derives the access level from the Service Reference booleans;
// iam-dataset's string is used only when the Service Reference has none.
func levelOf(a srAction, da *DatasetAction) AccessLevel {
	if a.Annotations != nil && a.Annotations.Properties != nil {
		p := a.Annotations.Properties
		switch {
		case p.IsPermissionManagement:
			return AccessPermissionsManagement
		case p.IsTaggingOnly:
			return AccessTagging
		case p.IsWrite:
			return AccessWrite
		case p.IsList:
			return AccessList
		}
		return AccessRead
	}
	if da != nil {
		switch da.AccessLevel {
		case "List":
			return AccessList
		case "Read":
			return AccessRead
		case "Write":
			return AccessWrite
		case "Permissions management":
			return AccessPermissionsManagement
		case "Tagging":
			return AccessTagging
		}
	}
	return AccessUnknown
}

func keyFromSR(k srKey, unknown func(string)) CKey {
	ck := CKey{Name: k.Name, Type: model.KeyString}
	if len(k.Types) == 0 {
		return ck
	}
	t := k.Types[0]
	if rest, ok := strings.CutPrefix(t, "ArrayOf"); ok {
		ck.Multivalued = true
		t = rest
	}
	switch t {
	case "String":
		ck.Type = model.KeyString
	case "ARN":
		ck.Type = model.KeyARN
	case "Numeric":
		ck.Type = model.KeyNumeric
	case "Date":
		ck.Type = model.KeyDate
	case "Bool":
		ck.Type = model.KeyBool
	case "IPAddress":
		ck.Type = model.KeyIP
	case "Binary":
		ck.Type = model.KeyBinary
	default:
		unknown(k.Types[0])
	}
	return ck
}

// ---------------------------------------------------------------- encoding, hash, version

// canonical returns the canonical JSON (RFC 8785) of c.
func canonical(c *Compiled) ([]byte, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// contentHash is the SHA-256 of the canonical JSON with the version blanked.
func contentHash(c *Compiled) (string, error) {
	cp := *c
	cp.Version = ""
	b, err := canonical(&cp)
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}

func versionFor(snapshot, hash string) string { return snapshot + "-" + hash[:16] }

func seal(c *Compiled) error {
	h, err := contentHash(c)
	if err != nil {
		return err
	}
	c.Version = versionFor(c.Snapshot, h)
	return nil
}

// Encode returns the artifact bytes: canonical JSON in a gzip stream with a
// zero header timestamp and no file name, at a fixed level. The catalog
// version (not the gzip bytes, which depend on the Go release's deflate) is
// the content hash.
func Encode(c *Compiled) ([]byte, error) {
	b, err := canonical(c)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zw.Header = gzip.Header{OS: 255} // unknown OS, zero ModTime, no name
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode parses and verifies an artifact: size caps, strict JSON, schema
// version, and a content hash that matches the embedded version.
func Decode(data []byte) (*Compiled, error) {
	if len(data) > maxCompiledBytes {
		return nil, errors.New("catalog: compiled artifact too large")
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("catalog: compiled artifact: %w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, maxCompiledExpanded+1))
	if err != nil {
		return nil, fmt.Errorf("catalog: compiled artifact: %w", err)
	}
	if len(raw) > maxCompiledExpanded {
		return nil, errors.New("catalog: compiled artifact expands beyond the limit")
	}
	var c Compiled
	if err := strictUnmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("catalog: compiled artifact: %w", err)
	}
	if c.Schema != SchemaVersion {
		return nil, fmt.Errorf("catalog: compiled schema %d, this build reads %d", c.Schema, SchemaVersion)
	}
	h, err := contentHash(&c)
	if err != nil {
		return nil, err
	}
	if c.Version != versionFor(c.Snapshot, h) {
		return nil, fmt.Errorf("catalog: compiled artifact %q fails its content hash", c.Version)
	}
	return &c, nil
}
