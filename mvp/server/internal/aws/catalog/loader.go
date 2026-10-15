package catalog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const compiledSuffix = ".json.gz"

// maxActions bounds a catalog (AWS has about 22,000 actions), so every
// ActionID fits a uint32 with a wide margin.
const maxActions = 1 << 22

// validVersion accepts "<YYYY-MM-DD>-<16 hex>", the only shape Compile makes.
func validVersion(v string) bool {
	if len(v) != 10+1+16 || !validDate(v[:10]) || v[10] != '-' {
		return false
	}
	for _, c := range []byte(v[11:]) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// CompiledPath is where Compile output for a version lives under dir.
func CompiledPath(dir, version string) string {
	return filepath.Join(dir, "compiled", version+compiledSuffix)
}

// Load reads compiled/<version>.json.gz from the catalog directory (for
// example mvp/server/catalog/aws), verifies it and returns the catalog. The
// artifact must carry the version asked for.
func Load(dir, version string) (*Catalog, error) {
	if !validVersion(version) {
		return nil, fmt.Errorf("catalog: invalid catalog version %q", version)
	}
	c, err := LoadCompiled(CompiledPath(dir, version))
	if err != nil {
		return nil, err
	}
	if c.Version != version {
		return nil, fmt.Errorf("catalog: %s holds version %q, not %q", CompiledPath(dir, version), c.Version, version)
	}
	return New(c)
}

// LoadCompiled reads and verifies one artifact file (without building indexes).
func LoadCompiled(path string) (*Compiled, error) {
	b, err := readCapped(path, maxCompiledBytes)
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return Decode(b)
}

// CompiledVersion names one compiled artifact on disk.
type CompiledVersion struct {
	Version  string
	Snapshot string
}

// ListCompiled lists the artifacts under dir/compiled, oldest snapshot first
// (then by version). A missing directory is an empty list.
func ListCompiled(dir string) ([]CompiledVersion, error) {
	ents, err := os.ReadDir(filepath.Join(dir, "compiled"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []CompiledVersion
	for _, e := range ents {
		v, ok := strings.CutSuffix(e.Name(), compiledSuffix)
		if !ok || !validVersion(v) {
			continue
		}
		out = append(out, CompiledVersion{Version: v, Snapshot: v[:10]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// ListSnapshots lists the snapshot dates under dir/snapshots, oldest first.
func ListSnapshots(dir string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(dir, "snapshots"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && validDate(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// New builds the read-only indexes of a verified Compiled.
func New(c *Compiled) (*Catalog, error) {
	if c == nil {
		return nil, errors.New("catalog: nil compiled catalog")
	}
	cat := &Catalog{
		version:  c.Version,
		snapshot: c.Snapshot,
		dataset:  c.IAMDatasetCommit,
		byLower:  map[string]ActionID{},
		svcRange: map[string][2]ActionID{},
		keys:     make(map[string]KeyInfo, len(c.Keys)),
		rtypes:   map[ResourceType]*rtRec{},
		rtBySvc:  map[string][]*rtRec{},
		rcp:      make(map[string]bool, len(c.Overlays.RCP.Services)),
		overlays: c.Overlays,
	}
	prev := ""
	for _, s := range c.Services {
		if !validPrefix(s.Prefix) || s.Prefix <= prev {
			return nil, fmt.Errorf("catalog: services out of order or invalid at %q", s.Prefix)
		}
		prev = s.Prefix
		lo := ActionID(len(cat.actions)) // #nosec G115 -- len(actions) ≤ maxActions, checked below
		for _, a := range s.Actions {
			if len(cat.actions) >= maxActions {
				return nil, fmt.Errorf("catalog: more than %d actions", maxActions)
			}
			low := asciiLower(a.Name)
			if !strings.HasPrefix(low, s.Prefix+":") {
				return nil, fmt.Errorf("catalog: action %q is not in service %q", a.Name, s.Prefix)
			}
			if _, dup := cat.byLower[low]; dup {
				return nil, fmt.Errorf("catalog: duplicate action %q", a.Name)
			}
			rec := actionRec{name: a.Name, level: a.Level, keys: a.Keys, dependent: a.Dependent}
			for _, r := range a.Resources {
				rec.rtypes = append(rec.rtypes, ResourceType(s.Prefix+":"+r))
			}
			cat.byLower[low] = ActionID(len(cat.actions)) // #nosec G115 -- len(actions) < maxActions
			cat.actions = append(cat.actions, rec)
		}
		cat.svcRange[s.Prefix] = [2]ActionID{lo, ActionID(len(cat.actions))} // #nosec G115 -- len(actions) ≤ maxActions
		for _, r := range s.Resources {
			rt := ResourceType(s.Prefix + ":" + r.Name)
			rr := &rtRec{rt: rt, formats: r.ARNFormats, keys: r.Keys}
			for _, f := range r.ARNFormats {
				rr.tmpl = append(rr.tmpl, parseTemplate(f))
			}
			cat.rtypes[rt] = rr
			// an ARN's service segment is not always the service prefix
			// (for example "s3" resources of "s3-object-lambda"), so index by it
			for _, f := range r.ARNFormats {
				parts := strings.SplitN(f, ":", 4)
				if len(parts) == 4 && !strings.Contains(parts[2], "${") {
					cat.rtBySvc[parts[2]] = appendUnique(cat.rtBySvc[parts[2]], rr)
				}
			}
		}
	}
	for _, k := range c.Keys {
		cat.keys[normKey(k.Name)] = KeyInfo{Name: k.Name, Type: k.Type, Multivalued: k.Multivalued}
	}
	for _, s := range c.Overlays.RCP.Services {
		cat.rcp[s] = true
	}
	return cat, nil
}

func appendUnique(s []*rtRec, r *rtRec) []*rtRec {
	for _, x := range s {
		if x == r {
			return s
		}
	}
	return append(s, r)
}
