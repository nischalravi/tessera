package agent

import (
	"errors"
	"slices"
)

// The plug-in host (issue #561).
//
// The agent reads a customer directory in the customer's network. LDAP and
// Active Directory are built in; other systems that need the same placement
// (RACF on z/OS, IBM i) are modules: a SyncerFactory registered under a name.
// A module is compiled into the agent binary (there is no dynamic loading, no
// script and no downloaded code), and it gets exactly what the built-in reader
// gets: the typed job, the credential read from the agent's own store, and the
// agent-local safedial Dialer, so every connection a module opens is checked
// against the local allowlist. A module returns the same typed, bounded
// SyncResult, so a module cannot send Tessera anything the protocol does not
// already allow.
//
// The set of module names is closed and shared by both ends: Tessera refuses a
// job that names another module, and the agent refuses one it does not carry.

// The module names. ACF2 and Top Secret join this list when their modules
// exist.
const (
	ModuleRACF = "racf"
	ModuleIBMi = "ibmi"
)

// ModuleNames is every module name a job may carry.
var ModuleNames = []string{ModuleRACF, ModuleIBMi}

// ValidModuleName reports whether name is a known module.
func ValidModuleName(name string) bool { return slices.Contains(ModuleNames, name) }

// ModuleAccountAttrs are the account attributes each module reports on its own
// (scope "account"). The server ingests exactly these, plus whatever the
// connection's attribute map lists, and drops any other attribute a module
// names (RecordAgentSync).
var ModuleAccountAttrs = map[string][]string{
	ModuleRACF: {"racfDefaultGroup", "racfOwner", "racfProgrammerName"},
	ModuleIBMi: {"userClass", "description"},
}

// ModuleAttribute reports whether target is a built-in account attribute of the module.
func ModuleAttribute(module, target string) bool {
	return slices.Contains(ModuleAccountAttrs[module], target)
}

// Module is one plug-in: a name from ModuleNames and the factory of its reader.
type Module struct {
	Name string
	New  SyncerFactory
}

var (
	// ErrBadModule: a module was registered with an unknown name or no factory.
	ErrBadModule = errors.New("agent: not a valid module")
	// ErrDuplicateModule: a module name was registered twice.
	ErrDuplicateModule = errors.New("agent: module is already registered")
)

// Register adds a module to the agent. It is called at start-up, before the
// agent polls.
func (e *Executor) Register(m Module) error {
	if !ValidModuleName(m.Name) || m.New == nil {
		return ErrBadModule
	}
	if _, dup := e.Modules[m.Name]; dup {
		return ErrDuplicateModule
	}
	if e.Modules == nil {
		e.Modules = map[string]SyncerFactory{}
	}
	e.Modules[m.Name] = m.New
	return nil
}

// ModuleList returns the names of the registered modules, sorted.
func (e *Executor) ModuleList() []string {
	out := make([]string, 0, len(e.Modules))
	for n := range e.Modules {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// syncerFor returns the reader factory of a module name (empty: the built-in
// LDAP reader), or false if this agent build does not carry it.
func (e *Executor) syncerFor(module string) (SyncerFactory, bool) {
	if module == "" {
		return e.NewSyncer, e.NewSyncer != nil
	}
	f, ok := e.Modules[module]
	return f, ok && f != nil
}
