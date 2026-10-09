package authz

// Residual is a predicate over request context that is left over when a
// symbolic ("can ever") evaluation cannot decide a request (§9.4).
//
// Residual is a closed sum type: only Const, And, Or, Not and Atom implement
// it, because the marker method is unexported. Simplification and rendering
// arrive with the condition evaluator (PR-4).
type Residual interface{ isResidual() }

// Const is the constant true or false.
type Const bool

// And is the conjunction of its terms. An empty And is true.
type And struct {
	Terms []Residual `json:"and"`
}

// Or is the disjunction of its terms. An empty Or is false.
type Or struct {
	Terms []Residual `json:"or"`
}

// Not negates its term.
type Not struct {
	Term Residual `json:"not"`
}

// Atom is one (operator, key, values) test, after variable substitution.
// The policy parser produces atoms with variables still unresolved.
type Atom struct {
	Op        string    `json:"op"`  // canonical operator without qualifier or IfExists, e.g. "StringLike", "IpAddress", "Null"
	Key       string    `json:"key"` // lower-cased context key, e.g. "aws:sourceip"
	Values    []string  `json:"values"`
	Qualifier Qualifier `json:"qualifier"` // default NoQualifier
	IfExists  bool      `json:"if_exists"`
	Negated   bool      `json:"negated"` // derived from the operator family; kept explicit for rendering
	Source    *StmtRef  `json:"source"`  // which statement contributed it; nil if none
}

func (Const) isResidual() {}
func (And) isResidual()   {}
func (Or) isResidual()    {}
func (Not) isResidual()   {}
func (Atom) isResidual()  {}
