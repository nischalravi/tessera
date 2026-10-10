package policy

// Limits caps the work the parser does on one document. Policy JSON is
// untrusted input (design §16 R2), so every dimension is bounded before any
// allocation that depends on it.
//
// The defaults sit well above AWS's own limits, so no policy AWS accepts is
// rejected. The largest AWS document limits are 32,768 bytes for a KMS key
// policy and 20 KB for S3 bucket and Secrets Manager policies; IAM's own
// limits are 2,048–10,240 characters excluding white space. Raw bytes here
// include white space and escapes, which is why MaxBytes has a wide margin.
type Limits struct {
	MaxBytes       int // raw document size in bytes
	MaxDepth       int // JSON nesting; the policy grammar needs at most 6
	MaxStatements  int // statements in one document
	MaxStringBytes int // any one JSON string (key or value), after unescaping
	MaxValues      int // total JSON values (objects, arrays, scalars) in the document
}

// DefaultLimits are used when Options.Limits is the zero value.
var DefaultLimits = Limits{
	MaxBytes:       128 << 10,
	MaxDepth:       16,
	MaxStatements:  2048,
	MaxStringBytes: 8 << 10,
	MaxValues:      64 << 10,
}

// orDefault fills zero fields from DefaultLimits.
func (l Limits) orDefault() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultLimits.MaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultLimits.MaxDepth
	}
	if l.MaxStatements <= 0 {
		l.MaxStatements = DefaultLimits.MaxStatements
	}
	if l.MaxStringBytes <= 0 {
		l.MaxStringBytes = DefaultLimits.MaxStringBytes
	}
	if l.MaxValues <= 0 {
		l.MaxValues = DefaultLimits.MaxValues
	}
	return l
}
