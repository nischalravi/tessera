package checks

// Snapshot is the staged dry-run data a data check reads (DR-4).
type Snapshot interface {
	RunID() string
}
