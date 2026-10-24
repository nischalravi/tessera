package servicenow

// CorrelationForTest exposes a target's correlation id of an operation key to the external tests.
func (t *Target) CorrelationForTest(key string) (string, error) { return t.correlation(key) }
