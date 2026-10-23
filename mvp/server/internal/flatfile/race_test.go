//go:build race

package flatfile_test

// raceEnabled widens wall-clock bounds: the pure-Go SQLite driver runs many
// times slower under the race detector.
const raceEnabled = true
