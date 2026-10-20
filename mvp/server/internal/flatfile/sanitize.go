// Package flatfile imports CSV files for disconnected applications (issue
// #105): apps with no connector whose owner uploads a file of accounts and of
// account-entitlement rows.
//
// The flow is Parse (bytes -> cells, bounded, UTF-8 only), Mapping.Accounts /
// Mapping.Entitlements (cells -> validated records, every bad row reported),
// Diff (records against the last applied snapshot -> added, removed,
// changed) and Apply (record the upload, feed the graph through the normal
// ingest path, confirm manual tasks). Apply takes the file as bytes, so an
// SFTP drop can call it later with the file it fetched; no SFTP server is
// built here.
package flatfile

import "strings"

// formulaPrefixes are the characters a spreadsheet reads as the start of a
// formula (OWASP CSV injection): = + - @, and tab and carriage return, which
// some programs skip before looking for one.
const formulaPrefixes = "=+-@\t\r"

// HasFormulaPrefix reports whether s starts like a spreadsheet formula.
func HasFormulaPrefix(s string) bool {
	return s != "" && strings.ContainsRune(formulaPrefixes, rune(s[0]))
}

// Neutralize makes a value safe to show or export to a spreadsheet: a value
// that starts like a formula gets a leading apostrophe, which spreadsheets
// read as "text". It is idempotent.
func Neutralize(s string) string {
	if HasFormulaPrefix(s) {
		return "'" + s
	}
	return s
}
