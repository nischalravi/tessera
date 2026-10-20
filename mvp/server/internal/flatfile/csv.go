package flatfile

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Bounds on one upload. The API server also caps the request body
// (api.DefaultMaxBodyBytes); MaxBytes is below it, so an oversized file is
// answered and recorded as a rejected upload rather than cut off.
const (
	MaxBytes     = 512 << 10
	MaxRows      = 5000
	MaxColumns   = 64
	MaxCellRunes = 256
)

// Error codes of a rejected row or file.
const (
	CodeFileTooLarge   = "file_too_large"
	CodeTooManyRows    = "too_many_rows"
	CodeTooManyColumns = "too_many_columns"
	CodeNotUTF8        = "not_utf8"
	CodeNoHeader       = "no_header"
	CodeBadCSV         = "bad_csv"
	CodeDuplicateCol   = "duplicate_column"
	CodeMissingColumn  = "missing_column"
	CodeColumnCount    = "column_count"
	CodeRequired       = "required"
	CodeTooLong        = "too_long"
	CodeControlChar    = "control_character"
	CodeFormulaPrefix  = "formula_prefix"
	CodeInvalidEmail   = "invalid_email"
	CodeInvalidStatus  = "invalid_status"
	CodeInvalidValue   = "invalid_value"
	CodeDuplicateKey   = "duplicate_key"
	CodeUnknownAccount = "unknown_account"
)

// RowError is one rejected row. Row is the 1-based data row, counted after
// the header (blank lines are not rows); Row 0 is the file as a whole.
type RowError struct {
	Row     int    `json:"row"`
	Column  string `json:"column"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Row is one data row: Num is its 1-based position after the header.
type Row struct {
	Num   int
	Cells []string
}

// Table is a parsed file: the header and the data rows, every row as long as
// the header.
type Table struct {
	Header []string
	Rows   []Row
	// Short lists the rows that had a different number of cells: they are not
	// in Rows, and each is an error.
	Short []RowError
	// Total is the number of data rows read, Rows and Short together.
	Total int
}

// Parse reads a CSV file. It refuses (with one file-level RowError) a file
// that is too large, is not valid UTF-8, has no header, a repeated header
// name, or too many rows or columns; a row of the wrong length is reported
// in Short and the rest are still read, so one pass lists every problem.
func Parse(raw []byte) (*Table, []RowError) {
	fileErr := func(code, format string, a ...any) (*Table, []RowError) {
		return nil, []RowError{{Code: code, Message: fmt.Sprintf(format, a...)}}
	}
	if len(raw) > MaxBytes {
		return fileErr(CodeFileTooLarge, "the file is larger than %d KiB", MaxBytes>>10)
	}
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return fileErr(CodeNotUTF8, "the file is not valid UTF-8 text (save it as CSV UTF-8)")
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) // a spreadsheet's byte order mark
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	r.LazyQuotes = false
	r.ReuseRecord = false
	var t Table
	for line := 0; ; line++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fileErr(CodeBadCSV, "the file is not valid CSV: %v", err)
		}
		if line == 0 {
			t.Header = make([]string, len(rec))
			seen := map[string]bool{}
			for i, h := range rec {
				h = strings.TrimSpace(h)
				if h == "" {
					return fileErr(CodeNoHeader, "the header row has an empty column name (column %d)", i+1)
				}
				k := strings.ToLower(h)
				if seen[k] {
					return fileErr(CodeDuplicateCol, "the header repeats the column %q", Neutralize(h))
				}
				seen[k] = true
				t.Header[i] = h
			}
			if len(t.Header) > MaxColumns {
				return fileErr(CodeTooManyColumns, "the file has more than %d columns", MaxColumns)
			}
			continue
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue // a blank line is not a row
		}
		if t.Total++; t.Total > MaxRows {
			return fileErr(CodeTooManyRows, "the file has more than %d rows", MaxRows)
		}
		if len(rec) != len(t.Header) {
			t.Short = append(t.Short, RowError{Row: t.Total, Code: CodeColumnCount,
				Message: fmt.Sprintf("the row has %d columns, the header has %d", len(rec), len(t.Header))})
			continue
		}
		for i := range rec {
			rec[i] = strings.TrimSpace(rec[i])
		}
		t.Rows = append(t.Rows, Row{Num: t.Total, Cells: rec})
	}
	if t.Header == nil {
		return fileErr(CodeNoHeader, "the file is empty: the first row must be the column names")
	}
	return &t, nil
}
