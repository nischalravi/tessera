// Package timeutil holds Tessera's time conventions: naive UTC timestamps with
// microsecond precision, Python-compatible ISO formatting and day arithmetic.
//
// The API contract (inherited from the original Python backend) uses naive UTC
// datetimes rendered by Python's datetime.isoformat(): no zone suffix, and a
// fractional part only when the microsecond is non-zero.
package timeutil

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// Clock returns "now" as naive UTC truncated to microseconds.
type Clock func() time.Time

// System is the wall clock.
func System() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// Frozen returns a clock that always reports t.
func Frozen(t time.Time) Clock {
	t = t.UTC().Truncate(time.Microsecond)
	return func() time.Time { return t }
}

const (
	dbLayout  = "2006-01-02 15:04:05.000000"
	isoLayout = "2006-01-02T15:04:05"
	// MicrosPerDay is the number of microseconds in a day.
	MicrosPerDay = int64(86400) * 1_000_000
	// MicrosPerHour is the number of microseconds in an hour.
	MicrosPerHour = int64(3600) * 1_000_000
)

// DB formats t the way the database stores timestamps (sortable text).
func DB(t time.Time) string { return t.UTC().Format(dbLayout) }

// ParseDB parses a stored timestamp. It accepts the stored layout and ISO 8601
// variants (with "T", with or without fraction).
func ParseDB(s string) (time.Time, error) {
	for _, layout := range []string{dbLayout, "2006-01-02 15:04:05", "2006-01-02T15:04:05.999999", isoLayout, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("timeutil: cannot parse %q", s)
}

// ParseISO parses an ISO-8601 timestamp such as TESSERA_NOW. A zone, if present,
// is converted to UTC.
func ParseISO(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Truncate(time.Microsecond), nil
	}
	t, err := ParseDB(s)
	return t.Truncate(time.Microsecond), err
}

// ISO renders t like Python's naive datetime.isoformat().
func ISO(t time.Time) string {
	t = t.UTC()
	if us := t.Nanosecond() / 1000; us != 0 {
		return t.Format(isoLayout) + fmt.Sprintf(".%06d", us)
	}
	return t.Format(isoLayout)
}

// ISOPtr renders an optional timestamp, nil for nil.
func ISOPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := ISO(*t)
	return &s
}

// Date renders the date part (YYYY-MM-DD).
func Date(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Days is Python's (a - b).days: whole days, rounded toward negative infinity.
func Days(a, b time.Time) int {
	us := a.Sub(b).Microseconds()
	d := us / MicrosPerDay
	if us%MicrosPerDay != 0 && us < 0 {
		d--
	}
	return int(d)
}

// Delta converts a float quantity of a unit (given in microseconds) into a
// duration exactly as CPython's timedelta constructor does, including its
// round-half-to-even handling of the leftover fraction of a microsecond.
func Delta(value float64, unitMicros int64) time.Duration {
	intpart, frac := math.Modf(value)
	sum := int64(intpart) * unitMicros
	leftover := 0.0
	if frac != 0 {
		ip, fp := math.Modf(frac * float64(unitMicros))
		sum += int64(ip)
		leftover = fp
	}
	if leftover != 0 {
		whole := math.Round(leftover)
		if math.Abs(whole-leftover) == 0.5 {
			odd := float64(sum & 1)
			whole = 2.0*math.Round((leftover+odd)*0.5) - odd
		}
		sum += int64(whole)
	}
	return time.Duration(sum) * time.Microsecond
}

// DaysAgo is now - timedelta(days=n).
func DaysAgo(now time.Time, n float64) time.Time { return now.Add(-Delta(n, MicrosPerDay)) }

// Round mirrors Python's round(x, ndigits) for floats (correctly rounded).
func Round(x float64, ndigits int) float64 {
	v, err := strconv.ParseFloat(strconv.FormatFloat(x, 'f', ndigits, 64), 64)
	if err != nil {
		return x
	}
	return v
}
