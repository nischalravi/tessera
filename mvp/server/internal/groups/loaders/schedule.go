package loaders

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a five-field cron expression (minute hour day-of-month month
// day-of-week; lists, ranges, steps and the names of months and days) in UTC.
// The shortcuts @hourly, @daily and @weekly are accepted. As in cron, when both
// day fields are restricted a day matches if either does.
type Schedule struct {
	minute, hour, dom, month, dow uint64
	domAny, dowAny                bool
}

var monthNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9,
	"oct": 10, "nov": 11, "dec": 12}
var dayNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

// ParseSchedule parses a cron expression.
func ParseSchedule(expr string) (*Schedule, error) {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "@hourly":
		expr = "0 * * * *"
	case "@daily":
		expr = "0 0 * * *"
	case "@weekly":
		expr = "0 0 * * 0"
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, errors.New("a schedule has five fields: minute hour day-of-month month day-of-week")
	}
	var s Schedule
	var err error
	if s.minute, _, err = parseField(f[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if s.hour, _, err = parseField(f[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if s.dom, s.domAny, err = parseField(f[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("day-of-month: %w", err)
	}
	if s.month, _, err = parseField(f[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if s.dow, s.dowAny, err = parseField(f[4], 0, 7, dayNames); err != nil {
		return nil, fmt.Errorf("day-of-week: %w", err)
	}
	if s.dow&(1<<7) != 0 { // 7 is Sunday too
		s.dow = s.dow&^(1<<7) | 1
	}
	return &s, nil
}

// parseField reads one field into a bit set; star says it was "*".
func parseField(field string, lo, hi int, names map[string]int) (set uint64, star bool, err error) {
	value := func(s string) (int, error) {
		if n, ok := names[strings.ToLower(s)]; ok {
			return n, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < lo || n > hi {
			return 0, fmt.Errorf("%q is not %d to %d", s, lo, hi)
		}
		return n, nil
	}
	for _, part := range strings.Split(field, ",") {
		step := 1
		if base, st, found := strings.Cut(part, "/"); found {
			n, err := strconv.Atoi(st)
			if err != nil || n < 1 {
				return 0, false, fmt.Errorf("bad step %q", st)
			}
			part, step = base, n
		}
		from, to := lo, hi
		switch {
		case part == "*":
			star = star || step == 1
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			if from, err = value(a); err != nil {
				return 0, false, err
			}
			if to, err = value(b); err != nil {
				return 0, false, err
			}
			if from > to {
				return 0, false, fmt.Errorf("range %q runs backwards", part)
			}
		default:
			n, verr := value(part)
			if verr != nil {
				return 0, false, verr
			}
			from, to = n, n
			if step > 1 {
				to = hi
			}
		}
		for n := from; n <= to; n += step {
			set |= 1 << uint(n)
		}
	}
	return set, star, nil
}

func (s *Schedule) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case s.domAny && s.dowAny:
		return true
	case s.domAny:
		return dow
	case s.dowAny:
		return dom
	}
	return dom || dow
}

// Next is the first time after t that the schedule fires, or the zero time if
// it never does within five years (a day that does not exist, 30 February).
func (s *Schedule) Next(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if s.month&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if s.hour&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, time.UTC)
			continue
		}
		if s.minute&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// Due reports whether a run is due at now: the schedule fired after the last
// run (or, for a loader that never ran, after it was created).
func (s *Schedule) Due(last, now time.Time) bool {
	next := s.Next(last)
	return !next.IsZero() && !next.After(now)
}
