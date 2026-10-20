package queue

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Spec is a parsed schedule: "@every <duration>" (at least one second) or a
// 5-field cron expression (minute hour day-of-month month day-of-week, UTC)
// with *, lists, ranges and steps, as in "*/15 * * * *" or "30 2 * * 1-5". As
// in cron, a day matches when either day field matches if both are restricted.
type Spec struct {
	every               time.Duration
	min, hour, dom, mon uint64
	dow                 uint64
	domStar, dowStar    bool
	text                string
}

// ParseSpec parses a schedule spec.
func ParseSpec(text string) (*Spec, error) {
	text = strings.TrimSpace(text)
	if rest, ok := strings.CutPrefix(text, "@every "); ok {
		d, err := time.ParseDuration(strings.TrimSpace(rest))
		if err != nil || d < time.Second {
			return nil, fmt.Errorf("queue: schedule %q: @every needs a duration of at least 1s", text)
		}
		return &Spec{every: d, text: text}, nil
	}
	f := strings.Fields(text)
	if len(f) != 5 {
		return nil, fmt.Errorf("queue: schedule %q: want @every <duration> or 5 cron fields", text)
	}
	s := &Spec{text: text, domStar: strings.HasPrefix(f[2], "*"), dowStar: strings.HasPrefix(f[4], "*")}
	var err error
	for i, p := range []struct {
		dst    *uint64
		lo, hi int
		name   string
	}{{&s.min, 0, 59, "minute"}, {&s.hour, 0, 23, "hour"}, {&s.dom, 1, 31, "day of month"}, {&s.mon, 1, 12, "month"},
		{&s.dow, 0, 7, "day of week"}} {
		if *p.dst, err = parseField(f[i], p.lo, p.hi); err != nil {
			return nil, fmt.Errorf("queue: schedule %q: %s: %w", text, p.name, err)
		}
	}
	if s.dow&(1<<7) != 0 { // 7 is Sunday too
		s.dow |= 1
	}
	return s, nil
}

func parseField(f string, lo, hi int) (uint64, error) {
	var set uint64
	for _, part := range strings.Split(f, ",") {
		rng, stepText, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepText)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("bad step %q", stepText)
			}
			step = n
		}
		a, b := lo, hi
		if rng != "*" {
			from, to, isRange := strings.Cut(rng, "-")
			var err error
			if a, err = strconv.Atoi(from); err != nil {
				return 0, fmt.Errorf("bad value %q", from)
			}
			b = a
			if isRange {
				if b, err = strconv.Atoi(to); err != nil {
					return 0, fmt.Errorf("bad value %q", to)
				}
			} else if hasStep {
				b = hi
			}
		}
		if a < lo || b > hi || a > b {
			return 0, fmt.Errorf("%q is outside %d-%d", part, lo, hi)
		}
		for v := a; v <= b; v += step {
			set |= 1 << uint(v)
		}
	}
	return set, nil
}

// String is the spec text.
func (s *Spec) String() string { return s.text }

// First is when a new schedule first fires: at once for @every (like the
// ticker loops it replaces, which ran on start), the next match for cron.
func (s *Spec) First(now time.Time) time.Time {
	if s.every > 0 {
		return now
	}
	return s.Next(now)
}

// Next is the first time after t that the spec fires (UTC).
func (s *Spec) Next(t time.Time) time.Time {
	if s.every > 0 {
		return t.Add(s.every)
	}
	t = t.UTC().Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		switch {
		case s.mon&(1<<uint(t.Month())) == 0:
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
		case !s.dayMatches(t):
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
		case s.hour&(1<<uint(t.Hour())) == 0:
			t = t.Truncate(time.Hour).Add(time.Hour)
		case s.min&(1<<uint(t.Minute())) == 0:
			t = t.Add(time.Minute)
		default:
			return t
		}
	}
	return limit // an impossible date such as 31 February: never within 5 years
}

func (s *Spec) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	if !s.domStar && !s.dowStar {
		return dom || dow
	}
	return dom && dow
}
