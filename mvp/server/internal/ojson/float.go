package ojson

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Float is a float64 that renders like Python's repr(float): always with a
// fractional part or exponent ("4.0", "0.35", "1e+16"), so values the API
// contract defines as floats keep their float spelling (the original backend
// returned 4.0, not 4).
type Float float64

// MarshalJSON renders the float in Python repr form. NaN and infinities are
// rejected, as Python's json module does with allow_nan=False.
func (f Float) MarshalJSON() ([]byte, error) {
	x := float64(f)
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return nil, errors.New("ojson: NaN and Infinity are not valid JSON")
	}
	return []byte(PyRepr(x)), nil
}

// PyRepr formats x like CPython's float.__repr__ (shortest round-trip digits,
// fixed notation for exponents in [-4, 16), scientific otherwise).
func PyRepr(x float64) string {
	if x == 0 {
		if math.Signbit(x) {
			return "-0.0"
		}
		return "0.0"
	}
	s := strconv.FormatFloat(x, 'e', -1, 64)
	mant, expS, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expS)
	neg := strings.HasPrefix(mant, "-")
	digits := strings.Replace(strings.TrimPrefix(mant, "-"), ".", "", 1)
	var out string
	switch {
	case exp >= 16 || exp < -4:
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		out = fmt.Sprintf("%se%s%02d", m, sign, exp)
	case exp >= 0:
		if len(digits) <= exp+1 {
			out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		} else {
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	default:
		out = "0." + strings.Repeat("0", -exp-1) + digits
	}
	if neg {
		out = "-" + out
	}
	return out
}
