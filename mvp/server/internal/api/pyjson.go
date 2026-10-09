package api

// checkJSON reports the first syntax error in a JSON document the way
// CPython's json module does (message and character offset), so malformed
// bodies get the same 422 json_invalid error the original API returned. It
// returns ok=true for valid documents, including CPython's NaN/Infinity
// extensions (which are then rejected by the Go decoder).
func checkJSON(s string) (msg string, pos int, ok bool) {
	p := &jsonScanner{s: []rune(s)}
	idx := p.ws(0)
	end, err := p.value(idx)
	if err != nil {
		return err.msg, err.pos, false
	}
	end = p.ws(end)
	if end != len(p.s) {
		return "Extra data", end, false
	}
	return "", 0, true
}

type scanErr struct {
	msg string
	pos int
}

type jsonScanner struct{ s []rune }

func (p *jsonScanner) ws(i int) int {
	for i < len(p.s) && (p.s[i] == ' ' || p.s[i] == '\t' || p.s[i] == '\n' || p.s[i] == '\r') {
		i++
	}
	return i
}

func (p *jsonScanner) at(i int) rune {
	if i < len(p.s) {
		return p.s[i]
	}
	return 0
}

func (p *jsonScanner) lit(i int, word string) bool {
	r := []rune(word)
	if i+len(r) > len(p.s) {
		return false
	}
	for k, c := range r {
		if p.s[i+k] != c {
			return false
		}
	}
	return true
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

func (p *jsonScanner) value(i int) (int, *scanErr) {
	if i >= len(p.s) {
		return 0, &scanErr{"Expecting value", i}
	}
	switch c := p.s[i]; {
	case c == '"':
		return p.str(i)
	case c == '{':
		return p.object(i + 1)
	case c == '[':
		return p.array(i + 1)
	case c == 'n' && p.lit(i, "null"):
		return i + 4, nil
	case c == 't' && p.lit(i, "true"):
		return i + 4, nil
	case c == 'f' && p.lit(i, "false"):
		return i + 5, nil
	case c == 'N' && p.lit(i, "NaN"):
		return i + 3, nil
	case c == 'I' && p.lit(i, "Infinity"):
		return i + 8, nil
	case c == '-' && p.lit(i, "-Infinity"):
		return i + 9, nil
	}
	return p.number(i)
}

func (p *jsonScanner) number(i int) (int, *scanErr) {
	start, j := i, i
	if p.at(j) == '-' {
		j++
	}
	switch {
	case p.at(j) == '0':
		j++
	case p.at(j) >= '1' && p.at(j) <= '9':
		for isDigit(p.at(j)) {
			j++
		}
	default:
		return 0, &scanErr{"Expecting value", start}
	}
	if p.at(j) == '.' && isDigit(p.at(j+1)) {
		j += 2
		for isDigit(p.at(j)) {
			j++
		}
	}
	if p.at(j) == 'e' || p.at(j) == 'E' {
		k := j + 1
		if p.at(k) == '+' || p.at(k) == '-' {
			k++
		}
		if isDigit(p.at(k)) {
			for isDigit(p.at(k)) {
				k++
			}
			j = k
		}
	}
	return j, nil
}

func isHex(r rune) bool {
	return isDigit(r) || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func (p *jsonScanner) str(begin int) (int, *scanErr) {
	i := begin + 1
	for {
		if i >= len(p.s) {
			return 0, &scanErr{"Unterminated string starting at", begin}
		}
		c := p.s[i]
		switch {
		case c == '"':
			return i + 1, nil
		case c == '\\':
			e := p.at(i + 1)
			if i+1 >= len(p.s) {
				return 0, &scanErr{"Unterminated string starting at", begin}
			}
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i += 2
			case 'u':
				for k := 2; k < 6; k++ {
					if !isHex(p.at(i + k)) {
						return 0, &scanErr{"Invalid \\uXXXX escape", i + 1}
					}
				}
				i += 6
			default:
				return 0, &scanErr{"Invalid \\escape", i}
			}
		case c < 0x20:
			return 0, &scanErr{"Invalid control character at", i}
		default:
			i++
		}
	}
}

func (p *jsonScanner) object(i int) (int, *scanErr) {
	i = p.ws(i)
	if p.at(i) == '}' && i < len(p.s) {
		return i + 1, nil
	}
	for {
		if i >= len(p.s) || p.s[i] != '"' {
			return 0, &scanErr{"Expecting property name enclosed in double quotes", i}
		}
		end, err := p.str(i)
		if err != nil {
			return 0, err
		}
		i = p.ws(end)
		if i >= len(p.s) || p.s[i] != ':' {
			return 0, &scanErr{"Expecting ':' delimiter", i}
		}
		i = p.ws(i + 1)
		if i, err = p.value(i); err != nil {
			return 0, err
		}
		i = p.ws(i)
		if i < len(p.s) && p.s[i] == '}' {
			return i + 1, nil
		}
		if i >= len(p.s) || p.s[i] != ',' {
			return 0, &scanErr{"Expecting ',' delimiter", i}
		}
		comma := i
		i = p.ws(i + 1)
		if i < len(p.s) && p.s[i] == '}' {
			return 0, &scanErr{"Illegal trailing comma before end of object", comma}
		}
	}
}

func (p *jsonScanner) array(i int) (int, *scanErr) {
	i = p.ws(i)
	if i < len(p.s) && p.s[i] == ']' {
		return i + 1, nil
	}
	for {
		var err *scanErr
		if i, err = p.value(i); err != nil {
			return 0, err
		}
		i = p.ws(i)
		if i < len(p.s) && p.s[i] == ']' {
			return i + 1, nil
		}
		if i >= len(p.s) || p.s[i] != ',' {
			return 0, &scanErr{"Expecting ',' delimiter", i}
		}
		comma := i
		i = p.ws(i + 1)
		if i < len(p.s) && p.s[i] == ']' {
			return 0, &scanErr{"Illegal trailing comma before end of array", comma}
		}
	}
}
