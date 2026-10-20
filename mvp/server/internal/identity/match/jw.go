package match

// Jaro returns the Jaro similarity of a and b, compared as runes: 1 for equal
// strings, 0 for nothing in common.
func Jaro(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	switch {
	case la == 0 && lb == 0:
		return 1
	case la == 0 || lb == 0:
		return 0
	}
	window := max(la, lb)/2 - 1
	if window < 0 {
		window = 0
	}
	ma, mb := make([]bool, la), make([]bool, lb)
	matches := 0
	for i := range ra {
		lo, hi := max(0, i-window), min(lb-1, i+window)
		for j := lo; j <= hi; j++ {
			if mb[j] || ra[i] != rb[j] {
				continue
			}
			ma[i], mb[j] = true, true
			matches++
			break
		}
	}
	if matches == 0 {
		return 0
	}
	transpositions, k := 0, 0
	for i := range ra {
		if !ma[i] {
			continue
		}
		for !mb[k] {
			k++
		}
		if ra[i] != rb[k] {
			transpositions++
		}
		k++
	}
	m := float64(matches)
	return (m/float64(la) + m/float64(lb) + (m-float64(transpositions)/2)/m) / 3
}

// JaroWinkler is Jaro raised for a common prefix of up to four runes (scale
// 0.1), applied only above the standard 0.7 threshold.
func JaroWinkler(a, b string) float64 {
	j := Jaro(a, b)
	if j <= 0.7 {
		return j
	}
	ra, rb := []rune(a), []rune(b)
	p := 0
	for p < len(ra) && p < len(rb) && p < 4 && ra[p] == rb[p] {
		p++
	}
	return j + float64(p)*0.1*(1-j)
}
