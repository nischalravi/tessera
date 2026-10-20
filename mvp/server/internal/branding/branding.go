// Package branding validates what a tenant shows on its sign-in page, its
// guest claim pages and in emails: the product name, a colour pair and a
// logo.
//
// Colours are #rrggbb. The pair (button background, text on it) must reach
// WCAG AA (4.5:1) or it is refused; an empty text colour is chosen
// automatically (white or black, whichever reads better). The logo is a
// raster image only: PNG or JPEG, never SVG (an SVG can carry script), at most
// MaxLogoBytes, with dimensions inside MinDim..MaxDim, checked by decoding it,
// so a file whose bytes do not match its type is refused. It is served with a
// strict content type (see internal/api/branding.go).
package branding

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/jpeg" // registers the JPEG decoder
	_ "image/png"  // registers the PNG decoder
	"math"
	"net/http"
	"strings"
	"unicode"
)

// Limits.
const (
	MaxLogoBytes = 256 << 10
	MinDim       = 32
	MaxDim       = 1024
	MaxName      = 80
	MinContrast  = 4.5 // WCAG 2.x AA for normal text
	DefaultName  = "Tessera"
)

// Error is a refused value; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(code, format string, args ...any) error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Name validates the product name.
func Name(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > MaxName {
		return "", refuse("invalid_name", "the name is 1 to %d characters", MaxName)
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '<' || r == '>' {
			return "", refuse("invalid_name", "the name cannot contain control characters, < or >")
		}
	}
	return s, nil
}

// rgb parses #rrggbb.
func rgb(s string) (r, g, b uint8, err error) {
	if len(s) != 7 || s[0] != '#' {
		return 0, 0, 0, refuse("invalid_color", "%q is not a colour: use #rrggbb", s)
	}
	var v [3]uint8
	for i := range v {
		x := 0
		if _, err := fmt.Sscanf(s[1+2*i:3+2*i], "%02x", &x); err != nil || !isHex(s[1+2*i:3+2*i]) {
			return 0, 0, 0, refuse("invalid_color", "%q is not a colour: use #rrggbb", s)
		}
		v[i] = uint8(x)
	}
	return v[0], v[1], v[2], nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func lin(c uint8) float64 {
	v := float64(c) / 255
	if v <= 0.03928 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

func luminance(s string) (float64, error) {
	r, g, b, err := rgb(s)
	if err != nil {
		return 0, err
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b), nil
}

// Contrast is the WCAG contrast ratio of two #rrggbb colours (1 to 21).
func Contrast(a, b string) (float64, error) {
	la, err := luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := luminance(b)
	if err != nil {
		return 0, err
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), nil
}

// Colors validates the colour pair and returns both in lower-case #rrggbb. An empty on is chosen: white or black,
// whichever has the higher contrast with primary.
func Colors(primary, on string) (string, string, error) {
	primary = strings.ToLower(strings.TrimSpace(primary))
	on = strings.ToLower(strings.TrimSpace(on))
	if _, err := luminance(primary); err != nil {
		return "", "", err
	}
	if on == "" {
		w, _ := Contrast(primary, "#ffffff")
		k, _ := Contrast(primary, "#000000")
		on = "#ffffff"
		if k > w {
			on = "#000000"
		}
	}
	c, err := Contrast(primary, on)
	if err != nil {
		return "", "", err
	}
	if c < MinContrast {
		w, _ := Contrast(primary, "#ffffff")
		k, _ := Contrast(primary, "#000000")
		best, bestC := "#ffffff", w
		if k > w {
			best, bestC = "#000000", k
		}
		return "", "", refuse("low_contrast", "the text colour %s on %s has a contrast of %.2f:1; WCAG AA needs %.1f:1 (%s gives %.2f:1)",
			on, primary, c, MinContrast, best, bestC)
	}
	return primary, on, nil
}

// Logo is a checked logo image.
type Logo struct {
	Data          []byte
	ContentType   string // image/png | image/jpeg
	Width, Height int
	SHA256        string
}

// CheckLogo validates logo bytes. declared is the content type the client sent ("" accepts the detected type).
func CheckLogo(data []byte, declared string) (*Logo, error) {
	if len(data) == 0 {
		return nil, refuse("invalid_logo", "the logo is empty")
	}
	if len(data) > MaxLogoBytes {
		return nil, &Error{Status: http.StatusRequestEntityTooLarge, Code: "logo_too_large",
			Msg: fmt.Sprintf("the logo is at most %d KiB", MaxLogoBytes>>10)}
	}
	var ct string
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		ct = "image/png"
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		ct = "image/jpeg"
	case bytes.Contains(bytes.ToLower(data[:min(len(data), 512)]), []byte("<svg")) || bytes.HasPrefix(bytes.TrimSpace(data), []byte("<")):
		return nil, refuse("svg_not_allowed", "SVG logos are not accepted (they can carry script); upload a PNG or JPEG")
	default:
		return nil, refuse("invalid_logo", "the logo must be a PNG or JPEG image")
	}
	if declared != "" && declared != ct {
		return nil, refuse("type_mismatch", "the file is a %s, not a %s", ct, declared)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg") {
		return nil, refuse("invalid_logo", "the logo cannot be read as a PNG or JPEG")
	}
	if cfg.Width < MinDim || cfg.Height < MinDim || cfg.Width > MaxDim || cfg.Height > MaxDim {
		return nil, refuse("logo_dimensions", "the logo is %dx%d pixels; it must be between %dx%d and %dx%d", cfg.Width, cfg.Height, MinDim, MinDim, MaxDim, MaxDim)
	}
	if _, _, err := image.Decode(bytes.NewReader(data)); err != nil { // bounded: at most MaxDim x MaxDim
		return nil, refuse("invalid_logo", "the logo is corrupt")
	}
	sum := sha256.Sum256(data)
	return &Logo{Data: data, ContentType: ct, Width: cfg.Width, Height: cfg.Height, SHA256: hex.EncodeToString(sum[:])}, nil
}
