package branding

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"maps"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func img(w, h int) image.Image {
	m := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			m.Set(x, y, color.RGBA{uint8(x), uint8(y), 120, 255})
		}
	}
	return m
}

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img(w, h)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func jpegBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img(w, h), nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func TestColors(t *testing.T) {
	for _, tc := range []struct {
		name, primary, on string
		wantPrimary       string
		wantOn            string
		wantCode          string
	}{
		{"default blue with white", "#0f6cbd", "#ffffff", "#0f6cbd", "#ffffff", ""},
		{"upper case is normalised", "#0F6CBD", "#FFFFFF", "#0f6cbd", "#ffffff", ""},
		{"text colour chosen: dark background", "#1a1a1a", "", "#1a1a1a", "#ffffff", ""},
		{"text colour chosen: light background", "#ffe08a", "", "#ffe08a", "#000000", ""},
		{"mid orange picks the better of black and white", "#ff8800", "", "#ff8800", "#000000", ""},
		{"white on yellow fails AA", "#ffe08a", "#ffffff", "", "", "low_contrast"},
		{"grey on grey fails AA", "#777777", "#888888", "", "", "low_contrast"},
		{"white on mid grey just fails", "#808080", "#ffffff", "", "", "low_contrast"},
		{"short form refused", "#fff", "#000", "", "", "invalid_color"},
		{"no hash", "0f6cbd", "#ffffff", "", "", "invalid_color"},
		{"not hex", "#zzzzzz", "#ffffff", "", "", "invalid_color"},
		{"css injection", "#000000;background:url(x)", "#ffffff", "", "", "invalid_color"},
		{"empty primary", "", "#ffffff", "", "", "invalid_color"},
		{"bad text colour", "#0f6cbd", "white", "", "", "invalid_color"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, o, err := Colors(tc.primary, tc.on)
			if got := code(err); got != tc.wantCode {
				t.Fatalf("code = %q, want %q (%v)", got, tc.wantCode, err)
			}
			if err == nil && (p != tc.wantPrimary || o != tc.wantOn) {
				t.Errorf("= %s on %s, want %s on %s", p, o, tc.wantPrimary, tc.wantOn)
			}
			if err == nil {
				if c, _ := Contrast(p, o); c < MinContrast {
					t.Errorf("accepted a pair with contrast %.2f", c)
				}
			}
		})
	}
	if c, _ := Contrast("#000000", "#ffffff"); c < 20.9 || c > 21.1 {
		t.Errorf("black on white = %.2f, want 21", c)
	}
	_, _, err := Colors("#ffe08a", "#ffffff")
	if !strings.Contains(err.Error(), "#000000") {
		t.Errorf("the refusal does not suggest a colour that works: %v", err)
	}
}

func TestName(t *testing.T) {
	for in, want := range map[string]string{"Larkspur": "Larkspur", "  Larkspur Health  ": "Larkspur Health", "Café ☕": "Café ☕"} {
		if got, err := Name(in); err != nil || got != want {
			t.Errorf("Name(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "   ", strings.Repeat("x", MaxName+1), "Lark<script>", "a\x00b", "a\nb"} {
		if _, err := Name(in); code(err) != "invalid_name" {
			t.Errorf("Name(%q) = %v", in, err)
		}
	}
}

func TestCheckLogo(t *testing.T) {
	big := pngBytes(t, 40, 40)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><script>alert(1)</script></svg>`)
	gif := []byte("GIF89a\x40\x00\x40\x00\x00\x00\x00;")
	corrupt := append(pngBytes(t, 64, 64)[:80], bytes.Repeat([]byte{0}, 40)...)
	for _, tc := range []struct {
		name     string
		data     []byte
		declared string
		wantType string
		wantW    int
		wantCode string
	}{
		{"png", pngBytes(t, 64, 48), "image/png", "image/png", 64, ""},
		{"png without a declared type", pngBytes(t, 64, 48), "", "image/png", 64, ""},
		{"jpeg", jpegBytes(t, 100, 100), "image/jpeg", "image/jpeg", 100, ""},
		{"smallest size", pngBytes(t, MinDim, MinDim), "", "image/png", MinDim, ""},
		{"largest size", pngBytes(t, MaxDim, 40), "", "image/png", MaxDim, ""},
		{"svg", svg, "image/svg+xml", "", 0, "svg_not_allowed"},
		{"svg declared as png", svg, "image/png", "", 0, "svg_not_allowed"},
		{"html", []byte("<html><body>x</body></html>"), "", "", 0, "svg_not_allowed"},
		{"gif", gif, "image/gif", "", 0, "invalid_logo"},
		{"png declared as jpeg", big, "image/jpeg", "", 0, "type_mismatch"},
		{"too small", pngBytes(t, 16, 16), "", "", 0, "logo_dimensions"},
		{"too wide", pngBytes(t, MaxDim+1, 40), "", "", 0, "logo_dimensions"},
		{"empty", nil, "", "", 0, "invalid_logo"},
		{"text", []byte("hello"), "", "", 0, "invalid_logo"},
		{"corrupt png", corrupt, "", "", 0, "invalid_logo"},
		{"over the size cap", append(pngBytes(t, 64, 64), bytes.Repeat([]byte{0}, MaxLogoBytes)...), "", "", 0, "logo_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := CheckLogo(tc.data, tc.declared)
			if got := code(err); got != tc.wantCode {
				t.Fatalf("code = %q, want %q (%v)", got, tc.wantCode, err)
			}
			if err == nil && (l.ContentType != tc.wantType || l.Width != tc.wantW || len(l.SHA256) != 64) {
				t.Errorf("logo = %+v", l)
			}
		})
	}
}

func TestLabels(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		want map[string]string
		code string
	}{
		{"rename", map[string]string{"entitlement": "permission set"}, map[string]string{"entitlement": "permission set"}, ""},
		{"spaces are tidied", map[string]string{"group": "  work   team "}, map[string]string{"group": "work team"}, ""},
		{"the default is dropped", map[string]string{"guest": "Guest"}, map[string]string{}, ""},
		{"unicode letters", map[string]string{"application": "système"}, map[string]string{"application": "système"}, ""},
		{"unknown term", map[string]string{"role": "job"}, nil, "invalid_label_term"},
		{"empty", map[string]string{"group": "  "}, nil, "invalid_label"},
		{"too long", map[string]string{"group": strings.Repeat("a", MaxLabel+1)}, nil, "invalid_label"},
		{"markup", map[string]string{"group": "<b>team</b>"}, nil, "invalid_label"},
		{"control character", map[string]string{"group": "team\u0000"}, nil, "invalid_label"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Labels(tc.in)
			if tc.code != "" {
				var be *Error
				if !errors.As(err, &be) || be.Code != tc.code {
					t.Fatalf("err = %v, want %s", err, tc.code)
				}
				return
			}
			if err != nil || !maps.Equal(got, tc.want) {
				t.Errorf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestSaveSettings(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if s, v, err := LoadSettings(c); err != nil || v != 0 || s.DefaultLanguage != "" || s.EmailLogo || len(s.Labels) != 0 {
			t.Fatalf("defaults = %+v v%d %v", s, v, err)
		}
		in := Settings{DefaultLanguage: "de-DE", EmailLogo: true, Labels: map[string]string{"entitlement": "permission set"}}
		if _, v, err := SaveSettings(c, in, 0, "admin", now); err != nil || v != 1 {
			t.Fatalf("save = v%d %v", v, err)
		}
		if s, v, err := LoadSettings(c); err != nil || v != 1 || s.DefaultLanguage != "de-DE" || !s.EmailLogo || s.Labels["entitlement"] != "permission set" {
			t.Fatalf("after = %+v v%d %v", s, v, err)
		}
		var ce *cfgerr.Error
		if _, _, err := SaveSettings(c, in, 0, "admin", now); !errors.As(err, &ce) || ce.Code != "version_conflict" {
			t.Errorf("stale save = %v", err)
		}
		in.DefaultLanguage = "xx-XX"
		if _, _, err := SaveSettings(c, in, 1, "admin", now); !errors.As(err, &ce) || ce.Code != "invalid_language" {
			t.Errorf("unknown language = %v", err)
		}
		in.DefaultLanguage = ""
		in.Labels = map[string]string{"nope": "x"}
		var be *Error
		if _, _, err := SaveSettings(c, in, 1, "admin", now); !errors.As(err, &be) || be.Code != "invalid_label_term" {
			t.Errorf("unknown term = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// B is untouched
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if s, v, err := LoadSettings(c); err != nil || v != 0 || s.DefaultLanguage != "" {
			t.Errorf("B = %+v v%d %v", s, v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
