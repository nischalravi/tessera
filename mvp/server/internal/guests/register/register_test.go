package register

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	ok := Request{GivenName: " Gwen ", FamilyName: "Guest", Email: "Gwen@Guest.Example", Purpose: "talk", EndsAt: now.AddDate(0, 0, 5), Handle: "h"}
	s := &Service{}
	got, err := s.Validate(ok, now)
	if err != nil || got.GivenName != "Gwen" || got.Email != "gwen@guest.example" || !got.StartsAt.Equal(now) {
		t.Fatalf("Validate(ok) = %+v, %v", got, err)
	}
	mod := func(f func(*Request)) Request { r := ok; f(&r); return r }
	for name, in := range map[string]Request{
		"no given name":   mod(func(r *Request) { r.GivenName = " " }),
		"long name":       mod(func(r *Request) { r.GivenName = strings.Repeat("x", MaxName+1) }),
		"control char":    mod(func(r *Request) { r.Purpose = "a\x00b" }),
		"no purpose":      mod(func(r *Request) { r.Purpose = "" }),
		"bad email":       mod(func(r *Request) { r.Email = "nope" }),
		"long email":      mod(func(r *Request) { r.Email = strings.Repeat("a", MaxEmail) + "@x.example" }),
		"no sponsor":      mod(func(r *Request) { r.Handle = "" }),
		"long code":       mod(func(r *Request) { r.Handle, r.Code = "", strings.Repeat("A", MaxCode+1) }),
		"ends in past":    mod(func(r *Request) { r.EndsAt = now.Add(-time.Hour) }),
		"ends before":     mod(func(r *Request) { r.StartsAt = now.AddDate(0, 0, 9) }),
		"too long a stay": mod(func(r *Request) { r.EndsAt = now.AddDate(0, 0, MaxTermDays+2) }),
		"starts too far": mod(func(r *Request) {
			r.StartsAt, r.EndsAt = now.AddDate(0, 0, MaxTermDays+1), now.AddDate(0, 0, MaxTermDays+5)
		}),
	} {
		if _, err := s.Validate(in, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{"abcde-fghjk": "ABCDEFGHJK", " ABCDE FGHJK ": "ABCDEFGHJK", "AbC-dE": "ABCDE"} {
		if got := normalizeCode(in); got != want {
			t.Errorf("normalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := newCode()
		if err != nil || len(c) != 11 || c[5] != '-' || strings.ContainsAny(c, "IO01") {
			t.Fatalf("newCode = %q, %v", c, err)
		}
		seen[c] = true
	}
	if len(seen) < 50 {
		t.Errorf("codes repeat: %d distinct of 50", len(seen))
	}
}

func TestChallengers(t *testing.T) {
	if ok, _ := (AllowAll{}).Verify(context.Background(), "", ""); !ok {
		t.Error("AllowAll refused")
	}
	f := Fake{Token: "pass"}
	if ok, _ := f.Verify(context.Background(), "pass", ""); !ok {
		t.Error("Fake refused its token")
	}
	if ok, _ := f.Verify(context.Background(), "", ""); ok {
		t.Error("Fake accepted no token")
	}
}
