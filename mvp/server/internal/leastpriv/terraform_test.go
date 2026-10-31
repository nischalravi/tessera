package leastpriv

import (
	"strings"
	"testing"
	"unicode/utf8"
)

const tfDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/${aws:username}/*"}]}`

func TestTerraform(t *testing.T) {
	in := TerraformInput{ID: "c1", PolicyARN: "arn:aws:iam::111111111111:policy/App-Read", Document: tfDoc, UnusedDays: 90, Confidence: "medium", Removed: 2}
	got, err := Terraform(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`resource "aws_iam_policy" "App_Read" {`, `name   = "App-Read"`, "<<-POLICY", "  POLICY\n}", "$${aws:username}",
		"drops 2 unused permission(s)", "last 90 days", "evidence confidence: medium"} {
		if !strings.Contains(got, want) {
			t.Errorf("snippet lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "path ") {
		t.Errorf("a policy at the root path names a path:\n%s", got)
	}
	// a policy variable is never left for Terraform to interpolate
	if strings.Contains(strings.ReplaceAll(got, "$${", ""), "${") {
		t.Errorf("an unescaped interpolation:\n%s", got)
	}
	if again, _ := Terraform(in); again != got {
		t.Error("not deterministic")
	}
	in.Removed = -1
	if s, _ := Terraform(in); strings.Contains(s, "drops") {
		t.Error("a removal count that is not known is stated")
	}
}

func TestTerraformRefusals(t *testing.T) {
	for name, in := range map[string]TerraformInput{
		"an AWS managed policy":  {PolicyARN: "arn:aws:iam::aws:policy/ReadOnlyAccess", Document: tfDoc},
		"not a policy":           {PolicyARN: "arn:aws:iam::111111111111:role/r", Document: tfDoc},
		"no name":                {PolicyARN: "arn:aws:iam::111111111111:policy/team/", Document: tfDoc},
		"a name that breaks out": {PolicyARN: "arn:aws:iam::111111111111:policy/a\"}\nresource \"x\" \"y\" {", Document: tfDoc},
		"an interpolation":       {PolicyARN: "arn:aws:iam::111111111111:policy/${x}", Document: tfDoc},
		"not json":               {PolicyARN: "arn:aws:iam::111111111111:policy/P", Document: "{"},
	} {
		if s, err := Terraform(in); err == nil {
			t.Errorf("%s: got a snippet:\n%s", name, s)
		}
	}
}

func TestTerraformNamesAreCutToPlainText(t *testing.T) {
	got, err := Terraform(TerraformInput{ID: "c1\nresource \"evil\" \"x\" {}", PolicyARN: "arn:aws:iam::111111111111:policy/9-start/Name.With-Dots", Document: tfDoc, UnusedDays: 90, Confidence: "high\n#x", Removed: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "resource") && !strings.HasPrefix(line, `resource "aws_iam_policy" "Name_With_Dots"`) {
			t.Errorf("an injected resource: %q", line)
		}
	}
	if !strings.Contains(got, `path   = "/9-start/"`) {
		t.Errorf("path missing:\n%s", got)
	}
}

func TestTerraformCommentStripsFormatCharactersAndCutsOnRunes(t *testing.T) {
	got, err := Terraform(TerraformInput{ID: "a\u202Eb\u200Bc\ufeffd\u2066e", PolicyARN: "arn:aws:iam::111111111111:policy/P", Document: tfDoc,
		UnusedDays: 90, Confidence: strings.Repeat("é", 300), Removed: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r == 0x202e || r == 0x200b || r == 0xfeff || r == 0x2066 {
			t.Errorf("a format character survived: %U", r)
		}
	}
	if !strings.Contains(got, strings.Repeat("é", 200)+"...") || strings.Contains(got, strings.Repeat("é", 201)) || !utf8.ValidString(got) {
		t.Errorf("the comment is not cut on a rune boundary:\n%s", got)
	}
}
