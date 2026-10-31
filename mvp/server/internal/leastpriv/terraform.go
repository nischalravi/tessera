package leastpriv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Terraform is the suggestion for a right-sized AWS managed policy (issue #665, LP-9): a narrowed aws_iam_policy resource
// the user pastes over their own. It is text only; nothing here writes anywhere.

// TerraformInput is one verified right-size.
type TerraformInput struct {
	// ID is the candidate's id, PolicyARN the managed policy and Document the policy document it is narrowed to.
	ID        string
	PolicyARN string
	Document  string
	// UnusedDays and Confidence are the evidence behind it; Removed is how many permissions it takes out when known (-1: not known).
	UnusedDays int
	Confidence string
	Removed    int
}

// Terraform renders the suggestion. The same input gives the same text: the document is re-indented from its canonical
// JSON, and nothing in it is a time or a random value. Names that come from the estate are cut to plain characters.
func Terraform(in TerraformInput) (string, error) {
	name, path, ok := policyName(in.PolicyARN)
	if !ok {
		return "", errors.New("leastpriv: the policy ARN is not a customer managed policy")
	}
	var doc bytes.Buffer
	if err := json.Indent(&doc, []byte(in.Document), "", "  "); err != nil {
		return "", errors.New("leastpriv: the right-sized document is not JSON")
	}
	body := hclEscape(jsonEscapeUnsafe(doc.String()))
	var b strings.Builder
	fmt.Fprintf(&b, "# Tessera right-sizing suggestion %s: the policy below keeps what was used in the last %d days", comment(in.ID), in.UnusedDays)
	if in.Removed >= 0 {
		fmt.Fprintf(&b, " and drops %d unused permission(s)", in.Removed)
	}
	fmt.Fprintf(&b, " (evidence confidence: %s).\n", comment(in.Confidence))
	b.WriteString("# Replace the policy document of your own resource for this policy with it, review the plan, and apply it yourself.\n")
	fmt.Fprintf(&b, "# Policy: %s\n", comment(in.PolicyARN))
	fmt.Fprintf(&b, "resource \"aws_iam_policy\" %q {\n", label(name))
	fmt.Fprintf(&b, "  name   = %q\n", name)
	if path != "/" {
		fmt.Fprintf(&b, "  path   = %q\n", path)
	}
	b.WriteString("  policy = <<-POLICY\n")
	for _, line := range strings.Split(body, "\n") {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString("  POLICY\n}\n")
	return b.String(), nil
}

// policyName splits arn:aws:iam::<account>:policy/<path>/<name> into the name and the path ("/" or "/a/b/"). An AWS
// managed policy (account "aws") is not suggested: it cannot be edited.
func policyName(arn string) (name, path string, ok bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[4] == "aws" || parts[4] == "" || !strings.HasPrefix(parts[5], "policy/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(parts[5], "policy/")
	i := strings.LastIndex(rest, "/")
	path = "/"
	if i >= 0 {
		path, rest = "/"+rest[:i+1], rest[i+1:]
	}
	if rest == "" || strings.ContainsAny(rest+path, "\"\\\n\r\x00${}%") || len(rest) > 128 {
		return "", "", false
	}
	return rest, path, true
}

// label makes a Terraform resource label: letters, digits and underscores, not starting with a digit.
func label(name string) string {
	l := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		}
		return '_'
	}, name)
	if l == "" || (l[0] >= '0' && l[0] <= '9') {
		l = "p_" + l
	}
	return l
}

// unsafeRune is the set ghapp's unsafeRune strips: controls, separators, bidi and zero-width characters.
func unsafeRune(r rune) bool {
	return r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == 0x061c || r == 0xfeff ||
		(r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2060 && r <= 0x2069)
}

// jsonEscapeUnsafe writes every unsafe rune of an indented JSON document other than its newlines as a \uXXXX escape (issue
// #794). Valid JSON holds such a rune only inside a string (outside, there is only ASCII whitespace), where the escape
// is the same character, so the policy is unchanged while nothing invisible or reordering reaches the snippet.
func jsonEscapeUnsafe(doc string) string {
	var b strings.Builder
	for _, r := range doc {
		if r != '\n' && r != ' ' && unsafeRune(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// comment cuts text from the estate to one short line of plain characters, for a Terraform comment.
func comment(s string) string {
	s = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return ' ' // the same set as ghapp's unsafeRune: controls, separators, bidi and zero-width characters
		}
		return r
	}, s)
	if rs := []rune(s); len(rs) > 200 {
		s = string(rs[:200]) + "..."
	}
	return s
}

// hclEscape stops Terraform reading a policy variable such as ${aws:username} (or a %{ directive) in a heredoc as a template
// sequence: "$${" and "%%{" are the literal text.
func hclEscape(s string) string {
	return strings.NewReplacer("${", "$${", "%{", "%%{").Replace(s)
}
