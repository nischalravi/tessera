package migration

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

type xmlNode struct {
	Name     string
	Attr     map[string]string
	Text     string
	Children []*xmlNode
}

// XML is read token by token; only one bounded top-level object is retained.
// No DTD, entity, export link, rule, or embedded Source is ever evaluated.
func parseXML(b []byte, r *Report) error {
	d := xml.NewDecoder(bytes.NewReader(b))
	var stack []*xmlNode
	tokens, objects, roots := 0, 0, 0
	wrapper := false
	r.Snapshot.SchemaVersion = 1
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("migration: invalid XML")
		}
		tokens++
		if tokens > MaxTokens {
			return errors.New("migration: XML token limit")
		}
		switch x := t.(type) {
		case xml.Directive:
			// A bare IIQ external DTD declaration is inert in encoding/xml.
			// Internal subsets and all other directives are rejected.
			s := strings.TrimSpace(string(x))
			if !strings.HasPrefix(s, "DOCTYPE ") || strings.ContainsAny(s, "[]") || strings.Contains(strings.ToUpper(s), "ENTITY") {
				return errors.New("migration: XML entities/directives refused")
			}
		case xml.StartElement:
			if x.Name.Space != "" || len(x.Name.Local) > MaxValueBytes || len(x.Attr) > 128 {
				return errors.New("migration: XML namespace, name or attribute-count limit")
			}
			if len(stack) == 0 {
				roots++
				if roots > 1 {
					return errors.New("migration: multiple XML roots")
				}
				wrapper = x.Name.Local == "sailpoint"
			}
			if len(stack) >= MaxDepth {
				return errors.New("migration: XML nesting limit")
			}
			n := &xmlNode{Name: x.Name.Local, Attr: map[string]string{}}
			for _, a := range x.Attr {
				if a.Name.Space != "" || len(a.Value) > MaxValueBytes || len(a.Name.Local) > MaxValueBytes {
					return errors.New("migration: XML attribute limit or namespace")
				}
				if _, exists := n.Attr[a.Name.Local]; exists {
					return errors.New("migration: duplicate XML attribute")
				}
				n.Attr[a.Name.Local] = a.Value
			}
			if len(stack) > 0 && !(wrapper && len(stack) == 1) {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			}
			stack = append(stack, n)
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(x)) != "" {
					return errors.New("migration: text outside XML root")
				}
				continue
			}
			n := stack[len(stack)-1]
			if len(n.Text)+len(x) > MaxValueBytes {
				return errors.New("migration: XML text limit")
			}
			n.Text += string(x)
		case xml.EndElement:
			if len(stack) == 0 {
				return errors.New("migration: invalid XML nesting")
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) == 0 && wrapper {
				if len(n.Attr) > 0 || strings.TrimSpace(n.Text) != "" {
					r.unsupportedXML(n, "snapshot", "", "wrapper_metadata")
				}
			} else if (wrapper && len(stack) == 1) || (!wrapper && len(stack) == 0) {
				objects++
				if objects > MaxRecords {
					return errors.New("migration: XML object limit")
				}
				r.xmlObject(n)
			}
		}
	}
	if roots != 1 || len(stack) != 0 {
		return errors.New("migration: empty or incomplete XML")
	}
	return nil
}

func (r *Report) unsupportedXML(n *xmlNode, kind, id, field string) {
	b, _ := json.Marshal(n)
	r.diagnostic("unsupported_xml_semantics", kind, id, field, digest(b))
}
func (r *Report) xmlID(n *xmlNode, kind string) string {
	if n.Attr["id"] != "" {
		return n.Attr["id"]
	}
	// Clean exports often strip IDs. Keep a provisional source-local reference,
	// never infer a live identity from its name or email.
	id := n.Attr["name"]
	if id == "" {
		b, _ := json.Marshal(n)
		id = "provisional-" + digest(b)
	}
	r.diagnostic("provisional_source_id", kind, id, "id", "")
	return id
}
func owner(n *xmlNode) string {
	for _, c := range n.Children {
		if c.Name == "Owner" {
			for _, ref := range c.Children {
				if ref.Name == "Reference" && ref.Attr["class"] == "sailpoint.object.Identity" {
					return ref.Attr["id"]
				}
			}
		}
	}
	return ""
}
func (r *Report) xmlRemainder(n *xmlNode, kind, id string, allowedAttrs, allowedChildren []string) {
	has := func(values []string, value string) bool {
		for _, v := range values {
			if v == value {
				return true
			}
		}
		return false
	}
	for key, value := range n.Attr {
		if !has(allowedAttrs, key) {
			r.diagnostic("unsupported_xml_attribute", kind, id, key, digest([]byte(value)))
		}
	}
	if strings.TrimSpace(n.Text) != "" {
		r.diagnostic("unsupported_xml_text", kind, id, "text", digest([]byte(n.Text)))
	}
	for _, c := range n.Children {
		if !has(allowedChildren, c.Name) {
			r.unsupportedXML(c, kind, id, c.Name)
		}
	}
	// Even allowed owner structures must be exact; otherwise a nested script or
	// ignored reference attribute would disappear from the assessment.
	owners := 0
	for _, c := range n.Children {
		if c.Name == "Owner" {
			owners++
			valid := len(c.Attr) == 0 && strings.TrimSpace(c.Text) == "" && len(c.Children) == 1
			if valid {
				ref := c.Children[0]
				valid = ref.Name == "Reference" && ref.Attr["class"] == "sailpoint.object.Identity" && ref.Attr["id"] != "" && len(ref.Children) == 0 && strings.TrimSpace(ref.Text) == ""
				for k := range ref.Attr {
					if k != "class" && k != "id" && k != "name" {
						valid = false
					}
				}
			}
			if !valid {
				r.unsupportedXML(c, kind, id, "Owner")
			}
		}
	}
	if owners > 1 {
		r.unsupportedXML(n, kind, id, "ambiguous_owner")
	}
}
func (r *Report) xmlObject(n *xmlNode) {
	switch n.Name {
	case "Identity":
		id := r.xmlID(n, "identity")
		r.Snapshot.Identities = append(r.Snapshot.Identities, Identity{id, n.Attr["name"]})
		r.xmlRemainder(n, "identity", id, []string{"id", "name"}, []string{"Links"})
		for _, c := range n.Children {
			if c.Name == "Links" {
				if len(c.Attr) > 0 || strings.TrimSpace(c.Text) != "" {
					r.unsupportedXML(c, "identity", id, "Links_metadata")
				}
				for _, link := range c.Children {
					if link.Name == "Link" {
						r.xmlAccount(link, id)
					} else {
						r.unsupportedXML(link, "identity", id, "Links")
					}
				}
			}
		}
	case "Link":
		r.xmlAccount(n, "")
	case "ManagedAttribute":
		id := r.xmlID(n, "entitlement")
		r.Snapshot.Entitlements = append(r.Snapshot.Entitlements, Entitlement{id, n.Attr["application"], n.Attr["attribute"], n.Attr["value"], owner(n)})
		r.xmlRemainder(n, "entitlement", id, []string{"id", "application", "attribute", "value"}, []string{"Owner"})
	case "Bundle":
		id := r.xmlID(n, "role")
		r.Snapshot.Roles = append(r.Snapshot.Roles, Role{ID: id, Name: n.Attr["name"], OwnerID: owner(n), EntitlementIDs: []string{}})
		r.xmlRemainder(n, "role", id, []string{"id", "name"}, []string{"Owner"})
		// Profiles, selectors and inheritance are deliberately not translated.
		r.diagnostic("role_membership_mapping_pending", "role", id, "membership/entitlements", "")
	default:
		id := r.xmlID(n, "unsupported")
		r.unsupportedXML(n, "unsupported", id, n.Name)
	}
}
func (r *Report) xmlAccount(n *xmlNode, identityID string) {
	id := r.xmlID(n, "account")
	r.Snapshot.Accounts = append(r.Snapshot.Accounts, Account{id, identityID, n.Attr["application"], n.Attr["nativeIdentity"], []string{}})
	r.xmlRemainder(n, "account", id, []string{"id", "application", "nativeIdentity"}, nil)
	// Native membership attributes require vendor/schema-specific mapping.
	r.diagnostic("account_entitlement_mapping_pending", "account", id, "entitlement_ids", "")
}
