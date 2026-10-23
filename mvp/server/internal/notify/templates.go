package notify

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Templates (Admin > Notifications, schema/0762_notification_templates.sql): a tenant's own wording for the email of one
// notification kind. A template is text with {{name}} placeholders and nothing else: no logic, no data beyond the
// notification itself, so it cannot reach anything the notification does not already carry. The inbox entry is unchanged.

// Template limits.
const (
	MaxTemplateSubject = 300
	MaxTemplateBody    = 4000
)

// TemplateVars are the placeholders a template may use, with what each stands for.
var TemplateVars = []TemplateVar{
	{"subject", "The notification's own subject."},
	{"body", "The notification's own text."},
	{"link", "The address of the page the notification points to (empty when it has none)."},
	{"product", "The product name (Admin > Branding & labels)."},
	{"recipient", "The recipient's email address."},
}

// TemplateVar is one placeholder.
type TemplateVar struct {
	Name string `json:"name"`
	Help string `json:"help"`
}

var placeholderRE = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*\}\}`)

func knownVar(n string) bool {
	for _, v := range TemplateVars {
		if v.Name == n {
			return true
		}
	}
	return false
}

// CheckTemplate validates the wording of one kind. An empty subject or body keeps the producer's.
func CheckTemplate(kind, subject, body string) error {
	if _, ok := KindByID(kind); !ok {
		return cfgerr.Refuse(404, "unknown_kind", "%q is not a notification kind", kind)
	}
	if len(subject) > MaxTemplateSubject || len(body) > MaxTemplateBody {
		return cfgerr.Refuse(422, "template_too_long", "a subject is at most %d characters and a body %d", MaxTemplateSubject, MaxTemplateBody)
	}
	if strings.TrimSpace(subject) == "" && strings.TrimSpace(body) == "" {
		return cfgerr.Refuse(422, "template_empty", "give a subject or a body, or reset the kind to its default")
	}
	if strings.ContainsAny(subject, "\r\n") {
		return cfgerr.Refuse(422, "invalid_subject", "a subject is one line")
	}
	for _, t := range []string{subject, body} {
		for _, m := range placeholderRE.FindAllStringSubmatch(t, -1) {
			if !knownVar(m[1]) {
				return cfgerr.Refuse(422, "unknown_placeholder", "{{%s}} is not a placeholder: use one of subject, body, link, product, recipient", m[1])
			}
		}
		if rest := placeholderRE.ReplaceAllString(t, ""); strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
			return cfgerr.Refuse(422, "invalid_placeholder", "a placeholder is written {{name}}")
		}
		for _, r := range t {
			if r < ' ' && r != '\n' && r != '\t' && r != '\r' || r == 0x7f {
				return cfgerr.Refuse(422, "invalid_text", "a template is plain text without control characters")
			}
		}
	}
	return nil
}

// Render fills the placeholders of a template. An unknown placeholder (never saved, but a stored row is data) is left out.
func Render(tpl string, vars map[string]string) string {
	return placeholderRE.ReplaceAllStringFunc(tpl, func(m string) string {
		return vars[placeholderRE.FindStringSubmatch(m)[1]]
	})
}

// Templates returns the tenant's wording by kind.
func Templates(tx *store.TenantTx) (map[string]store.NotificationTemplateRow, error) {
	rows, err := tx.NotificationTemplates()
	if err != nil {
		return nil, err
	}
	out := make(map[string]store.NotificationTemplateRow, len(rows))
	for _, r := range rows {
		out[r.Kind] = *r
	}
	return out, nil
}

// SaveTemplate saves the wording of a kind and audits it.
func SaveTemplate(tx *store.TenantTx, kind, subject, body, by string, now time.Time) error {
	if err := CheckTemplate(kind, subject, body); err != nil {
		return err
	}
	if err := tx.PutNotificationTemplate(&store.NotificationTemplateRow{Kind: kind, Subject: subject, Body: body, UpdatedBy: by}, now); err != nil {
		return err
	}
	return tx.Audit(now, by, "notification.template.update", ojson.Object{{Key: "kind", Value: kind},
		{Key: "subject_length", Value: len(subject)}, {Key: "body_length", Value: len(body)}})
}

// ResetTemplate returns a kind to the producer's wording and audits it.
func ResetTemplate(tx *store.TenantTx, kind, by string, now time.Time) error {
	if _, ok := KindByID(kind); !ok {
		return cfgerr.Refuse(404, "unknown_kind", "%q is not a notification kind", kind)
	}
	if err := tx.DeleteNotificationTemplate(kind); errors.Is(err, store.ErrNotFound) {
		return cfgerr.Refuse(404, "template_not_found", "that kind has no template of its own")
	} else if err != nil {
		return err
	}
	return tx.Audit(now, by, "notification.template.reset", ojson.Object{{Key: "kind", Value: kind}})
}
