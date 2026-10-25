package salesforce

import "context"

// SOQL runs a read-only SOQL query and returns every row (following the paging links), for another
// Salesforce connector that reuses this client's JWT bearer sign-in. The caller builds soql from constants and
// ids it has validated (idRE); it never carries free text.
func (c *Client) SOQL(ctx context.Context, soql string) ([]map[string]any, error) {
	rows, err := c.rows(ctx, soql)
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out, err
}

// IDValid reports whether s has the shape of a Salesforce record id.
func IDValid(s string) bool { return idRE.MatchString(s) }

// Identity is the integration user the client signs in as.
func (c *Client) Identity() string { return c.cfg.Username }
