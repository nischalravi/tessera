package connsync

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

// MaxPages bounds one paged walk, so a source that never stops paging (or
// links in a circle) cannot keep a sync running forever.
const MaxPages = 20000

// ErrPaging is returned when a walk exceeds MaxPages or revisits a page link.
var ErrPaging = errors.New("connsync: paging does not terminate")

// Walk follows a chain of pages. page fetches one URL and returns the next
// page's URL, or "" at the end. next links are validated against base (same
// origin) by Walk before they are followed.
func Walk(ctx context.Context, base *url.URL, first string, page func(ctx context.Context, pageURL string) (string, error)) error {
	seen := map[string]bool{}
	cur := first
	for n := 0; cur != ""; n++ {
		if n >= MaxPages || seen[cur] {
			return ErrPaging
		}
		seen[cur] = true
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := page(ctx, cur)
		if err != nil {
			return err
		}
		if next != "" {
			u, err := SameOrigin(base, next)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			next = u.String()
		}
		cur = next
	}
	return nil
}
