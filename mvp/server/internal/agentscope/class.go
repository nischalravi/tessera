package agentscope

import "strings"

// ClassOf is the action class of a permission: delegate (it lets the holder act as, or pass authority to,
// another principal), admin (it is privileged, a wildcard, or changes who can do what), read (it only observes)
// or write (everything else, so a verb nobody classified is never taken for a read). privileged is the
// permission's own flag from the connector and makes it admin unless it delegates.
//
// The class is read from the action name as a connector reports it ("s3:GetObject", "iam:PassRole", "read"); the
// service prefix is ignored except for delegation words and the bare wildcard.
func ClassOf(action string, privileged bool) string {
	a := strings.ToLower(strings.TrimSpace(action))
	verb := a
	if i := strings.LastIndex(a, ":"); i >= 0 {
		verb = a[i+1:]
	}
	switch {
	case hasAny(a, delegateWords):
		return ClassDelegate
	case privileged, verb == "*", verb == "":
		return ClassAdmin
	case hasPrefixAny(verb, readVerbs):
		return ClassRead
	case hasAny(verb, adminWords), strings.HasSuffix(verb, "*"):
		return ClassAdmin
	}
	return ClassWrite
}

var (
	delegateWords = []string{"passrole", "assumerole", "impersonat", "delegat", "run_as", "act_as", "sudo", "tokenexchange", "token_exchange"}
	adminWords    = []string{"admin", "owner", "manage", "policy", "policies", "acl", "attach", "detach", "createrole", "createuser",
		"createaccesskey", "grant", "revoke", "keydeletion", "deletekey", "permission"}
	readVerbs = []string{"get", "list", "describe", "head", "read", "select", "view", "query", "scan", "search", "fetch",
		"download", "show", "lookup", "batchget", "browse"}
)

func hasAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
