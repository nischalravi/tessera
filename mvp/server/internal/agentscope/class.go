package agentscope

import "strings"

// ClassOf is the action class of a permission: delegate (it lets the holder act as, or pass authority to,
// another principal), admin (it is privileged, a wildcard, or changes who can do what), read (it only observes)
// or write (everything else, so a verb nobody classified is never taken for a read). privileged is the
// permission's own flag from the connector and makes it admin unless it delegates.
//
// The class is read from the action name as a connector reports it ("s3:GetObject", "iam:PassRole",
// "Microsoft.Authorization/roleAssignments/write", "iam.serviceAccounts.actAs", "read"). The verb is the last
// segment after ":", "/" or "."; for a name with three or more segments (Azure, GCP) the segment before the verb
// names the object and counts too, so a write to role assignments is admin. A wildcard anywhere in the verb is
// admin, never read: "s3:Get*" also matches credential-minting verbs.
func ClassOf(action string, privileged bool) string {
	a := strings.ToLower(strings.TrimSpace(action))
	segs := strings.FieldsFunc(a, func(r rune) bool { return r == ':' || r == '/' || r == '.' })
	verb, obj := "", ""
	if n := len(segs); n > 0 {
		verb = segs[n-1]
		if n >= 3 {
			obj = segs[n-2]
		}
	}
	switch {
	case hasAny(a, delegateWords), verb == "actas":
		return ClassDelegate
	case privileged, verb == "", strings.ContainsAny(verb, "*?"):
		return ClassAdmin
	case hasPrefixAny(verb, readVerbs):
		return ClassRead
	case hasAny(verb, adminWords), hasAny(obj, adminWords):
		return ClassAdmin
	}
	return ClassWrite
}

var (
	delegateWords = []string{"passrole", "assumerole", "impersonat", "delegat", "run_as", "act_as", "sudo", "tokenexchange", "token_exchange",
		// verbs that mint credentials for a principal, checked before the read prefixes since most begin with "get"
		"getfederationtoken", "getsessiontoken", "getclustercredentials", "getauthorizationtoken", "getcredentials",
		"getaccesstoken", "generateaccesstoken", "generateidtoken", "signjwt", "signblob"}
	adminWords = []string{"admin", "owner", "manage", "policy", "policies", "acl", "attach", "detach", "createrole", "createuser",
		"createaccesskey", "grant", "revoke", "keydeletion", "deletekey", "permission",
		"loginprofile", "addusertogroup", "servicelinkedrole", "mfadevice", "roleassignment"}
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
