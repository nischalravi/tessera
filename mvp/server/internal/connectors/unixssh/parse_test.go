package unixssh

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParsePasswd(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		ok   []string
		bad  int
	}{
		{"plain", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\n", []string{"root", "alice"}, 0},
		{"blank lines", "\nroot:x:0:0::/root:/bin/sh\n\n", []string{"root"}, 0},
		{"crlf", "root:x:0:0::/root:/bin/sh\r\n", []string{"root"}, 0},
		{"machine account", "host1$:x:1500:1500::/home:/bin/false\n", []string{"host1$"}, 0},
		{"too few fields", "root:x:0:0:/root\n", nil, 1},
		{"too many fields", "root:x:0:0:a:/root:/bin/sh:extra\n", nil, 1},
		{"non numeric uid", "root:x:zero:0::/root:/bin/sh\n", nil, 1},
		{"negative uid", "root:x:-1:0::/root:/bin/sh\n", nil, 1},
		{"uid over 32 bits", "root:x:4294967296:0::/root:/bin/sh\n", nil, 1},
		{"name with a space", "a b:x:1:1::/h:/bin/sh\n", nil, 1},
		{"name with a slash", "../x:x:1:1::/h:/bin/sh\n", nil, 1},
		{"empty name", ":x:1:1::/h:/bin/sh\n", nil, 1},
		{"control character", "alice:x:1:1:a\x1bb:/h:/bin/sh\n", nil, 1},
		{"invalid utf-8", "alice:x:1:1:\xff\xfe:/h:/bin/sh\n", nil, 1},
		{"duplicate name", "a:x:1:1::/h:/bin/sh\na:x:2:2::/h:/bin/sh\n", []string{"a"}, 1},
		{"field too long", "a:x:1:1:" + strings.Repeat("g", 300) + ":/h:/bin/sh\n", nil, 1},
		{"good and bad", "a:x:1:1::/h:/bin/sh\nnonsense\nb:x:2:2::/h:/bin/sh\n", []string{"a", "b"}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, bad := ParsePasswd([]byte(c.in))
			var names []string
			for _, a := range got {
				names = append(names, a.Name)
			}
			if !slices.Equal(names, c.ok) || bad != c.bad {
				t.Errorf("names %v bad %d, want %v %d", names, bad, c.ok, c.bad)
			}
		})
	}
	got, _ := ParsePasswd([]byte("root:x:0:0:r:/root:/bin/bash\nbob:x:1001:100::/home/bob:/bin/sh\n"))
	if !got[0].Privileged || got[1].Privileged || got[1].GID != 100 || got[1].Home != "/home/bob" || got[1].Shell != "/bin/sh" {
		t.Errorf("fields: %+v", got)
	}
}

func TestParsePasswdLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxAccounts+5; i++ {
		b.WriteString("u" + strings.Repeat("x", 3) + itoa(i) + ":x:1:1::/h:/bin/sh\n")
	}
	got, bad := ParsePasswd([]byte(b.String()))
	if len(got) != maxAccounts || bad != 5 {
		t.Errorf("%d accounts, %d bad", len(got), bad)
	}
}

func itoa(i int) string {
	const d = "0123456789"
	if i == 0 {
		return "0"
	}
	var out []byte
	for ; i > 0; i /= 10 {
		out = append([]byte{d[i%10]}, out...)
	}
	return string(out)
}

func TestParseGroup(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		ok   map[string][]string
		bad  int
	}{
		{"members", "devs:x:100:alice,bob\nempty:x:101:\n", map[string][]string{"devs": {"alice", "bob"}, "empty": nil}, 0},
		{"too few fields", "devs:x:100\n", nil, 1},
		{"bad gid", "devs:x:abc:alice\n", nil, 1},
		{"member with a space", "devs:x:100:alice, bob\n", nil, 1},
		{"empty member", "devs:x:100:alice,,bob\n", nil, 1},
		{"member with a control character", "devs:x:100:al\x00ice\n", nil, 1},
		{"duplicate", "a:x:1:\na:x:2:\n", map[string][]string{"a": nil}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, bad := ParseGroup([]byte(c.in))
			m := map[string][]string{}
			for _, g := range got {
				m[g.Name] = g.Members
			}
			if bad != c.bad || len(m) != len(c.ok) {
				t.Fatalf("got %v bad %d, want %v %d", m, bad, c.ok, c.bad)
			}
			for k, v := range c.ok {
				if !slices.Equal(m[k], v) {
					t.Errorf("%s members %v, want %v", k, m[k], v)
				}
			}
		})
	}
}

func TestParseLastlog(t *testing.T) {
	in := `Username         Port     From             Latest
root                                       **Never logged in**
alice            pts/0    10.1.2.3         Mon Oct 20 09:15:02 +0200 2026
bob                       192.168.0.4      Tue Oct  6 23:59:59 2026
weird line without a time
carol            tty1                      not a date at all
`
	got := ParseLastlog([]byte(in))
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if want := time.Date(2026, 10, 20, 7, 15, 2, 0, time.UTC); !got["alice"].Equal(want) {
		t.Errorf("alice = %v, want %v", got["alice"], want)
	}
	if want := time.Date(2026, 10, 6, 23, 59, 59, 0, time.UTC); !got["bob"].Equal(want) {
		t.Errorf("bob = %v", got["bob"])
	}
}

func TestParseSudoers(t *testing.T) {
	for _, c := range []struct {
		name    string
		in      string
		rules   int
		skipped int
		check   func(t *testing.T, r []Rule)
	}{
		{"comments and defaults", "# c\nDefaults env_reset\n\n@includedir /etc/sudoers.d\n#includedir /etc/sudoers.d\nHost_Alias H = a\nRunas_Alias R = b\n", 0, 0, nil},
		{"all", "root ALL=(ALL:ALL) ALL\n", 1, 0, func(t *testing.T, r []Rule) {
			if !r[0].Full || !slices.Equal(r[0].Principals, []string{"u:root"}) {
				t.Errorf("%+v", r[0])
			}
		}},
		{"group", "%sudo ALL=(ALL) ALL\n%admin ALL = (ALL) ALL\n", 2, 0, func(t *testing.T, r []Rule) {
			if !slices.Equal(r[0].Principals, []string{"g:sudo"}) || !slices.Equal(r[1].Principals, []string{"g:admin"}) {
				t.Errorf("%+v", r)
			}
		}},
		{"restricted", "bob ALL=(root) /usr/bin/less\n", 1, 0, func(t *testing.T, r []Rule) {
			if r[0].Full {
				t.Error("a single command is not full")
			}
		}},
		{"nopasswd all", "bob ALL=(root) NOPASSWD: ALL\n", 1, 0, func(t *testing.T, r []Rule) {
			if !r[0].Full {
				t.Error("ALL commands is full")
			}
		}},
		{"user list with spaces", "alice, bob ALL=(root) /bin/ls\n", 1, 0, func(t *testing.T, r []Rule) {
			if !slices.Equal(r[0].Principals, []string{"u:alice", "u:bob"}) {
				t.Errorf("%+v", r[0])
			}
		}},
		{"user alias", "User_Alias ADMINS = alice, %devs\nADMINS ALL=(ALL) ALL\n", 1, 0, func(t *testing.T, r []Rule) {
			if !slices.Equal(r[0].Principals, []string{"u:alice", "g:devs"}) {
				t.Errorf("%+v", r[0])
			}
		}},
		{"cmnd alias all", "Cmnd_Alias EVERYTHING = ALL\nbob ALL=(root) EVERYTHING\n", 1, 0, func(t *testing.T, r []Rule) {
			if !r[0].Full {
				t.Error("an alias of ALL is full")
			}
		}},
		{"cmnd alias limited", "Cmnd_Alias NET = /sbin/ip\nbob ALL=(root) NET\n", 1, 0, func(t *testing.T, r []Rule) {
			if r[0].Full {
				t.Error("a limited alias is not full")
			}
		}},
		{"ALL user has no principal", "ALL ALL=(ALL) /bin/true\n", 1, 0, func(t *testing.T, r []Rule) {
			if len(r[0].Principals) != 0 {
				t.Errorf("%+v", r[0])
			}
		}},
		{"negation grants nothing", "!mallory,alice ALL=(root) /bin/ls\n", 1, 0, func(t *testing.T, r []Rule) {
			if !slices.Equal(r[0].Principals, []string{"u:alice"}) {
				t.Errorf("%+v", r[0])
			}
		}},
		{"continuation", "alice ALL=(root) /bin/ls, \\\n  /bin/cat\n", 1, 0, func(t *testing.T, r []Rule) {
			if !strings.Contains(r[0].Text, "/bin/cat") {
				t.Errorf("%+v", r[0])
			}
		}},
		{"undefined alias", "NOBODYS ALL=(ALL) ALL\n", 0, 1, nil},
		{"uid spec", "#1000 ALL=(ALL) ALL\n", 0, 1, nil},
		{"no equals", "alice ALL\n", 0, 1, nil},
		{"three tokens before =", "alice bob ALL=(ALL) ALL\n", 0, 1, nil},
		{"bad user", "al$ice;id ALL=(ALL) ALL\n", 0, 1, nil},
		{"control character", "alice ALL=(ALL) A\x1bLL\n", 0, 1, nil},
		{"empty rhs", "alice ALL=\n", 0, 1, nil},
		{"unterminated continuation flood", strings.Repeat("alice ALL=(ALL) "+strings.Repeat("x", 200)+" \\\n", 40), 0, 1, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			rules, skipped := ParseSudoers([]byte(c.in))
			if len(rules) != c.rules || skipped < c.skipped || (c.skipped == 0 && skipped != 0) {
				t.Fatalf("%d rules, %d skipped, want %d, %d", len(rules), skipped, c.rules, c.skipped)
			}
			if c.check != nil {
				c.check(t, rules)
			}
		})
	}
	a, _ := ParseSudoers([]byte("alice ALL=(ALL) ALL\n"))
	b, _ := ParseSudoers([]byte("alice   ALL=(ALL)   ALL\n"))
	if a[0].ID != b[0].ID || len(a[0].ID) != 12 {
		t.Errorf("ids %q %q: not stable across whitespace", a[0].ID, b[0].ID)
	}
}
