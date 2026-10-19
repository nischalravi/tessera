package awsorg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func testSealer(t *testing.T) *seal.Sealer {
	t.Helper()
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testTenant(t *testing.T, n byte) tenancy.ID {
	t.Helper()
	id, err := tenancy.Parse(fmt.Sprintf("00000000-0000-4000-8000-0000000000%02x", n))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

var goodCreds = Credentials{AccessKeyID: "AKIAEXAMPLEEXAMPLE1", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

// TestCredentialsAreSealed: credentials are sealed with internal/seal, bound
// to their tenant, table, column and connector (AAD), and never printed.
func TestCredentialsAreSealed(t *testing.T) {
	s := testSealer(t)
	a, b := testTenant(t, 1), testTenant(t, 2)
	creds := goodCreds
	creds.SessionToken = "FwoGZXIvYXdzEXAMPLE"
	blob, err := SealCredentials(s, a, "conn-1", creds)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{creds.SecretAccessKey, creds.AccessKeyID, creds.SessionToken} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Errorf("the sealed blob holds %q in the clear", secret)
		}
	}
	got, err := OpenCredentials(s, a, "conn-1", blob)
	if err != nil || got != creds {
		t.Fatalf("Open = %v, %v", got.String(), err)
	}

	// bound to tenant and connector: copied elsewhere it does not open
	if _, err := OpenCredentials(s, b, "conn-1", blob); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("another tenant opened it: %v", err)
	}
	if _, err := OpenCredentials(s, a, "conn-2", blob); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("another connector opened it: %v", err)
	}
	// another KEK, a flipped bit, a truncated blob, nothing
	if _, err := OpenCredentials(testSealer(t), a, "conn-1", blob); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("another KEK opened it: %v", err)
	}
	flipped := bytes.Clone(blob)
	flipped[len(flipped)-1] ^= 1
	if _, err := OpenCredentials(s, a, "conn-1", flipped); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("a tampered blob opened: %v", err)
	}
	if _, err := OpenCredentials(s, a, "conn-1", blob[:10]); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("a truncated blob opened: %v", err)
	}
	if _, err := OpenCredentials(nil, a, "conn-1", blob); err == nil {
		t.Error("opened without a sealer")
	}
	if _, err := SealCredentials(nil, a, "conn-1", creds); err == nil {
		t.Error("sealed without a sealer")
	}

	// never printed or marshalled by accident
	for _, out := range []string{creds.String(), creds.GoString(), fmt.Sprintf("%v|%+v|%#v|%s", creds, creds, creds, creds)} {
		if strings.Contains(out, creds.SecretAccessKey) || strings.Contains(out, creds.SessionToken) || !strings.Contains(out, "REDACTED") {
			t.Errorf("credentials printed as %q", out)
		}
	}
}

func TestCredentialsValidate(t *testing.T) {
	ok := func(c Credentials) bool { return c.Validate() == nil }
	if !ok(goodCreds) {
		t.Fatal("good credentials refused")
	}
	for name, c := range map[string]Credentials{
		"no key id":        {SecretAccessKey: goodCreds.SecretAccessKey},
		"lower-case id":    {AccessKeyID: "akiaexampleexample1", SecretAccessKey: goodCreds.SecretAccessKey},
		"id with a space":  {AccessKeyID: "AKIA EXAMPLE EXAMPL", SecretAccessKey: goodCreds.SecretAccessKey},
		"no secret":        {AccessKeyID: goodCreds.AccessKeyID},
		"short secret":     {AccessKeyID: goodCreds.AccessKeyID, SecretAccessKey: "short"},
		"secret with a nl": {AccessKeyID: goodCreds.AccessKeyID, SecretAccessKey: goodCreds.SecretAccessKey + "\n"},
		"huge secret":      {AccessKeyID: goodCreds.AccessKeyID, SecretAccessKey: strings.Repeat("a", 300)},
		"token with space": {AccessKeyID: goodCreds.AccessKeyID, SecretAccessKey: goodCreds.SecretAccessKey, SessionToken: "a b"},
		"huge token":       {AccessKeyID: goodCreds.AccessKeyID, SecretAccessKey: goodCreds.SecretAccessKey, SessionToken: strings.Repeat("a", 5000)},
	} {
		if ok(c) {
			t.Errorf("%s accepted", name)
		}
		if _, err := SealCredentials(testSealer(t), testTenant(t, 1), "c", c); err == nil {
			t.Errorf("%s sealed", name)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	good := func() Config {
		return Config{Regions: []string{"us-east-1", "eu-west-1"}, AccountIDs: []string{"222222222222", "111111111111", "222222222222"}}
	}
	c := good()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.RoleName != DefaultRoleName || len(c.AccountIDs) != 2 || c.AccountIDs[0] != "111111111111" {
		t.Errorf("normalized config = %+v", c)
	}
	org := Config{Regions: []string{"us-east-1"}, ManagementAccountID: "111111111111"}
	if err := org.Validate(); err != nil {
		t.Errorf("an organization config with no account list: %v", err)
	}

	manyRegions := func(n int) []string {
		var o []string
		for i := range n {
			o = append(o, "us-"+string(rune('a'+i/26))+string(rune('a'+i%26))+"-1") // distinct, well-formed names
		}
		return o
	}
	manyAccounts := func(n int) []string {
		var o []string
		for i := range n {
			o = append(o, fmt.Sprintf("%012d", i))
		}
		return o
	}
	if c := (Config{Regions: manyRegions(MaxRegions), AccountIDs: manyAccounts(MaxAccounts)}); c.Validate() != nil {
		t.Errorf("a config at the limits is refused: %v", c.Validate())
	}
	for name, mut := range map[string]func(*Config){
		"no regions":          func(c *Config) { c.Regions = nil },
		"bad region":          func(c *Config) { c.Regions = []string{"us-east-1.evil.example"} },
		"region repeated":     func(c *Config) { c.Regions = []string{"us-east-1", "us-east-1"} },
		"upper-case region":   func(c *Config) { c.Regions = []string{"US-EAST-1"} },
		"too many regions":    func(c *Config) { c.Regions = manyRegions(MaxRegions + 1) },
		"bad account":         func(c *Config) { c.AccountIDs = []string{"12345"} },
		"account injection":   func(c *Config) { c.AccountIDs = []string{"111111111111/../x"} },
		"too many accounts":   func(c *Config) { c.AccountIDs = manyAccounts(MaxAccounts + 1) },
		"bad management":      func(c *Config) { c.ManagementAccountID = "abc" },
		"no accounts, no org": func(c *Config) { c.AccountIDs = nil },
		"bad role name":       func(c *Config) { c.RoleName = "role/with/slash" },
		"long role name":      func(c *Config) { c.RoleName = strings.Repeat("r", 65) },
		"bad identity center": func(c *Config) { c.IdentityCenterRegion = "nowhere" },
	} {
		c := good()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// ParseConfig: strict about what is stored
	if _, err := ParseConfig([]byte(`{"regions":["us-east-1"],"account_ids":["111111111111"]}`)); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{``, `[]`, `{"regions":[]}`, `{"regions":["us-east-1"]}`, `not json`} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("ParseConfig(%q) accepted", bad)
		}
	}
	b, _ := json.Marshal(good())
	if strings.Contains(string(b), "secret") {
		t.Errorf("the config has a secret field: %s", b)
	}
}
