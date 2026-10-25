package wire_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
)

// TestAWSOptions_ProdRefusesStoredKeys: a governed AWS connection holds an
// access key, so production does not open its prober (EP-2); dev still does.
func TestAWSOptions_ProdRefusesStoredKeys(t *testing.T) {
	p := governed.Params{Secret: `{"access_key_id":"AKIAEXAMPLEEXAMPLE1","secret_access_key":"baseSecretKeyForTestsOnly0123456789abcd"}`,
		Settings: map[string]string{"regions": "us-east-1", "management_account_id": "111111111111"}}
	now := func() time.Time { return time.Unix(0, 0) }
	if _, err := wire.Options(&http.Client{}, connsynctest.Runtime, "", true).AWS(p, &http.Client{}, now); !errors.Is(err, awsorg.ErrStaticKeysDisabled) {
		t.Errorf("prod: err = %v", err)
	}
	if pr, err := wire.Options(&http.Client{}, connsynctest.Runtime, "", false).AWS(p, &http.Client{}, now); err != nil || pr == nil {
		t.Errorf("dev: %v", err)
	}
}
