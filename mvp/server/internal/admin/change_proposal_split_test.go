package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSplitProposalSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, kind, body string
		secrets          map[string]string
		in, notIn        []string
		wantErr          bool
	}{
		{"webhook URL and secret", KindAlertChannel, `{"name":"a","kind":"webhook","target":"https://h.example.com/x?t=SECRET","signing_secret":"S1"}`,
			map[string]string{"target": "https://h.example.com/x?t=SECRET", "signing_secret": "S1"},
			[]string{`"target":"set"`, `"signing_secret":"set"`, `"target_origin":"https://h.example.com:443"`}, []string{"SECRET", "S1"}, false},
		{"email target is not a secret", KindAlertChannel, `{"name":"a","kind":"email","target":"a@example.com"}`,
			map[string]string{}, []string{`"target":"a@example.com"`}, []string{"target_origin"}, false},
		{"a spoofed origin is dropped", KindSiemSink, `{"name":"a","kind":"syslog","target":"collector:6514","target_origin":"https://trusted.example.com"}`,
			map[string]string{}, []string{`"target":"collector:6514"`}, []string{"trusted.example.com"}, false},
		{"connection secret", KindConnection, `{"name":"c","credential":{"secret":"PW","reference":""}}`,
			map[string]string{"credential.secret": "PW"}, []string{`"secret":"set"`}, []string{"PW"}, false},
		{"a reference is not a secret", KindConnection, `{"name":"c","credential":{"reference":"vault:kv/okta"}}`,
			map[string]string{}, []string{"vault:kv/okta"}, nil, false},
		{"null leaves the secret out", KindSiemSink, `{"name":"a","token":null}`, map[string]string{}, nil, nil, false},
		{"an empty secret is refused", KindSiemSink, `{"name":"a","token":""}`, nil, nil, nil, true},
		{"a number is refused", KindSiemSink, `{"name":"a","token":12345}`, nil, nil, nil, true},
		{"not an object", KindSiemSink, `["x"]`, nil, nil, nil, true},
		{"a kind with no secrets is untouched", KindRole, `{"name":"r","token":"visible"}`, nil, []string{"visible"}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clean, secrets, err := splitProposalSecrets(tc.kind, json.RawMessage(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %t", err, tc.wantErr)
			}
			if err != nil {
				if strings.Contains(err.Error(), "12345") {
					t.Errorf("the error echoes the value: %v", err)
				}
				return
			}
			if tc.secrets != nil && len(secrets) != len(tc.secrets) {
				t.Errorf("secrets = %v, want %v", secrets, tc.secrets)
			}
			for k, v := range tc.secrets {
				if secrets[k] != v {
					t.Errorf("secret %s = %q, want %q", k, secrets[k], v)
				}
			}
			for _, s := range tc.in {
				if !strings.Contains(string(clean), s) {
					t.Errorf("%s lacks %s", clean, s)
				}
			}
			for _, s := range tc.notIn {
				if strings.Contains(string(clean), s) {
					t.Errorf("%s still has %s", clean, s)
				}
			}
		})
	}
}
