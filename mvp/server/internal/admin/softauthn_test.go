package admin_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

// softAuthn is a software FIDO2 authenticator for the break-glass tests. It
// answers the WebAuthn creation and request options the server sends with
// the same bytes a hardware key would: a packed attestation signed by an
// attestation certificate that a CA generated in the test issued (or a
// "none" or self attestation), and assertions signed with the credential
// key. Its knobs produce exactly the responses the server must refuse.
type softAuthn struct {
	t      *testing.T
	rpID   string
	origin string

	caCert  *x509.Certificate
	caDER   []byte
	attKey  *ecdsa.PrivateKey
	attDER  []byte
	aaguid  uuid.UUID
	key     *ecdsa.PrivateKey
	credID  []byte
	counter uint32

	// Knobs. format is "packed" (x5c from the test CA), "self" or "none".
	format         string
	backupEligible bool
	backupState    bool
	noUV           bool
	userHandle     []byte
}

// newSoftAuthn makes an authenticator of model aaguid for the relying party
// rpID at origin, with a fresh test CA, attestation certificate and key.
func newSoftAuthn(t *testing.T, rpID, origin string, aaguid uuid.UUID) *softAuthn {
	t.Helper()
	a := &softAuthn{t: t, rpID: rpID, origin: origin, aaguid: aaguid, format: "packed"}
	caKey := a.genKey()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Soft Authn Test CA", Organization: []string{"Tessera tests"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	var err error
	if a.caDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey); err != nil {
		t.Fatal(err)
	}
	if a.caCert, err = x509.ParseCertificate(a.caDER); err != nil {
		t.Fatal(err)
	}
	a.attKey = a.genKey()
	// the packed attestation certificate requirements of WebAuthn §8.2.1
	aaguidExt, err := asn1.Marshal(aaguid[:])
	if err != nil {
		t.Fatal(err)
	}
	attTmpl := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{Country: []string{"US"}, Organization: []string{"Soft Authn Inc"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Soft Authn attestation"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour), BasicConstraintsValid: true, IsCA: false,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: aaguidExt}}}
	if a.attDER, err = x509.CreateCertificate(rand.Reader, attTmpl, a.caCert, &a.attKey.PublicKey, caKey); err != nil {
		t.Fatal(err)
	}
	a.key = a.genKey()
	a.credID = make([]byte, 32)
	if _, err := rand.Read(a.credID); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *softAuthn) genKey() *ecdsa.PrivateKey {
	a.t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		a.t.Fatal(err)
	}
	return k
}

func (a *softAuthn) flags(attested bool) byte {
	f := byte(0x01) // user present
	if !a.noUV {
		f |= 0x04 // user verified
	}
	if a.backupEligible {
		f |= 0x08
	}
	if a.backupState {
		f |= 0x10
	}
	if attested {
		f |= 0x40
	}
	return f
}

// coseKey is the credential public key as a COSE_Key (ES256).
func (a *softAuthn) coseKey() []byte {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		a.t.Fatal(err)
	}
	b, err := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
		-2: a.key.PublicKey.X.FillBytes(make([]byte, 32)), -3: a.key.PublicKey.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

func (a *softAuthn) authData(attested bool, counter uint32) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, a.flags(attested))
	out = binary.BigEndian.AppendUint32(out, counter)
	if attested {
		out = append(out, a.aaguid[:]...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID))) // #nosec G115 -- 32 bytes
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return out
}

func (a *softAuthn) clientData(typ string, challenge protocol.URLEncodedBase64) []byte {
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge.String(), "origin": a.origin, "crossOrigin": false})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

func (a *softAuthn) sign(key *ecdsa.PrivateKey, authData, clientData []byte) []byte {
	cdh := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return sig
}

func b64(b []byte) string { return protocol.URLEncodedBase64(b).String() }

// Register answers a credential creation request: the JSON of the
// PublicKeyCredential the browser would hand to the server.
func (a *softAuthn) Register(creation *protocol.CredentialCreation) []byte {
	a.t.Helper()
	cd := a.clientData("webauthn.create", creation.Response.Challenge)
	ad := a.authData(true, 0)
	stmt := map[string]any{}
	switch a.format {
	case "packed":
		stmt["alg"], stmt["sig"], stmt["x5c"] = -7, a.sign(a.attKey, ad, cd), [][]byte{a.attDER, a.caDER}
	case "self":
		stmt["alg"], stmt["sig"] = -7, a.sign(a.key, ad, cd)
	case "none":
	default:
		a.t.Fatalf("unknown attestation format %q", a.format)
	}
	wireFormat := a.format
	if wireFormat == "self" {
		wireFormat = "packed" // self attestation is the packed format without x5c
	}
	obj, err := cbor.Marshal(map[string]any{"fmt": wireFormat, "attStmt": stmt, "authData": ad})
	if err != nil {
		a.t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"authenticatorAttachment": "cross-platform",
		"response":                map[string]any{"clientDataJSON": b64(cd), "attestationObject": b64(obj), "transports": []string{"usb"}},
		"clientExtensionResults":  map[string]any{}})
	if err != nil {
		a.t.Fatal(err)
	}
	return out
}

// Assert answers a credential request: the JSON of the PublicKeyCredential
// carrying an assertion with the next sign count.
func (a *softAuthn) Assert(assertion *protocol.CredentialAssertion) []byte {
	a.t.Helper()
	a.counter++
	return a.AssertWithCount(assertion, a.counter)
}

// AssertWithCount is Assert with an explicit sign count.
func (a *softAuthn) AssertWithCount(assertion *protocol.CredentialAssertion, count uint32) []byte {
	a.t.Helper()
	cd := a.clientData("webauthn.get", assertion.Response.Challenge)
	ad := a.authData(false, count)
	resp := map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(a.sign(a.key, ad, cd))}
	if a.userHandle != nil {
		resp["userHandle"] = b64(a.userHandle)
	}
	out, err := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"authenticatorAttachment": "cross-platform", "response": resp, "clientExtensionResults": map[string]any{}})
	if err != nil {
		a.t.Fatal(err)
	}
	return out
}
