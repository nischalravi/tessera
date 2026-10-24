package ldapwrite

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"unicode/utf16"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// PasswordPolicy is the shape of a generated initial password (Saviynt's PASSWORD_MIN_LENGTH,
// PASSWORD_MAX_LENGTH, PASSWORD_NOOF_CAPSALPHA, PASSWORD_NOOF_DIGITS and PASSWORD_NOOF_SPLCHARS).
// The counts are minimums; the rest of the password is lower case letters.
type PasswordPolicy struct {
	MinLength  int `json:"min_length,omitempty"`
	MaxLength  int `json:"max_length,omitempty"`
	MinUpper   int `json:"min_upper,omitempty"`
	MinDigits  int `json:"min_digits,omitempty"`
	MinSpecial int `json:"min_special,omitempty"`
}

const (
	lowerSet   = "abcdefghijklmnopqrstuvwxyz"
	upperSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitSet   = "0123456789"
	specialSet = "!#$%&*+-=?@^_"

	defaultMinLen = 16
	defaultMaxLen = 24
	hardMaxLen    = 128
	hardMinLen    = 8
)

// normalized fills the defaults (16 to 24 characters).
func (p PasswordPolicy) normalized() PasswordPolicy {
	if p.MinLength == 0 {
		p.MinLength = defaultMinLen
	}
	if p.MaxLength == 0 {
		p.MaxLength = max(defaultMaxLen, p.MinLength)
	}
	return p
}

// Validate reports why the policy cannot produce a password ("" when it can). The text is fixed.
func (p PasswordPolicy) Validate() string {
	p = p.normalized()
	switch {
	case p.MinLength < hardMinLen || p.MaxLength > hardMaxLen || p.MaxLength < p.MinLength:
		return "the password length must be from 8 to 128, minimum not above maximum"
	case p.MinUpper < 0 || p.MinDigits < 0 || p.MinSpecial < 0 || p.MinUpper > 64 || p.MinDigits > 64 || p.MinSpecial > 64:
		return "the upper case, digit and special character counts are from 0 to 64"
	case p.MinUpper+p.MinDigits+p.MinSpecial > p.MinLength:
		return "the character counts add up to more than the minimum length"
	}
	return ""
}

func pick(r io.Reader, set string) (byte, error) {
	n, err := rand.Int(r, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

// GeneratePassword makes a password that meets the policy from r (crypto/rand.Reader in
// production). The result is a connsync.Secret: it never prints.
func GeneratePassword(p PasswordPolicy, r io.Reader) (connsync.Secret, error) {
	if msg := p.Validate(); msg != "" {
		return connsync.Secret{}, errors.New(msg)
	}
	p = p.normalized()
	length := p.MinLength
	if p.MaxLength > p.MinLength {
		n, err := rand.Int(r, big.NewInt(int64(p.MaxLength-p.MinLength+1)))
		if err != nil {
			return connsync.Secret{}, err
		}
		length += int(n.Int64())
	}
	buf := make([]byte, 0, length)
	for _, s := range []struct {
		set string
		n   int
	}{{upperSet, p.MinUpper}, {digitSet, p.MinDigits}, {specialSet, p.MinSpecial}, {lowerSet, length - p.MinUpper - p.MinDigits - p.MinSpecial}} {
		for range s.n {
			c, err := pick(r, s.set)
			if err != nil {
				return connsync.Secret{}, err
			}
			buf = append(buf, c)
		}
	}
	for i := len(buf) - 1; i > 0; i-- { // Fisher-Yates
		n, err := rand.Int(r, big.NewInt(int64(i+1)))
		if err != nil {
			return connsync.Secret{}, err
		}
		j := int(n.Int64())
		buf[i], buf[j] = buf[j], buf[i]
	}
	return connsync.NewSecret(string(buf)), nil
}

// UnicodePwd is the value Active Directory takes for unicodePwd: the password in double quotes,
// UTF-16 little endian. It is only accepted over an encrypted connection.
func UnicodePwd(pw string) []byte {
	u := utf16.Encode([]rune(`"` + pw + `"`))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2*i:], c)
	}
	return out
}
