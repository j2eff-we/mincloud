// Package credgen generates AWS-style identifiers and secrets — access key IDs,
// secret access keys, user IDs, and account IDs. Centralizing the format rules
// keeps IAM key issuance and admin account creation minting identical shapes.
package credgen

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

const (
	alphabet        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	idBodyLength    = 16
	secretRawBytes  = 30 // base64-encodes to exactly 40 characters
	accountIDDigits = 12
)

// AccessKeyID returns a new access key ID: "AKIA" + 16 uppercase alphanumerics.
func AccessKeyID() string { return "AKIA" + randomAlnum(idBodyLength) }

// UserID returns a new user ID with the given prefix (e.g. "AIDA" + 16 chars).
func UserID(prefix string) string { return prefix + randomAlnum(idBodyLength) }

// SecretAccessKey returns a new 40-character base64 secret.
func SecretAccessKey() (string, error) {
	raw := make([]byte, secretRawBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// AccountID returns a new 12-digit account ID with a non-zero first digit.
func AccountID() string {
	digits := make([]byte, accountIDDigits)
	digits[0] = byte('1' + mustIntn(9)) // 1..9
	for i := 1; i < accountIDDigits; i++ {
		digits[i] = byte('0' + mustIntn(10))
	}
	return string(digits)
}

func randomAlnum(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[mustIntn(len(alphabet))]
	}
	return string(b)
}

func mustIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return int(v.Int64())
}
