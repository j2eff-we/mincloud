// Package credgen generates AWS-style identifiers and secrets — access key IDs,
// secret access keys, user IDs, and account IDs. Centralizing the format rules
// keeps IAM key issuance and admin account creation minting identical shapes.
//
// Access key IDs embed the account ID the way real AWS keys do: the 12-digit
// account is encoded into the key's base32 body, so it can be recovered from
// the key alone, with no API call. See AccountFromAccessKeyID.
package credgen

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
)

const (
	alphabet        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	idBodyLength    = 16
	secretRawBytes  = 30 // base64-encodes to exactly 40 characters
	accountIDDigits = 12

	// accountMask selects the 40 account bits (7..46) inside the first 6 bytes
	// of a decoded access key body; the low 7 bits are per-key entropy. This is
	// the same layout the public "account id from access key" tools assume.
	accountMask  = 0x7fffffffff80
	accountShift = 7
)

// AccessKeyID returns a new access key ID: "AKIA" + a 16-char base32 body that
// encodes accountID, so AccountFromAccessKeyID can recover it later.
func AccessKeyID(accountID string) string {
	return "AKIA" + encodeAccount(accountID)
}

// TempAccessKeyID returns a temporary access key ID ("ASIA…"), the prefix AWS
// uses for STS-issued credentials. It encodes the account just like AKIA keys.
func TempAccessKeyID(accountID string) string {
	return "ASIA" + encodeAccount(accountID)
}

// SessionToken returns an opaque token accompanying a temporary credential.
func SessionToken() (string, error) {
	raw := make([]byte, 48)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// AccountFromAccessKeyID recovers the 12-digit account ID encoded in an access
// key ID. It returns false if the body is not the expected base32 shape (e.g.
// the well-known seed key, which is not account-encoded).
func AccountFromAccessKeyID(id string) (string, bool) {
	if len(id) < 4 {
		return "", false
	}
	data, err := base32.StdEncoding.DecodeString(id[4:])
	if err != nil || len(data) < 6 {
		return "", false
	}
	var z uint64
	for i := 0; i < 6; i++ {
		z = z<<8 | uint64(data[i])
	}
	account := (z & accountMask) >> accountShift
	return fmt.Sprintf("%012d", account), true
}

// encodeAccount packs accountID into a 16-char base32 body: the first 6 bytes
// carry the account (shifted, with random low bits), the last 4 bytes are
// random so two keys for the same account still differ.
func encodeAccount(accountID string) string {
	acct, _ := strconv.ParseUint(accountID, 10, 64)
	z := acct<<accountShift | uint64(mustIntn(1<<accountShift))

	var body [10]byte
	for i := 5; i >= 0; i-- {
		body[i] = byte(z & 0xff)
		z >>= 8
	}
	if _, err := rand.Read(body[6:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base32.StdEncoding.EncodeToString(body[:])
}

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
