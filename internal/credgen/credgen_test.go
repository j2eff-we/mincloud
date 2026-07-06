package credgen

import (
	"strings"
	"testing"
)

func TestAccessKeyIDFormat(t *testing.T) {
	id := AccessKeyID("123456789012")
	if !strings.HasPrefix(id, "AKIA") || len(id) != len("AKIA")+16 {
		t.Errorf("AccessKeyID = %q, want AKIA + 16 chars", id)
	}
}

func TestAccessKeyIDEncodesAccount(t *testing.T) {
	for _, acct := range []string{"123456789012", "000000000001", "999999999999", "511043339935"} {
		id := AccessKeyID(acct)
		got, ok := AccountFromAccessKeyID(id)
		if !ok {
			t.Fatalf("AccountFromAccessKeyID(%q) failed to decode", id)
		}
		if got != acct {
			t.Errorf("round-trip for %s: key %q decoded to %s", acct, id, got)
		}
	}
}

func TestAccountFromAccessKeyIDRejectsNonEncoded(t *testing.T) {
	// The seed key is not account-encoded (contains non-base32 chars).
	if _, ok := AccountFromAccessKeyID("MINCLOUDTESTKEY0000A"); ok {
		t.Error("decoded a non-encoded key id")
	}
}

func TestUserIDFormat(t *testing.T) {
	id := UserID("AIDA")
	if !strings.HasPrefix(id, "AIDA") || len(id) != len("AIDA")+16 {
		t.Errorf("UserID = %q, want AIDA + 16 chars", id)
	}
}

func TestSecretAccessKeyLength(t *testing.T) {
	s, err := SecretAccessKey()
	if err != nil {
		t.Fatalf("SecretAccessKey: %v", err)
	}
	if len(s) != 40 {
		t.Errorf("SecretAccessKey length = %d, want 40", len(s))
	}
}

func TestAccountIDIs12DigitsNonZeroLead(t *testing.T) {
	for i := 0; i < 50; i++ {
		id := AccountID()
		if len(id) != 12 {
			t.Fatalf("AccountID = %q, want 12 digits", id)
		}
		if id[0] == '0' {
			t.Errorf("AccountID = %q, leads with 0", id)
		}
		for _, c := range id {
			if c < '0' || c > '9' {
				t.Fatalf("AccountID = %q, non-digit", id)
			}
		}
	}
}

// Uniqueness is not guaranteed by contract, but a collision across a handful of
// calls would signal the generator is not actually random.
func TestAccessKeyIDsDiffer(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := AccessKeyID("123456789012")
		if seen[id] {
			t.Fatalf("duplicate AccessKeyID %q within 100 calls", id)
		}
		seen[id] = true
	}
}
