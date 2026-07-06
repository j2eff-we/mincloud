package credgen

import (
	"strings"
	"testing"
)

func TestAccessKeyIDFormat(t *testing.T) {
	id := AccessKeyID()
	if !strings.HasPrefix(id, "AKIA") || len(id) != len("AKIA")+16 {
		t.Errorf("AccessKeyID = %q, want AKIA + 16 chars", id)
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
		id := AccessKeyID()
		if seen[id] {
			t.Fatalf("duplicate AccessKeyID %q within 100 calls", id)
		}
		seen[id] = true
	}
}
