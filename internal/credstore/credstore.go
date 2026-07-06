// Package credstore maps access key IDs to secrets and their identities.
package credstore

import (
	"sync"
	"time"
)

// Identity is who a credential authenticates as.
type Identity struct {
	Account string
	UserID  string
	ARN     string
}

// Credential pairs a secret access key with the identity it belongs to.
//
// SessionToken and Expires are set only for temporary credentials minted by
// STS AssumeRole: such a request must present a matching security token and be
// used before Expires. For long-lived credentials both are zero.
type Credential struct {
	SecretAccessKey string
	Identity        Identity
	SessionToken    string
	Expires         time.Time
}

// Store maps access key IDs to credentials. Implementations must be safe for
// concurrent use by multiple services. The interface is deliberately small so
// its backing can move — from an in-memory map (New) to DynamoDB (OpenDynamo)
// — without any handler noticing.
type Store interface {
	Put(accessKeyID string, c Credential)
	Lookup(accessKeyID string) (Credential, bool)
}

// memStore is an in-memory Store, safe for concurrent use since it may be
// shared across services (e.g. IAM and STS) handling requests on separate
// goroutines. State is lost when the process exits; use OpenDynamo to persist.
type memStore struct {
	mu    sync.RWMutex
	creds map[string]Credential
}

// New returns an empty in-memory Store.
func New() Store {
	return &memStore{creds: map[string]Credential{}}
}

func (s *memStore) Put(accessKeyID string, c Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[accessKeyID] = c
}

func (s *memStore) Lookup(accessKeyID string) (Credential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.creds[accessKeyID]
	return c, ok
}
