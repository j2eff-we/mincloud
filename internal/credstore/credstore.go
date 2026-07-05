// Package credstore maps access key IDs to secrets and their identities.
package credstore

import "sync"

// Identity is who a credential authenticates as.
type Identity struct {
	Account string
	UserID  string
	ARN     string
}

// Credential pairs a secret access key with the identity it belongs to.
type Credential struct {
	SecretAccessKey string
	Identity        Identity
}

// Store maps access key IDs to credentials. Implementations must be safe for
// concurrent use by multiple services.
type Store interface {
	Put(accessKeyID string, c Credential)
	Lookup(accessKeyID string) (Credential, bool)
}

// memStore is an in-memory Store, safe for concurrent use since it may be
// shared across services (e.g. IAM and STS) handling requests on separate
// goroutines.
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
