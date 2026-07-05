// Package credstore maps access key IDs to secrets and their identities.
package credstore

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

// Store is an in-memory credential store.
type Store struct {
	creds map[string]Credential
}

func New() *Store {
	return &Store{creds: map[string]Credential{}}
}

func (s *Store) Put(accessKeyID string, c Credential) {
	s.creds[accessKeyID] = c
}

func (s *Store) Lookup(accessKeyID string) (Credential, bool) {
	c, ok := s.creds[accessKeyID]
	return c, ok
}
