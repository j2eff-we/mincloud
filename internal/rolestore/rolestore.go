// Package rolestore holds IAM roles: named, assumable identities whose trust
// policy decides who may assume them. Unlike credentials, roles have no secret
// of their own — you become one, briefly, via STS AssumeRole.
package rolestore

import (
	"sync"
	"time"
)

// Role is an assumable identity in an account.
type Role struct {
	RoleName         string
	RoleID           string // "AROA…"
	Account          string
	ARN              string // arn:aws:iam::<account>:role/<name>
	AssumeRolePolicy string // trust policy document (raw JSON): who may assume
	CreateDate       time.Time
}

// Store maps role ARNs to roles. Roles live in memory: they are cheap to
// recreate and, unlike issued credentials, not yet persisted.
type Store interface {
	Put(r Role)
	Get(arn string) (Role, bool)
}

type memStore struct {
	mu    sync.RWMutex
	roles map[string]Role
}

// New returns an empty in-memory role Store.
func New() Store {
	return &memStore{roles: map[string]Role{}}
}

func (s *memStore) Put(r Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.ARN] = r
}

func (s *memStore) Get(arn string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[arn]
	return r, ok
}
