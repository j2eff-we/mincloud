package ec2

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// EC2 instance state codes, as reported by the real API.
const (
	stateCodePending    = 0
	stateCodeRunning    = 16
	stateCodeTerminated = 48

	stateNamePending    = "pending"
	stateNameRunning    = "running"
	stateNameTerminated = "terminated"
)

// instance is a single simulated EC2 instance. There is no real machine behind
// it: mincloud tracks only the control-plane state and the launch metadata the
// API contract requires.
type instance struct {
	id            string
	imageID       string
	instanceType  string
	reservationID string
	ownerID       string
	stateCode     int
	stateName     string
	launchTime    time.Time
}

// instanceStore holds launched instances in memory. It is safe for concurrent
// use since a single store is shared across all requests to an EC2 handler.
type instanceStore struct {
	mu        sync.Mutex
	instances map[string]*instance
	order     []string // instance IDs in launch order, for stable Describe output
}

func newInstanceStore() *instanceStore {
	return &instanceStore{instances: map[string]*instance{}}
}

// run launches count instances of the given image and type under a single new
// reservation, all in the pending state, and returns them in launch order.
func (s *instanceStore) run(imageID, instanceType, ownerID string, count int) []*instance {
	s.mu.Lock()
	defer s.mu.Unlock()

	reservationID := newID("r-")
	now := time.Now().UTC()
	launched := make([]*instance, 0, count)
	for i := 0; i < count; i++ {
		inst := &instance{
			id:            newID("i-"),
			imageID:       imageID,
			instanceType:  instanceType,
			reservationID: reservationID,
			ownerID:       ownerID,
			stateCode:     stateCodePending,
			stateName:     stateNamePending,
			launchTime:    now,
		}
		s.instances[inst.id] = inst
		s.order = append(s.order, inst.id)
		launched = append(launched, inst)
	}
	return launched
}

// describe returns instances in launch order, optionally filtered to ids. As a
// deterministic stand-in for asynchronous boot, any instance still pending is
// transitioned to running the first time it is observed — so a Describe that
// follows a RunInstances sees the instance running, just like real AWS.
func (s *instanceStore) describe(ids []string) []*instance {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}

	var out []*instance
	for _, id := range s.order {
		inst := s.instances[id]
		if len(ids) > 0 && !want[id] {
			continue
		}
		if inst.stateName == stateNamePending {
			inst.stateCode = stateCodeRunning
			inst.stateName = stateNameRunning
		}
		out = append(out, inst)
	}
	return out
}

// terminated pairs an instance's id with its state transition, for the
// TerminateInstances response.
type terminated struct {
	id           string
	previousCode int
	previousName string
}

// terminate moves the named instances to the terminated state and reports each
// one's previous state. Unknown ids are skipped.
func (s *instanceStore) terminate(ids []string) []terminated {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []terminated
	for _, id := range ids {
		inst, ok := s.instances[id]
		if !ok {
			continue
		}
		out = append(out, terminated{id: inst.id, previousCode: inst.stateCode, previousName: inst.stateName})
		inst.stateCode = stateCodeTerminated
		inst.stateName = stateNameTerminated
	}
	return out
}

// newID returns an AWS-style resource ID: a prefix ("i-", "r-") followed by 16
// lowercase hex characters.
func newID(prefix string) string {
	var b [8]byte
	rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}
