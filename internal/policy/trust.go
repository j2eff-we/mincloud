// Package policy evaluates AWS-style JSON policy documents. For now it handles
// just enough for role trust policies — "who may assume this role" — which is
// the first place authorization stops being a hardcoded check and becomes data.
package policy

import (
	"encoding/json"
	"strings"
)

// TrustAllows reports whether trustJSON permits a caller with the given ARN and
// account to perform sts:AssumeRole. An unparseable or empty policy denies.
func TrustAllows(trustJSON, callerARN, callerAccount string) bool {
	var doc document
	if err := json.Unmarshal([]byte(trustJSON), &doc); err != nil {
		return false
	}
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if !st.Action.contains("sts:AssumeRole") && !st.Action.contains("*") {
			continue
		}
		if principalMatches(st.Principal, callerARN, callerAccount) {
			return true
		}
	}
	return false
}

type document struct {
	Statement []statement `json:"Statement"`
}

type statement struct {
	Effect    string    `json:"Effect"`
	Action    stringSet `json:"Action"`
	Principal principal `json:"Principal"`
}

// principalMatches reports whether the statement's principal covers the caller.
// A principal may be "*", the caller's exact ARN, the caller account's root ARN
// (which stands for "any principal in that account"), or a bare account id.
func principalMatches(p principal, callerARN, callerAccount string) bool {
	if p.wildcard {
		return true
	}
	accountRoot := "arn:aws:iam::" + callerAccount + ":root"
	for _, v := range p.AWS {
		switch v {
		case "*", callerARN, accountRoot, callerAccount:
			return true
		}
	}
	return false
}

// principal parses `"Principal": "*"` and `"Principal": {"AWS": ...}` forms.
type principal struct {
	wildcard bool
	AWS      stringSet
}

func (p *principal) UnmarshalJSON(b []byte) error {
	var wildcard string
	if err := json.Unmarshal(b, &wildcard); err == nil {
		p.wildcard = wildcard == "*"
		return nil
	}
	var obj struct {
		AWS stringSet `json:"AWS"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	p.AWS = obj.AWS
	return nil
}

// stringSet accepts either a single string or an array of strings, the way AWS
// policy documents let a field be one value or many.
type stringSet []string

func (s *stringSet) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func (s stringSet) contains(v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
