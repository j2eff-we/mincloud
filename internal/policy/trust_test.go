package policy

import "testing"

const accountRootTrust = `{
  "Version": "2012-10-17",
  "Statement": [{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]
}`

func TestTrustAllows(t *testing.T) {
	cases := []struct {
		name       string
		doc        string
		callerARN  string
		callerAcct string
		want       bool
	}{
		{"account root principal covers that account's root", accountRootTrust,
			"arn:aws:iam::111111111111:root", "111111111111", true},
		{"account root principal covers any user in that account", accountRootTrust,
			"arn:aws:iam::111111111111:user/bob", "111111111111", true},
		{"other account is denied", accountRootTrust,
			"arn:aws:iam::222222222222:root", "222222222222", false},
		{"wildcard principal allows anyone",
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
			"arn:aws:iam::999999999999:root", "999999999999", true},
		{"specific user allowed",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"sts:AssumeRole"}]}`,
			"arn:aws:iam::111111111111:user/alice", "111111111111", true},
		{"specific user denies a different user",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"sts:AssumeRole"}]}`,
			"arn:aws:iam::111111111111:user/bob", "111111111111", false},
		{"wrong action denies",
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:GetSessionToken"}]}`,
			"arn:aws:iam::111111111111:root", "111111111111", false},
		{"malformed policy denies", `not json`,
			"arn:aws:iam::111111111111:root", "111111111111", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TrustAllows(c.doc, c.callerARN, c.callerAcct); got != c.want {
				t.Errorf("TrustAllows = %v, want %v", got, c.want)
			}
		})
	}
}
