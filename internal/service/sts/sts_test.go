package sts

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"net/url"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/rolestore"
	"github.com/j2eff-we/mincloud/internal/sigv4"
)

const (
	testAccessKeyID = "STSTESTKEY000000000A"
	testSecretKey   = "sts-test-secret-not-real"
)

var testIdentity = credstore.Identity{
	Account: "123456789012",
	UserID:  "AIDATESTKEY000000000A",
	ARN:     "arn:aws:iam::123456789012:user/jeff",
}

func newTestStore() credstore.Store {
	store := credstore.New()
	store.Put(testAccessKeyID, credstore.Credential{SecretAccessKey: testSecretKey, Identity: testIdentity})
	return store
}

// signedRequest builds a self-signed POST request using sigv4.ComputeSignature
// directly, since the signature verifier itself is already covered by
// internal/sigv4's real-capture test vectors.
func signedRequest(t *testing.T, scopeService, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("X-Amz-Date", "20260705T120000Z")

	auth := sigv4.Authorization{
		AccessKeyID:   testAccessKeyID,
		Date:          "20260705",
		Region:        "ap-northeast-2",
		Service:       scopeService,
		SignedHeaders: []string{"content-type", "host", "x-amz-date"},
	}
	auth.Signature = sigv4.ComputeSignature(r, auth, []byte(body), testSecretKey)
	r.Header.Set("Authorization", sigv4.Algorithm+" Credential="+testAccessKeyID+"/"+auth.Scope()+
		", SignedHeaders="+strings.Join(auth.SignedHeaders, ";")+", Signature="+auth.Signature)
	return r
}

func TestGetCallerIdentity(t *testing.T) {
	store := newTestStore()
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	r := signedRequest(t, "sts", body)
	w := httptest.NewRecorder()

	Handler(store, rolestore.New(), false).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp getCallerIdentityResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Result.Account != testIdentity.Account {
		t.Errorf("Account = %q, want %q", resp.Result.Account, testIdentity.Account)
	}
	if resp.Result.UserID != testIdentity.UserID {
		t.Errorf("UserId = %q, want %q", resp.Result.UserID, testIdentity.UserID)
	}
	if resp.Result.Arn != testIdentity.ARN {
		t.Errorf("Arn = %q, want %q", resp.Result.Arn, testIdentity.ARN)
	}
}

func TestRejectsWrongServiceScope(t *testing.T) {
	store := newTestStore()
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	// Signed for iam, sent to the sts handler: must be rejected even though
	// the access key and secret are valid.
	r := signedRequest(t, "iam", body)
	w := httptest.NewRecorder()

	Handler(store, rolestore.New(), false).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp errorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Code != "SignatureDoesNotMatch" {
		t.Errorf("Code = %q, want SignatureDoesNotMatch", resp.Code)
	}
}

func assumeRoleBody(roleArn string) string {
	return "Action=AssumeRole&RoleArn=" + url.QueryEscape(roleArn) + "&RoleSessionName=sess1&Version=2011-06-15"
}

func TestAssumeRoleAllowedByTrust(t *testing.T) {
	store := newTestStore()
	roles := rolestore.New()
	roleArn := "arn:aws:iam::123456789012:role/OrgAccess"
	roles.Put(rolestore.Role{
		RoleName: "OrgAccess", RoleID: "AROATESTROLE00000000", Account: "123456789012", ARN: roleArn,
		AssumeRolePolicy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`,
	})

	w := httptest.NewRecorder()
	Handler(store, roles, false).ServeHTTP(w, signedRequest(t, "sts", assumeRoleBody(roleArn)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp assumeRoleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !strings.HasPrefix(resp.Result.Credentials.AccessKeyId, "ASIA") {
		t.Errorf("temp AccessKeyId = %q, want ASIA prefix", resp.Result.Credentials.AccessKeyId)
	}
	if resp.Result.Credentials.SessionToken == "" {
		t.Error("SessionToken is empty")
	}
	if want := "arn:aws:sts::123456789012:assumed-role/OrgAccess/sess1"; resp.Result.AssumedRoleUser.Arn != want {
		t.Errorf("AssumedRole Arn = %q, want %q", resp.Result.AssumedRoleUser.Arn, want)
	}
}

func TestAssumeRoleDeniedWhenNotTrusted(t *testing.T) {
	store := newTestStore()
	roles := rolestore.New()
	roleArn := "arn:aws:iam::123456789012:role/Closed"
	roles.Put(rolestore.Role{
		RoleName: "Closed", RoleID: "AROATESTROLE00000001", Account: "123456789012", ARN: roleArn,
		// Trusts a different account, so the test caller must be refused.
		AssumeRolePolicy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`,
	})

	w := httptest.NewRecorder()
	Handler(store, roles, false).ServeHTTP(w, signedRequest(t, "sts", assumeRoleBody(roleArn)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
	var resp errorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Code != "AccessDenied" {
		t.Errorf("Code = %q, want AccessDenied", resp.Code)
	}
}
