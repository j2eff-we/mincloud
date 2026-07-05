package sts

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/j2eff-we/mincloud/internal/credstore"
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

	Handler(store, false).ServeHTTP(w, r)

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

	Handler(store, false).ServeHTTP(w, r)

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
