package iam

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/rolestore"
	"github.com/j2eff-we/mincloud/internal/service/sts"
	"github.com/j2eff-we/mincloud/internal/sigv4"
)

const (
	testAccessKeyID = "IAMTESTKEY000000000A"
	testSecretKey   = "iam-test-secret-not-real"
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
func signedRequest(t *testing.T, accessKeyID, secretKey, scopeService, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("X-Amz-Date", "20260705T120000Z")

	auth := sigv4.Authorization{
		AccessKeyID:   accessKeyID,
		Date:          "20260705",
		Region:        "ap-northeast-2",
		Service:       scopeService,
		SignedHeaders: []string{"content-type", "host", "x-amz-date"},
	}
	auth.Signature = sigv4.ComputeSignature(r, auth, []byte(body), secretKey)
	r.Header.Set("Authorization", sigv4.Algorithm+" Credential="+accessKeyID+"/"+auth.Scope()+
		", SignedHeaders="+strings.Join(auth.SignedHeaders, ";")+", Signature="+auth.Signature)
	return r
}

func TestCreateAccessKeyForSelf(t *testing.T) {
	store := newTestStore()
	body := "Action=CreateAccessKey&Version=2010-05-08"
	r := signedRequest(t, testAccessKeyID, testSecretKey, "iam", body)
	w := httptest.NewRecorder()

	Handler(store, rolestore.New(), false).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp createAccessKeyResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	ak := resp.Result.AccessKey
	if ak.UserName != "jeff" {
		t.Errorf("UserName = %q, want jeff", ak.UserName)
	}
	if !strings.HasPrefix(ak.AccessKeyId, "AKIA") || len(ak.AccessKeyId) != len("AKIA")+16 {
		t.Errorf("AccessKeyId = %q, want AKIA prefix + 16 chars", ak.AccessKeyId)
	}
	if len(ak.SecretAccessKey) != 40 {
		t.Errorf("SecretAccessKey length = %d, want 40", len(ak.SecretAccessKey))
	}
	if ak.Status != "Active" {
		t.Errorf("Status = %q, want Active", ak.Status)
	}
	if ak.AccessKeyId == testAccessKeyID {
		t.Errorf("issued access key must not equal the caller's own key")
	}

	cred, ok := store.Lookup(ak.AccessKeyId)
	if !ok {
		t.Fatalf("issued access key %q not found in store", ak.AccessKeyId)
	}
	if cred.SecretAccessKey != ak.SecretAccessKey {
		t.Errorf("stored secret does not match response secret")
	}
	if cred.Identity != testIdentity {
		t.Errorf("stored identity = %+v, want caller identity %+v", cred.Identity, testIdentity)
	}
}

func TestCreateAccessKeyThenSTSAuthenticates(t *testing.T) {
	store := newTestStore()
	body := "Action=CreateAccessKey&Version=2010-05-08"
	r := signedRequest(t, testAccessKeyID, testSecretKey, "iam", body)
	w := httptest.NewRecorder()
	Handler(store, rolestore.New(), false).ServeHTTP(w, r)

	var resp createAccessKeyResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	ak := resp.Result.AccessKey

	stsBody := "Action=GetCallerIdentity&Version=2011-06-15"
	stsReq := signedRequest(t, ak.AccessKeyId, ak.SecretAccessKey, "sts", stsBody)
	stsW := httptest.NewRecorder()
	sts.Handler(store, rolestore.New(), false).ServeHTTP(stsW, stsReq)

	if stsW.Code != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body = %s", stsW.Code, stsW.Body.String())
	}
	if !strings.Contains(stsW.Body.String(), testIdentity.ARN) {
		t.Errorf("GetCallerIdentity response %s does not contain caller ARN %s", stsW.Body.String(), testIdentity.ARN)
	}
}

func TestRejectsWrongServiceScope(t *testing.T) {
	store := newTestStore()
	body := "Action=CreateAccessKey&Version=2010-05-08"
	// Signed for sts, sent to the iam handler: must be rejected even though
	// the access key and secret are valid.
	r := signedRequest(t, testAccessKeyID, testSecretKey, "sts", body)
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
