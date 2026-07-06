package mgmt

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
	mgmtRootKey   = "MGMTROOTKEY000000000"
	mgmtRootSec   = "mgmt-root-secret-not-real"
	memberRootKey = "MEMBERROOTKEY0000000"
	memberRootSec = "member-root-secret-not-real"
)

func newTestStore() credstore.Store {
	s := credstore.New()
	s.Put(mgmtRootKey, credstore.Credential{
		SecretAccessKey: mgmtRootSec,
		Identity:        credstore.Identity{Account: managementAccountID, UserID: managementAccountID, ARN: "arn:aws:iam::" + managementAccountID + ":root"},
	})
	s.Put(memberRootKey, credstore.Credential{
		SecretAccessKey: memberRootSec,
		Identity:        credstore.Identity{Account: "222222222222", UserID: "222222222222", ARN: "arn:aws:iam::222222222222:root"},
	})
	return s
}

// signedRequest self-signs a mincloud-scoped POST; the verifier itself is
// covered by internal/sigv4's real-capture vectors.
func signedRequest(t *testing.T, keyID, secret, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("X-Amz-Date", "20260705T120000Z")

	auth := sigv4.Authorization{
		AccessKeyID:   keyID,
		Date:          "20260705",
		Region:        "us-east-1",
		Service:       serviceName,
		SignedHeaders: []string{"content-type", "host", "x-amz-date"},
	}
	auth.Signature = sigv4.ComputeSignature(r, auth, []byte(body), secret)
	r.Header.Set("Authorization", sigv4.Algorithm+" Credential="+keyID+"/"+auth.Scope()+
		", SignedHeaders="+strings.Join(auth.SignedHeaders, ";")+", Signature="+auth.Signature)
	return r
}

func TestCreateAccountByManagementRoot(t *testing.T) {
	w := httptest.NewRecorder()
	Handler(newTestStore(), false).ServeHTTP(w, signedRequest(t, mgmtRootKey, mgmtRootSec, "Action=CreateAccount&Version=2026-01-01"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp createAccountResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !strings.HasPrefix(resp.Result.Account.RootAccessKeyID, "AKIA") {
		t.Errorf("RootAccessKeyId = %q, want AKIA prefix", resp.Result.Account.RootAccessKeyID)
	}
	if len(resp.Result.Account.AccountID) != 12 {
		t.Errorf("AccountId = %q, want 12 digits", resp.Result.Account.AccountID)
	}
	if resp.Result.Account.RootSecretAccessKey == "" {
		t.Error("RootSecretAccessKey is empty")
	}
}

func TestCreateAccountByMemberRootIsDenied(t *testing.T) {
	// A member account's root is authenticated fine, but not authorized to
	// create accounts — only the management root is.
	w := httptest.NewRecorder()
	Handler(newTestStore(), false).ServeHTTP(w, signedRequest(t, memberRootKey, memberRootSec, "Action=CreateAccount&Version=2026-01-01"))

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
