package sigv4

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Test vectors captured from a real AWS CLI v2 request:
//
//	aws sts get-caller-identity --endpoint-url http://localhost:9900
//
// with AWS_ACCESS_KEY_ID=MINCLOUDTESTKEY0000A and
// AWS_SECRET_ACCESS_KEY=mincloud-test-secret-not-real (fake test credentials).
const (
	testAccessKeyID = "MINCLOUDTESTKEY0000A"
	testSecretKey   = "mincloud-test-secret-not-real"
	testBody        = "Action=GetCallerIdentity&Version=2011-06-15"
)

var capturedRequests = []struct {
	name      string
	amzDate   string
	signature string
}{
	{"first capture", "20260705T112547Z", "285b60204ba0de2785782461e04d6aa0c962ec010b8196276f4a1112306dab85"},
	{"second capture", "20260705T112814Z", "3e4361b978419419ae9c741d1c518fcf2930d8afdcaed1256962637320bb3984"},
}

func capturedAuthHeader(signature string) string {
	return Algorithm + " Credential=" + testAccessKeyID + "/20260705/ap-northeast-2/sts/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, Signature=" + signature
}

func TestParseAuthorization(t *testing.T) {
	auth, err := ParseAuthorization(capturedAuthHeader(capturedRequests[0].signature))
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	if auth.AccessKeyID != testAccessKeyID {
		t.Errorf("AccessKeyID = %q, want %q", auth.AccessKeyID, testAccessKeyID)
	}
	if auth.Scope() != "20260705/ap-northeast-2/sts/aws4_request" {
		t.Errorf("Scope() = %q", auth.Scope())
	}
	if got := strings.Join(auth.SignedHeaders, ";"); got != "content-type;host;x-amz-date" {
		t.Errorf("SignedHeaders = %q", got)
	}
	if auth.Signature != capturedRequests[0].signature {
		t.Errorf("Signature = %q", auth.Signature)
	}
}

func TestParseAuthorizationRejectsMalformed(t *testing.T) {
	for _, header := range []string{
		"",
		"Basic dXNlcjpwYXNz",
		Algorithm + " Credential=only/two, SignedHeaders=host, Signature=abc",
		Algorithm + " SignedHeaders=host, Signature=abc", // no credential
	} {
		if _, err := ParseAuthorization(header); err == nil {
			t.Errorf("ParseAuthorization(%q) succeeded, want error", header)
		}
	}
}

func TestVerifyCapturedRequests(t *testing.T) {
	for _, tc := range capturedRequests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://localhost:9900/", strings.NewReader(testBody))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			r.Header.Set("X-Amz-Date", tc.amzDate)

			auth, err := ParseAuthorization(capturedAuthHeader(tc.signature))
			if err != nil {
				t.Fatalf("ParseAuthorization: %v", err)
			}
			if got := ComputeSignature(r, auth, []byte(testBody), testSecretKey); got != tc.signature {
				t.Errorf("ComputeSignature = %s, want %s", got, tc.signature)
			}
			if err := Verify(r, auth, []byte(testBody), testSecretKey); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	tc := capturedRequests[0]
	r := httptest.NewRequest("POST", "http://localhost:9900/", strings.NewReader(testBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("X-Amz-Date", tc.amzDate)

	auth, err := ParseAuthorization(capturedAuthHeader(tc.signature))
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	if err := Verify(r, auth, []byte(testBody), "wrong-secret"); err != ErrSignatureMismatch {
		t.Errorf("Verify with wrong secret = %v, want ErrSignatureMismatch", err)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	tc := capturedRequests[0]
	r := httptest.NewRequest("POST", "http://localhost:9900/", strings.NewReader(testBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("X-Amz-Date", tc.amzDate)

	auth, err := ParseAuthorization(capturedAuthHeader(tc.signature))
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	tampered := []byte("Action=AssumeRole&Version=2011-06-15")
	if err := Verify(r, auth, tampered, testSecretKey); err != ErrSignatureMismatch {
		t.Errorf("Verify with tampered body = %v, want ErrSignatureMismatch", err)
	}
}
