package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authHeader(scopeService string) string {
	return "AWS4-HMAC-SHA256 Credential=AKIATEST/20260724/ap-northeast-2/" + scopeService +
		"/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef"
}

func TestRoutesByScopeService(t *testing.T) {
	var got string
	mark := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = name })
	}
	h := New(map[string]http.Handler{"sts": mark("sts"), "ec2": mark("ec2")})

	for _, svc := range []string{"sts", "ec2"} {
		r := httptest.NewRequest(http.MethodPost, "http://localhost/", nil)
		r.Header.Set("Authorization", authHeader(svc))
		h.ServeHTTP(httptest.NewRecorder(), r)
		if got != svc {
			t.Errorf("scope %q routed to %q", svc, got)
		}
	}
}

func TestUnknownServiceRejected(t *testing.T) {
	h := New(map[string]http.Handler{})
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", nil)
	r.Header.Set("Authorization", authHeader("s3"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "UnknownService") {
		t.Errorf("body = %s, want UnknownService", w.Body.String())
	}
}

func TestMissingAuthorizationRejected(t *testing.T) {
	h := New(map[string]http.Handler{})
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "MissingAuthenticationToken") {
		t.Errorf("body = %s, want MissingAuthenticationToken", w.Body.String())
	}
}
