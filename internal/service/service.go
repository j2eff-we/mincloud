// Package service holds behavior shared by mincloud's AWS-compatible query
// API services (iam, sts): request authentication and XML response framing.
package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/sigv4"
)

// AuthError is a failed authentication attempt, carrying the HTTP status and
// AWS-style error code the caller's service should render.
type AuthError struct {
	Status  int
	Code    string
	Message string
}

func (e *AuthError) Error() string { return e.Message }

// Authenticate verifies r's SigV4 signature against store and checks that the
// request's credential scope names serviceName (e.g. "iam", "sts"). This
// mirrors AWS: a signature scoped to one service is rejected by another,
// even if the access key and secret are otherwise valid. On success it
// returns the request's credential.
func Authenticate(r *http.Request, body []byte, store credstore.Store, serviceName string) (credstore.Credential, *AuthError) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return credstore.Credential{}, &AuthError{
			Status: http.StatusForbidden, Code: "MissingAuthenticationToken",
			Message: "Request is missing Authentication Token",
		}
	}
	auth, err := sigv4.ParseAuthorization(authHeader)
	if err != nil {
		return credstore.Credential{}, &AuthError{
			Status: http.StatusForbidden, Code: "IncompleteSignature", Message: err.Error(),
		}
	}
	cred, ok := store.Lookup(auth.AccessKeyID)
	if !ok {
		return credstore.Credential{}, &AuthError{
			Status: http.StatusForbidden, Code: "InvalidClientTokenId",
			Message: "The security token included in the request is invalid.",
		}
	}
	if auth.Service != serviceName {
		return credstore.Credential{}, &AuthError{
			Status: http.StatusForbidden, Code: "SignatureDoesNotMatch",
			Message: fmt.Sprintf("Credential should be scoped to correct service: '%s'.", serviceName),
		}
	}
	if err := sigv4.Verify(r, auth, body, cred.SecretAccessKey); err != nil {
		return credstore.Credential{}, &AuthError{
			Status: http.StatusForbidden, Code: "SignatureDoesNotMatch",
			Message: "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method.",
		}
	}
	return cred, nil
}

// WriteXML writes v as an AWS query-protocol XML response.
func WriteXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	enc.Encode(v)
}

// RequestID returns a fresh pseudo request ID in AWS's UUID-like format.
func RequestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:])
}
