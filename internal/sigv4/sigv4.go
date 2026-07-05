// Package sigv4 verifies AWS Signature Version 4 signed requests.
//
// Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"
)

const Algorithm = "AWS4-HMAC-SHA256"

var ErrSignatureMismatch = errors.New("sigv4: signature mismatch")

// Authorization is the parsed form of an AWS4-HMAC-SHA256 Authorization header:
//
//	AWS4-HMAC-SHA256 Credential=<akid>/<date>/<region>/<service>/aws4_request,
//	SignedHeaders=<h1;h2;...>, Signature=<hex>
type Authorization struct {
	AccessKeyID   string
	Date          string // YYYYMMDD portion of the credential scope
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
}

// Scope returns the credential scope: <date>/<region>/<service>/aws4_request.
func (a Authorization) Scope() string {
	return strings.Join([]string{a.Date, a.Region, a.Service, "aws4_request"}, "/")
}

// ParseAuthorization parses an Authorization header value.
func ParseAuthorization(header string) (Authorization, error) {
	var auth Authorization
	rest, ok := strings.CutPrefix(header, Algorithm)
	if !ok {
		return auth, fmt.Errorf("sigv4: unsupported algorithm in %q", header)
	}
	for _, part := range strings.Split(rest, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			return auth, fmt.Errorf("sigv4: malformed component %q", part)
		}
		switch key {
		case "Credential":
			fields := strings.Split(value, "/")
			if len(fields) != 5 || fields[4] != "aws4_request" {
				return auth, fmt.Errorf("sigv4: malformed credential scope %q", value)
			}
			auth.AccessKeyID, auth.Date, auth.Region, auth.Service = fields[0], fields[1], fields[2], fields[3]
		case "SignedHeaders":
			auth.SignedHeaders = strings.Split(value, ";")
		case "Signature":
			auth.Signature = value
		default:
			return auth, fmt.Errorf("sigv4: unknown component %q", key)
		}
	}
	if auth.AccessKeyID == "" || len(auth.SignedHeaders) == 0 || auth.Signature == "" {
		return auth, errors.New("sigv4: incomplete authorization header")
	}
	return auth, nil
}

// Verify recomputes the signature of r with the given secret key and compares
// it against the signature claimed in auth. body must be the full request body.
func Verify(r *http.Request, auth Authorization, body []byte, secretAccessKey string) error {
	want, err := hex.DecodeString(auth.Signature)
	if err != nil {
		return fmt.Errorf("sigv4: signature is not hex: %w", err)
	}
	got, err := hex.DecodeString(ComputeSignature(r, auth, body, secretAccessKey))
	if err != nil {
		return err
	}
	if !hmac.Equal(want, got) {
		return ErrSignatureMismatch
	}
	return nil
}

// ComputeSignature derives the SigV4 signature for r as the client must have
// computed it: canonical request -> string to sign -> signing key chain.
func ComputeSignature(r *http.Request, auth Authorization, body []byte, secretAccessKey string) string {
	payloadHash := sha256Hex(body)
	canonical := canonicalRequest(r, auth.SignedHeaders, payloadHash)
	toSign := strings.Join([]string{
		Algorithm,
		r.Header.Get("X-Amz-Date"),
		auth.Scope(),
		sha256Hex([]byte(canonical)),
	}, "\n")
	key := signingKey(secretAccessKey, auth.Date, auth.Region, auth.Service)
	return hex.EncodeToString(hmacSHA256(key, []byte(toSign)))
}

func canonicalRequest(r *http.Request, signedHeaders []string, payloadHash string) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte('\n')
	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	b.WriteString(uri)
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(r))
	b.WriteByte('\n')
	for _, name := range signedHeaders {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(canonicalHeaderValue(r, name))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(strings.Join(signedHeaders, ";"))
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String()
}

func canonicalQuery(r *http.Request) string {
	// url.Values.Encode sorts by key; SigV4 additionally requires %20 for
	// spaces rather than '+'.
	return strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20")
}

func canonicalHeaderValue(r *http.Request, name string) string {
	if name == "host" {
		return trimAll(r.Host)
	}
	values := r.Header.Values(textproto.CanonicalMIMEHeaderKey(name))
	trimmed := make([]string, len(values))
	for i, v := range values {
		trimmed[i] = trimAll(v)
	}
	return strings.Join(trimmed, ",")
}

// trimAll trims leading/trailing whitespace and collapses internal runs of
// whitespace to a single space, as required for canonical header values.
func trimAll(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func signingKey(secretAccessKey, date, region, service string) []byte {
	key := hmacSHA256([]byte("AWS4"+secretAccessKey), []byte(date))
	key = hmacSHA256(key, []byte(region))
	key = hmacSHA256(key, []byte(service))
	return hmacSHA256(key, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
