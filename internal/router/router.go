// Package router dispatches requests to service handlers on a single port.
//
// SigV4 requires every request's credential scope to name its target service
// (e.g. 20260724/ap-northeast-2/ec2/aws4_request), so the Authorization
// header alone tells us where a request belongs — no per-service ports,
// paths, or hostnames needed. This is in-process glue: if services ever
// split into separate processes, a gateway takes this role and the service
// handlers move unchanged.
package router

import (
	"encoding/xml"
	"net/http"

	"github.com/j2eff-we/mincloud/internal/service"
	"github.com/j2eff-we/mincloud/internal/sigv4"
)

type errorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Type      string   `xml:"Error>Type"`
	Code      string   `xml:"Error>Code"`
	Message   string   `xml:"Error>Message"`
	RequestID string   `xml:"RequestId"`
}

// New returns a handler that routes each request to services[scope-service].
// Signature verification stays inside each service handler; the router only
// parses the Authorization header to pick a destination.
func New(services map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusForbidden, "MissingAuthenticationToken",
				"Request is missing Authentication Token")
			return
		}
		auth, err := sigv4.ParseAuthorization(authHeader)
		if err != nil {
			writeError(w, http.StatusForbidden, "IncompleteSignature", err.Error())
			return
		}
		h, ok := services[auth.Service]
		if !ok {
			writeError(w, http.StatusBadRequest, "UnknownService",
				"mincloud does not implement service '"+auth.Service+"'")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	service.WriteXML(w, status, errorResponse{
		Type:      "Sender",
		Code:      code,
		Message:   message,
		RequestID: service.RequestID(),
	})
}
