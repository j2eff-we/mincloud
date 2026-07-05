// Package sts implements an AWS STS-compatible query API HTTP handler.
//
// Response shapes follow https://docs.aws.amazon.com/STS/latest/APIReference/
// (see also moto's moto/sts/responses.py for reference templates).
package sts

import (
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/service"
)

const (
	xmlns       = "https://sts.amazonaws.com/doc/2011-06-15/"
	serviceName = "sts"
)

type getCallerIdentityResponse struct {
	XMLName   xml.Name                `xml:"GetCallerIdentityResponse"`
	Xmlns     string                  `xml:"xmlns,attr"`
	Result    getCallerIdentityResult `xml:"GetCallerIdentityResult"`
	RequestID string                  `xml:"ResponseMetadata>RequestId"`
}

type getCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserID  string `xml:"UserId"`
	Account string `xml:"Account"`
}

type errorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Xmlns     string   `xml:"xmlns,attr"`
	Type      string   `xml:"Error>Type"`
	Code      string   `xml:"Error>Code"`
	Message   string   `xml:"Error>Message"`
	RequestID string   `xml:"RequestId"`
}

// Handler returns an http.Handler implementing the STS query API. Each
// request is authenticated against store; verbose enables full request
// dumps to the log.
func Handler(store credstore.Store, verbose bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verbose {
			if dump, err := httputil.DumpRequest(r, true); err == nil {
				log.Printf("request:\n%s", dump)
			}
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequest", "unable to read request body")
			return
		}
		cred, authErr := service.Authenticate(r, body, store, serviceName)
		if authErr != nil {
			writeError(w, authErr.Status, authErr.Code, authErr.Message)
			return
		}

		form, err := url.ParseQuery(string(body))
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequest", "unable to parse request body")
			return
		}
		action := form.Get("Action")
		log.Printf("sts %s by %s", action, cred.Identity.ARN)

		switch action {
		case "GetCallerIdentity":
			writeGetCallerIdentity(w, cred.Identity)
		default:
			writeError(w, http.StatusBadRequest, "InvalidAction", "Could not find operation "+action)
		}
	})
}

func writeGetCallerIdentity(w http.ResponseWriter, id credstore.Identity) {
	service.WriteXML(w, http.StatusOK, getCallerIdentityResponse{
		Xmlns: xmlns,
		Result: getCallerIdentityResult{
			Arn:     id.ARN,
			UserID:  id.UserID,
			Account: id.Account,
		},
		RequestID: service.RequestID(),
	})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	service.WriteXML(w, status, errorResponse{
		Xmlns:     xmlns,
		Type:      "Sender",
		Code:      code,
		Message:   message,
		RequestID: service.RequestID(),
	})
}
