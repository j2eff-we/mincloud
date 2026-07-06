// Package mgmt implements mincloud's control service — the signed API for
// managing the organization. Its one operation, CreateAccount, is where the
// first *authorization* check lives: a request may be perfectly authenticated
// yet still refused, because only the management account's root may create
// accounts.
package mgmt

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/j2eff-we/mincloud/internal/credgen"
	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/service"
)

const (
	xmlns       = "https://mincloud.local/doc/2026-01-01/"
	serviceName = "mincloud"

	// managementAccountID is the genesis account; only its root may create
	// accounts. Kept in sync with the seed in cmd/mincloud (loadManagementRoot).
	managementAccountID = "000000000001"
)

type createAccountResponse struct {
	XMLName   xml.Name            `xml:"CreateAccountResponse"`
	Xmlns     string              `xml:"xmlns,attr"`
	Result    createAccountResult `xml:"CreateAccountResult"`
	RequestID string              `xml:"ResponseMetadata>RequestId"`
}

type createAccountResult struct {
	Account account `xml:"Account"`
}

type account struct {
	AccountID           string `xml:"AccountId"`
	RootAccessKeyID     string `xml:"RootAccessKeyId"`
	RootSecretAccessKey string `xml:"RootSecretAccessKey"`
}

type errorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Xmlns     string   `xml:"xmlns,attr"`
	Type      string   `xml:"Error>Type"`
	Code      string   `xml:"Error>Code"`
	Message   string   `xml:"Error>Message"`
	RequestID string   `xml:"RequestId"`
}

// Handler returns an http.Handler implementing the mincloud control API. Each
// request is authenticated against store; verbose enables full request dumps.
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
		log.Printf("mincloud %s by %s", action, cred.Identity.ARN)

		switch action {
		case "CreateAccount":
			createAccount(w, store, cred)
		default:
			writeError(w, http.StatusBadRequest, "InvalidAction", "Could not find operation "+action)
		}
	})
}

// createAccount mints a new member account with its own root credential, and
// returns that root credential to the caller. It is gated: only the management
// account's root is authorized. This is authentication (who are you) followed
// by authorization (are you allowed) — the two are not the same, and here they
// diverge for the first time.
func createAccount(w http.ResponseWriter, store credstore.Store, caller credstore.Credential) {
	if !isManagementRoot(caller.Identity) {
		writeError(w, http.StatusForbidden, "AccessDenied", fmt.Sprintf(
			"User: %s is not authorized to perform: mincloud:CreateAccount", caller.Identity.ARN))
		return
	}

	accountID := credgen.AccountID()
	accessKeyID := credgen.AccessKeyID(accountID)
	secret, err := credgen.SecretAccessKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "InternalFailure", "unable to generate credentials")
		return
	}
	store.Put(accessKeyID, credstore.Credential{
		SecretAccessKey: secret,
		Identity: credstore.Identity{
			Account: accountID,
			UserID:  accountID, // the root user's UserId is the account id
			ARN:     "arn:aws:iam::" + accountID + ":root",
		},
	})

	service.WriteXML(w, http.StatusOK, createAccountResponse{
		Xmlns: xmlns,
		Result: createAccountResult{
			Account: account{
				AccountID:           accountID,
				RootAccessKeyID:     accessKeyID,
				RootSecretAccessKey: secret,
			},
		},
		RequestID: service.RequestID(),
	})
}

// isManagementRoot reports whether identity is the root of the management
// account — the only principal permitted to create accounts.
func isManagementRoot(id credstore.Identity) bool {
	return id.Account == managementAccountID && strings.HasSuffix(id.ARN, ":root")
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
