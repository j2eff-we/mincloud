// Package sts implements an AWS STS-compatible query API HTTP handler.
//
// Response shapes follow https://docs.aws.amazon.com/STS/latest/APIReference/
// (see also moto's moto/sts/responses.py for reference templates).
package sts

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/j2eff-we/mincloud/internal/credgen"
	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/policy"
	"github.com/j2eff-we/mincloud/internal/rolestore"
	"github.com/j2eff-we/mincloud/internal/service"
)

const sessionDuration = time.Hour

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

// Handler returns an http.Handler implementing the STS query API. Each request
// is authenticated against store; AssumeRole reads roles and writes the
// temporary credentials back into store. verbose enables full request dumps.
func Handler(store credstore.Store, roles rolestore.Store, verbose bool) http.Handler {
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
		case "AssumeRole":
			assumeRole(w, store, roles, cred, form)
		default:
			writeError(w, http.StatusBadRequest, "InvalidAction", "Could not find operation "+action)
		}
	})
}

type assumeRoleResponse struct {
	XMLName   xml.Name         `xml:"AssumeRoleResponse"`
	Xmlns     string           `xml:"xmlns,attr"`
	Result    assumeRoleResult `xml:"AssumeRoleResult"`
	RequestID string           `xml:"ResponseMetadata>RequestId"`
}

type assumeRoleResult struct {
	Credentials     credentials     `xml:"Credentials"`
	AssumedRoleUser assumedRoleUser `xml:"AssumedRoleUser"`
}

type credentials struct {
	AccessKeyId     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type assumedRoleUser struct {
	AssumedRoleId string `xml:"AssumedRoleId"`
	Arn           string `xml:"Arn"`
}

// assumeRole hands the caller temporary credentials for a role, but only if the
// role's trust policy names them. This is the first time authorization is
// decided from a policy *document* rather than a hardcoded check — the caller
// is already authenticated; the trust policy decides whether they may assume.
func assumeRole(w http.ResponseWriter, store credstore.Store, roles rolestore.Store, caller credstore.Credential, form url.Values) {
	roleArn := form.Get("RoleArn")
	sessionName := form.Get("RoleSessionName")
	if roleArn == "" || sessionName == "" {
		writeError(w, http.StatusBadRequest, "ValidationError", "RoleArn and RoleSessionName are required")
		return
	}
	role, ok := roles.Get(roleArn)
	if !ok || !policy.TrustAllows(role.AssumeRolePolicy, caller.Identity.ARN, caller.Identity.Account) {
		writeError(w, http.StatusForbidden, "AccessDenied", fmt.Sprintf(
			"User: %s is not authorized to perform: sts:AssumeRole on resource: %s", caller.Identity.ARN, roleArn))
		return
	}

	tempKey := credgen.TempAccessKeyID(role.Account)
	tempSecret, err := credgen.SecretAccessKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "InternalFailure", "unable to generate credentials")
		return
	}
	token, err := credgen.SessionToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "InternalFailure", "unable to generate session token")
		return
	}
	expires := time.Now().UTC().Add(sessionDuration)
	assumedID := role.RoleID + ":" + sessionName
	assumedArn := "arn:aws:sts::" + role.Account + ":assumed-role/" + role.RoleName + "/" + sessionName

	// The temporary credential authenticates as the assumed role until it
	// expires; store it so subsequent requests can look it up.
	store.Put(tempKey, credstore.Credential{
		SecretAccessKey: tempSecret,
		Identity:        credstore.Identity{Account: role.Account, UserID: assumedID, ARN: assumedArn},
		SessionToken:    token,
		Expires:         expires,
	})

	service.WriteXML(w, http.StatusOK, assumeRoleResponse{
		Xmlns: xmlns,
		Result: assumeRoleResult{
			Credentials: credentials{
				AccessKeyId:     tempKey,
				SecretAccessKey: tempSecret,
				SessionToken:    token,
				Expiration:      expires.Format(time.RFC3339),
			},
			AssumedRoleUser: assumedRoleUser{AssumedRoleId: assumedID, Arn: assumedArn},
		},
		RequestID: service.RequestID(),
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
