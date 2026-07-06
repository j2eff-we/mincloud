// Package iam implements an AWS IAM-compatible query API HTTP handler.
//
// Response shapes follow https://docs.aws.amazon.com/IAM/latest/APIReference/.
package iam

import (
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/j2eff-we/mincloud/internal/credgen"
	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/rolestore"
	"github.com/j2eff-we/mincloud/internal/service"
)

const (
	xmlns       = "https://iam.amazonaws.com/doc/2010-05-08/"
	serviceName = "iam"
)

type createAccessKeyResponse struct {
	XMLName   xml.Name              `xml:"CreateAccessKeyResponse"`
	Xmlns     string                `xml:"xmlns,attr"`
	Result    createAccessKeyResult `xml:"CreateAccessKeyResult"`
	RequestID string                `xml:"ResponseMetadata>RequestId"`
}

type createAccessKeyResult struct {
	AccessKey accessKey `xml:"AccessKey"`
}

type accessKey struct {
	UserName        string `xml:"UserName"`
	AccessKeyId     string `xml:"AccessKeyId"`
	Status          string `xml:"Status"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	CreateDate      string `xml:"CreateDate"`
}

type errorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Xmlns     string   `xml:"xmlns,attr"`
	Type      string   `xml:"Error>Type"`
	Code      string   `xml:"Error>Code"`
	Message   string   `xml:"Error>Message"`
	RequestID string   `xml:"RequestId"`
}

// Handler returns an http.Handler implementing the IAM query API. Each request
// is authenticated against store; created roles are kept in roles; verbose
// enables full request dumps to the log.
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
		log.Printf("iam %s by %s", action, cred.Identity.ARN)

		switch action {
		case "CreateAccessKey":
			createAccessKey(w, store, cred, form.Get("UserName"))
		case "CreateRole":
			createRole(w, roles, cred, form)
		default:
			writeError(w, http.StatusBadRequest, "InvalidAction", "Could not find operation "+action)
		}
	})
}

type createRoleResponse struct {
	XMLName   xml.Name         `xml:"CreateRoleResponse"`
	Xmlns     string           `xml:"xmlns,attr"`
	Result    createRoleResult `xml:"CreateRoleResult"`
	RequestID string           `xml:"ResponseMetadata>RequestId"`
}

type createRoleResult struct {
	Role roleXML `xml:"Role"`
}

type roleXML struct {
	Path                     string `xml:"Path"`
	RoleName                 string `xml:"RoleName"`
	RoleId                   string `xml:"RoleId"`
	Arn                      string `xml:"Arn"`
	CreateDate               string `xml:"CreateDate"`
	AssumeRolePolicyDocument string `xml:"AssumeRolePolicyDocument"`
}

// createRole records a new assumable role in the caller's account, carrying the
// trust policy that will decide who may assume it. There is no permission check
// here yet — that is what the policy engine (a later step) will add.
func createRole(w http.ResponseWriter, roles rolestore.Store, caller credstore.Credential, form url.Values) {
	name := form.Get("RoleName")
	trust := form.Get("AssumeRolePolicyDocument")
	if name == "" || trust == "" {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"RoleName and AssumeRolePolicyDocument are required")
		return
	}
	account := caller.Identity.Account
	role := rolestore.Role{
		RoleName:         name,
		RoleID:           credgen.UserID("AROA"),
		Account:          account,
		ARN:              "arn:aws:iam::" + account + ":role/" + name,
		AssumeRolePolicy: trust,
		CreateDate:       time.Now().UTC(),
	}
	roles.Put(role)

	service.WriteXML(w, http.StatusOK, createRoleResponse{
		Xmlns: xmlns,
		Result: createRoleResult{
			Role: roleXML{
				Path:                     "/",
				RoleName:                 role.RoleName,
				RoleId:                   role.RoleID,
				Arn:                      role.ARN,
				CreateDate:               role.CreateDate.Format("2006-01-02T15:04:05Z"),
				AssumeRolePolicyDocument: trust,
			},
		},
		RequestID: service.RequestID(),
	})
}

// createAccessKey issues a new access key for userName, or for the caller
// itself when userName is empty, and stores it so it authenticates
// immediately as that identity.
func createAccessKey(w http.ResponseWriter, store credstore.Store, caller credstore.Credential, userName string) {
	identity := caller.Identity
	name := userNameFromARN(identity.ARN)
	if userName != "" && userName != name {
		name = userName
		identity = credstore.Identity{
			Account: caller.Identity.Account,
			UserID:  credgen.UserID("AIDA"),
			ARN:     "arn:aws:iam::" + caller.Identity.Account + ":user/" + userName,
		}
	}

	accessKeyID := credgen.AccessKeyID(identity.Account)
	secretAccessKey, err := credgen.SecretAccessKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "InternalFailure", "unable to generate credentials")
		return
	}
	store.Put(accessKeyID, credstore.Credential{
		SecretAccessKey: secretAccessKey,
		Identity:        identity,
	})

	service.WriteXML(w, http.StatusOK, createAccessKeyResponse{
		Xmlns: xmlns,
		Result: createAccessKeyResult{
			AccessKey: accessKey{
				UserName:        name,
				AccessKeyId:     accessKeyID,
				Status:          "Active",
				SecretAccessKey: secretAccessKey,
				CreateDate:      time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			},
		},
		RequestID: service.RequestID(),
	})
}

// userNameFromARN extracts the trailing path segment of an IAM user ARN
// (arn:aws:iam::<account>:user/<name> -> <name>).
func userNameFromARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
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
