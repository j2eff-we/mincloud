// Package sts renders responses for the STS query API.
//
// Response shapes follow https://docs.aws.amazon.com/STS/latest/APIReference/
// (see also moto's moto/sts/responses.py for reference templates).
package sts

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"net/http"
)

const xmlns = "https://sts.amazonaws.com/doc/2011-06-15/"

// CallerIdentity is the payload of a GetCallerIdentity response.
type CallerIdentity struct {
	Account string
	UserID  string
	ARN     string
}

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

// WriteGetCallerIdentity writes a successful GetCallerIdentity XML response.
func WriteGetCallerIdentity(w http.ResponseWriter, id CallerIdentity) {
	writeXML(w, http.StatusOK, getCallerIdentityResponse{
		Xmlns: xmlns,
		Result: getCallerIdentityResult{
			Arn:     id.ARN,
			UserID:  id.UserID,
			Account: id.Account,
		},
		RequestID: requestID(),
	})
}

// WriteError writes an STS ErrorResponse with the given code and message.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	writeXML(w, status, errorResponse{
		Xmlns:     xmlns,
		Type:      "Sender",
		Code:      code,
		Message:   message,
		RequestID: requestID(),
	})
}

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	enc.Encode(v)
}

func requestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:])
}
