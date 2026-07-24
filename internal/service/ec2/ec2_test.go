package ec2

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/sigv4"
)

const (
	testAccessKeyID = "EC2TESTKEY0000000000"
	testSecretKey   = "ec2-test-secret-not-real"
)

var testIdentity = credstore.Identity{
	Account: "123456789012",
	UserID:  "AIDATESTKEY000000000A",
	ARN:     "arn:aws:iam::123456789012:user/jeff",
}

func newTestStore() credstore.Store {
	store := credstore.New()
	store.Put(testAccessKeyID, credstore.Credential{SecretAccessKey: testSecretKey, Identity: testIdentity})
	return store
}

func signedRequest(t *testing.T, scopeService, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("X-Amz-Date", "20260705T120000Z")

	auth := sigv4.Authorization{
		AccessKeyID:   testAccessKeyID,
		Date:          "20260705",
		Region:        "ap-northeast-2",
		Service:       scopeService,
		SignedHeaders: []string{"content-type", "host", "x-amz-date"},
	}
	auth.Signature = sigv4.ComputeSignature(r, auth, []byte(body), testSecretKey)
	r.Header.Set("Authorization", sigv4.Algorithm+" Credential="+testAccessKeyID+"/"+auth.Scope()+
		", SignedHeaders="+strings.Join(auth.SignedHeaders, ";")+", Signature="+auth.Signature)
	return r
}

func TestRunThenDescribeInstances(t *testing.T) {
	store := newTestStore()
	handler := Handler(store, false)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, signedRequest(t, "ec2",
		"Action=RunInstances&Version=2016-11-15&ImageId=ami-12345678&InstanceType=t3.small&MinCount=2&MaxCount=2"))
	if w.Code != http.StatusOK {
		t.Fatalf("RunInstances status = %d, body = %s", w.Code, w.Body.String())
	}
	var run runInstancesResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatalf("Unmarshal RunInstances: %v", err)
	}
	if len(run.Instances) != 2 {
		t.Fatalf("len(Instances) = %d, want 2", len(run.Instances))
	}
	if run.Instances[0].State.Name != "pending" {
		t.Errorf("State = %q, want pending", run.Instances[0].State.Name)
	}
	if run.OwnerID != testIdentity.Account {
		t.Errorf("OwnerID = %q, want %q", run.OwnerID, testIdentity.Account)
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, signedRequest(t, "ec2", "Action=DescribeInstances&Version=2016-11-15"))
	if w.Code != http.StatusOK {
		t.Fatalf("DescribeInstances status = %d, body = %s", w.Code, w.Body.String())
	}
	var desc describeInstancesResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &desc); err != nil {
		t.Fatalf("Unmarshal DescribeInstances: %v", err)
	}
	if len(desc.Reservations) != 1 || len(desc.Reservations[0].Instances) != 2 {
		t.Fatalf("reservations = %+v, want 1 reservation with 2 instances", desc.Reservations)
	}
	got := desc.Reservations[0].Instances[0]
	if got.InstanceID != run.Instances[0].InstanceID {
		t.Errorf("InstanceID = %q, want %q", got.InstanceID, run.Instances[0].InstanceID)
	}
	if got.State.Name != "running" {
		t.Errorf("State = %q, want running", got.State.Name)
	}
	if got.ImageID != "ami-12345678" || got.InstanceType != "t3.small" {
		t.Errorf("instance = %+v, want ami-12345678 / t3.small", got)
	}
}

func TestErrorUsesEC2ResponseShape(t *testing.T) {
	store := newTestStore()
	w := httptest.NewRecorder()
	Handler(store, false).ServeHTTP(w, signedRequest(t, "ec2", "Action=DoesNotExist&Version=2016-11-15"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp errorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Code != "InvalidAction" {
		t.Errorf("Code = %q, want InvalidAction", resp.Code)
	}
	if !strings.HasPrefix(w.Body.String(), xml.Header+"<Response>") {
		t.Errorf("error body should be an EC2-style <Response>, got: %s", w.Body.String())
	}
}
