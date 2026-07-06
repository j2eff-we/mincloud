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
	testAccessKeyID = "EC2TESTKEY000000000A"
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

// signedRequest builds a self-signed EC2 POST request. The signature verifier
// itself is covered by internal/sigv4's real-capture vectors; here we only need
// requests the shared Authenticate accepts.
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

// call sends one signed EC2 action to h and returns the recorder.
func call(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(t, "ec2", body))
	return w
}

func TestRunInstancesReturnsPending(t *testing.T) {
	h := Handler(newTestStore(), false)
	w := call(t, h, "Action=RunInstances&ImageId=ami-01&InstanceType=t2.micro&MinCount=1&MaxCount=1&Version=2016-11-15")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp runInstancesResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(resp.InstancesSet) != 1 {
		t.Fatalf("instances = %d, want 1", len(resp.InstancesSet))
	}
	inst := resp.InstancesSet[0]
	if !strings.HasPrefix(inst.InstanceID, "i-") {
		t.Errorf("InstanceId = %q, want i- prefix", inst.InstanceID)
	}
	if inst.InstanceState.Name != stateNamePending {
		t.Errorf("state = %q, want %q", inst.InstanceState.Name, stateNamePending)
	}
	if inst.ImageID != "ami-01" || inst.InstanceType != "t2.micro" {
		t.Errorf("image/type = %q/%q, want ami-01/t2.micro", inst.ImageID, inst.InstanceType)
	}
	if !strings.HasPrefix(resp.ReservationID, "r-") {
		t.Errorf("ReservationId = %q, want r- prefix", resp.ReservationID)
	}
}

func TestDescribeTransitionsPendingToRunning(t *testing.T) {
	h := Handler(newTestStore(), false)
	call(t, h, "Action=RunInstances&ImageId=ami-01&MaxCount=1&Version=2016-11-15")

	w := call(t, h, "Action=DescribeInstances&Version=2016-11-15")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp describeInstancesResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(resp.ReservationSet) != 1 || len(resp.ReservationSet[0].InstancesSet) != 1 {
		t.Fatalf("reservations/instances = %d/%v, want 1/1", len(resp.ReservationSet), resp.ReservationSet)
	}
	if got := resp.ReservationSet[0].InstancesSet[0].InstanceState.Name; got != stateNameRunning {
		t.Errorf("state = %q, want %q", got, stateNameRunning)
	}
}

func TestTerminateReportsPreviousAndCurrentState(t *testing.T) {
	h := Handler(newTestStore(), false)
	runW := call(t, h, "Action=RunInstances&ImageId=ami-01&MaxCount=1&Version=2016-11-15")
	var run runInstancesResponse
	if err := xml.Unmarshal(runW.Body.Bytes(), &run); err != nil {
		t.Fatalf("Unmarshal run: %v", err)
	}
	id := run.InstancesSet[0].InstanceID
	// Describe once so the instance is running, giving terminate a non-pending
	// previous state.
	call(t, h, "Action=DescribeInstances&Version=2016-11-15")

	w := call(t, h, "Action=TerminateInstances&InstanceId.1="+id+"&Version=2016-11-15")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp terminateInstancesResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(resp.InstancesSet) != 1 {
		t.Fatalf("instances = %d, want 1", len(resp.InstancesSet))
	}
	item := resp.InstancesSet[0]
	if item.InstanceID != id {
		t.Errorf("InstanceId = %q, want %q", item.InstanceID, id)
	}
	if item.CurrentState.Name != stateNameTerminated {
		t.Errorf("current = %q, want %q", item.CurrentState.Name, stateNameTerminated)
	}
	if item.PreviousState.Name != stateNameRunning {
		t.Errorf("previous = %q, want %q", item.PreviousState.Name, stateNameRunning)
	}
}

func TestRunInstancesRequiresImageId(t *testing.T) {
	h := Handler(newTestStore(), false)
	w := call(t, h, "Action=RunInstances&MaxCount=1&Version=2016-11-15")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
	var resp errorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Code != "MissingParameter" {
		t.Errorf("Code = %q, want MissingParameter", resp.Code)
	}
}

func TestRejectsWrongServiceScope(t *testing.T) {
	h := Handler(newTestStore(), false)
	// Signed for sts, sent to the ec2 handler: rejected despite a valid key.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(t, "sts", "Action=DescribeInstances&Version=2016-11-15"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
	var resp errorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Code != "SignatureDoesNotMatch" {
		t.Errorf("Code = %q, want SignatureDoesNotMatch", resp.Code)
	}
}
