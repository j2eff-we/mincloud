// Package ec2 implements an AWS EC2-compatible query API HTTP handler.
//
// Response shapes follow https://docs.aws.amazon.com/AWSEC2/latest/APIReference/.
// EC2 uses the older query protocol: a lowercase <requestId>, no
// <ResponseMetadata> wrapper, and a <Response><Errors>… error envelope, all of
// which differ from IAM and STS.
package ec2

import (
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/service"
)

const (
	xmlns       = "http://ec2.amazonaws.com/doc/2016-11-15/"
	serviceName = "ec2"

	defaultInstanceType = "t2.micro"
	maxRunCount         = 64
	launchTimeFormat    = "2006-01-02T15:04:05.000Z"
)

type instanceState struct {
	Code int    `xml:"code"`
	Name string `xml:"name"`
}

type instanceItem struct {
	InstanceID    string        `xml:"instanceId"`
	ImageID       string        `xml:"imageId"`
	InstanceState instanceState `xml:"instanceState"`
	InstanceType  string        `xml:"instanceType"`
	LaunchTime    string        `xml:"launchTime"`
}

func toItem(inst *instance) instanceItem {
	return instanceItem{
		InstanceID:    inst.id,
		ImageID:       inst.imageID,
		InstanceState: instanceState{Code: inst.stateCode, Name: inst.stateName},
		InstanceType:  inst.instanceType,
		LaunchTime:    inst.launchTime.Format(launchTimeFormat),
	}
}

type runInstancesResponse struct {
	XMLName       xml.Name       `xml:"RunInstancesResponse"`
	Xmlns         string         `xml:"xmlns,attr"`
	RequestID     string         `xml:"requestId"`
	ReservationID string         `xml:"reservationId"`
	OwnerID       string         `xml:"ownerId"`
	InstancesSet  []instanceItem `xml:"instancesSet>item"`
}

type describeInstancesResponse struct {
	XMLName        xml.Name          `xml:"DescribeInstancesResponse"`
	Xmlns          string            `xml:"xmlns,attr"`
	RequestID      string            `xml:"requestId"`
	ReservationSet []reservationItem `xml:"reservationSet>item"`
}

type reservationItem struct {
	ReservationID string         `xml:"reservationId"`
	OwnerID       string         `xml:"ownerId"`
	InstancesSet  []instanceItem `xml:"instancesSet>item"`
}

type terminateInstancesResponse struct {
	XMLName      xml.Name        `xml:"TerminateInstancesResponse"`
	Xmlns        string          `xml:"xmlns,attr"`
	RequestID    string          `xml:"requestId"`
	InstancesSet []terminateItem `xml:"instancesSet>item"`
}

type terminateItem struct {
	InstanceID    string        `xml:"instanceId"`
	CurrentState  instanceState `xml:"currentState"`
	PreviousState instanceState `xml:"previousState"`
}

type errorResponse struct {
	XMLName   xml.Name `xml:"Response"`
	Code      string   `xml:"Errors>Error>Code"`
	Message   string   `xml:"Errors>Error>Message"`
	RequestID string   `xml:"RequestID"`
}

// Handler returns an http.Handler implementing the EC2 query API. Each request
// is authenticated against store; launched instances live in an in-memory
// instance store private to this handler. verbose enables full request dumps.
func Handler(store credstore.Store, verbose bool) http.Handler {
	insts := newInstanceStore()

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
		log.Printf("ec2 %s by %s", action, cred.Identity.ARN)

		switch action {
		case "RunInstances":
			runInstances(w, insts, cred, form)
		case "DescribeInstances":
			describeInstances(w, insts, form)
		case "TerminateInstances":
			terminateInstances(w, insts, form)
		default:
			writeError(w, http.StatusBadRequest, "InvalidAction", "Could not find operation "+action)
		}
	})
}

func runInstances(w http.ResponseWriter, insts *instanceStore, caller credstore.Credential, form url.Values) {
	imageID := form.Get("ImageId")
	if imageID == "" {
		writeError(w, http.StatusBadRequest, "MissingParameter", "The request must contain the parameter ImageId")
		return
	}
	instanceType := form.Get("InstanceType")
	if instanceType == "" {
		instanceType = defaultInstanceType
	}
	count := runCount(form)
	if count < 1 {
		writeError(w, http.StatusBadRequest, "InvalidParameterValue", "MaxCount must be at least 1")
		return
	}
	if count > maxRunCount {
		writeError(w, http.StatusBadRequest, "InstanceLimitExceeded",
			"MaxCount exceeds the mincloud per-request limit of "+strconv.Itoa(maxRunCount))
		return
	}

	launched := insts.run(imageID, instanceType, caller.Identity.Account, count)
	items := make([]instanceItem, len(launched))
	for i, inst := range launched {
		items[i] = toItem(inst)
	}
	service.WriteXML(w, http.StatusOK, runInstancesResponse{
		Xmlns:         xmlns,
		RequestID:     service.RequestID(),
		ReservationID: launched[0].reservationID,
		OwnerID:       caller.Identity.Account,
		InstancesSet:  items,
	})
}

func describeInstances(w http.ResponseWriter, insts *instanceStore, form url.Values) {
	found := insts.describe(instanceIDs(form))

	// Group instances back into their reservations, preserving launch order.
	var order []string
	byReservation := map[string]*reservationItem{}
	for _, inst := range found {
		res, ok := byReservation[inst.reservationID]
		if !ok {
			res = &reservationItem{ReservationID: inst.reservationID, OwnerID: inst.ownerID}
			byReservation[inst.reservationID] = res
			order = append(order, inst.reservationID)
		}
		res.InstancesSet = append(res.InstancesSet, toItem(inst))
	}
	reservations := make([]reservationItem, len(order))
	for i, id := range order {
		reservations[i] = *byReservation[id]
	}

	service.WriteXML(w, http.StatusOK, describeInstancesResponse{
		Xmlns:          xmlns,
		RequestID:      service.RequestID(),
		ReservationSet: reservations,
	})
}

func terminateInstances(w http.ResponseWriter, insts *instanceStore, form url.Values) {
	ids := instanceIDs(form)
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "MissingParameter",
			"The request must contain the parameter InstanceId")
		return
	}
	results := insts.terminate(ids)
	if len(results) == 0 {
		writeError(w, http.StatusBadRequest, "InvalidInstanceID.NotFound",
			"The instance ID does not exist")
		return
	}
	items := make([]terminateItem, len(results))
	for i, t := range results {
		items[i] = terminateItem{
			InstanceID:    t.id,
			CurrentState:  instanceState{Code: stateCodeTerminated, Name: stateNameTerminated},
			PreviousState: instanceState{Code: t.previousCode, Name: t.previousName},
		}
	}
	service.WriteXML(w, http.StatusOK, terminateInstancesResponse{
		Xmlns:        xmlns,
		RequestID:    service.RequestID(),
		InstancesSet: items,
	})
}

// runCount reads MaxCount from an EC2 RunInstances request, defaulting to 1
// when absent (as the aws CLI omits it for a single instance).
func runCount(form url.Values) int {
	raw := form.Get("MaxCount")
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}

// instanceIDs collects the InstanceId.N list an EC2 query request uses to name
// specific instances (InstanceId.1, InstanceId.2, …).
func instanceIDs(form url.Values) []string {
	var ids []string
	for i := 1; ; i++ {
		v := form.Get("InstanceId." + strconv.Itoa(i))
		if v == "" {
			break
		}
		ids = append(ids, v)
	}
	return ids
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	service.WriteXML(w, status, errorResponse{
		Code:      code,
		Message:   message,
		RequestID: service.RequestID(),
	})
}
