// Package ec2 implements a minimal AWS EC2-compatible query API HTTP handler.
//
// Response shapes follow https://docs.aws.amazon.com/AWSEC2/latest/APIReference/.
// Unlike IAM/STS, EC2 renders errors as <Response><Errors><Error> without a
// namespace, and result elements use lowerCamelCase names.
package ec2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/service"
)

const (
	xmlns       = "http://ec2.amazonaws.com/doc/2016-11-15/"
	serviceName = "ec2"
	region      = "ap-northeast-2"
)

type instanceState struct {
	Code int    `xml:"code"`
	Name string `xml:"name"`
}

type instance struct {
	InstanceID   string        `xml:"instanceId"`
	ImageID      string        `xml:"imageId"`
	State        instanceState `xml:"instanceState"`
	InstanceType string        `xml:"instanceType"`
	LaunchTime   string        `xml:"launchTime"`
	Placement    struct {
		AvailabilityZone string `xml:"availabilityZone"`
	} `xml:"placement"`
}

type reservation struct {
	ReservationID string     `xml:"reservationId"`
	OwnerID       string     `xml:"ownerId"`
	Instances     []instance `xml:"instancesSet>item"`
}

type runInstancesResponse struct {
	XMLName       xml.Name   `xml:"RunInstancesResponse"`
	Xmlns         string     `xml:"xmlns,attr"`
	RequestID     string     `xml:"requestId"`
	ReservationID string     `xml:"reservationId"`
	OwnerID       string     `xml:"ownerId"`
	Instances     []instance `xml:"instancesSet>item"`
}

type describeInstancesResponse struct {
	XMLName      xml.Name      `xml:"DescribeInstancesResponse"`
	Xmlns        string        `xml:"xmlns,attr"`
	RequestID    string        `xml:"requestId"`
	Reservations []reservation `xml:"reservationSet>item"`
}

type describeRegionsResponse struct {
	XMLName   xml.Name `xml:"DescribeRegionsResponse"`
	Xmlns     string   `xml:"xmlns,attr"`
	RequestID string   `xml:"requestId"`
	Regions   []struct {
		RegionName     string `xml:"regionName"`
		RegionEndpoint string `xml:"regionEndpoint"`
	} `xml:"regionInfo>item"`
}

type errorResponse struct {
	XMLName   xml.Name `xml:"Response"`
	Code      string   `xml:"Errors>Error>Code"`
	Message   string   `xml:"Errors>Error>Message"`
	RequestID string   `xml:"RequestID"`
}

// registry is the in-memory instance store: enough state for a
// run-instances / describe-instances round trip to look real.
type registry struct {
	mu           sync.Mutex
	reservations []reservation
}

// Handler returns an http.Handler implementing a minimal EC2 query API.
// Each request is authenticated against store; verbose enables full
// request dumps to the log.
func Handler(store credstore.Store, verbose bool) http.Handler {
	reg := &registry{}
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
			runInstances(w, reg, cred.Identity.Account, form)
		case "DescribeInstances":
			describeInstances(w, reg)
		case "DescribeRegions":
			describeRegions(w)
		default:
			writeError(w, http.StatusBadRequest, "InvalidAction",
				"The action "+action+" is not valid for this web service.")
		}
	})
}

// runInstances launches MinCount fake instances. The response reports them
// as pending (like real EC2); by the next DescribeInstances they are running.
func runInstances(w http.ResponseWriter, reg *registry, account string, form url.Values) {
	imageID := form.Get("ImageId")
	if imageID == "" {
		writeError(w, http.StatusBadRequest, "MissingParameter",
			"The request must contain the parameter ImageId")
		return
	}
	instanceType := form.Get("InstanceType")
	if instanceType == "" {
		instanceType = "t3.micro"
	}
	count := 1
	if n, err := strconv.Atoi(form.Get("MinCount")); err == nil && n > 0 {
		count = n
	}

	launchTime := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	res := reservation{
		ReservationID: "r-" + randomHexID(),
		OwnerID:       account,
	}
	for range count {
		inst := instance{
			InstanceID:   "i-" + randomHexID(),
			ImageID:      imageID,
			State:        instanceState{Code: 16, Name: "running"},
			InstanceType: instanceType,
			LaunchTime:   launchTime,
		}
		inst.Placement.AvailabilityZone = region + "a"
		res.Instances = append(res.Instances, inst)
	}

	reg.mu.Lock()
	reg.reservations = append(reg.reservations, res)
	reg.mu.Unlock()

	pending := make([]instance, len(res.Instances))
	for i, inst := range res.Instances {
		inst.State = instanceState{Code: 0, Name: "pending"}
		pending[i] = inst
	}
	service.WriteXML(w, http.StatusOK, runInstancesResponse{
		Xmlns:         xmlns,
		RequestID:     service.RequestID(),
		ReservationID: res.ReservationID,
		OwnerID:       res.OwnerID,
		Instances:     pending,
	})
}

func describeInstances(w http.ResponseWriter, reg *registry) {
	reg.mu.Lock()
	reservations := make([]reservation, len(reg.reservations))
	copy(reservations, reg.reservations)
	reg.mu.Unlock()

	service.WriteXML(w, http.StatusOK, describeInstancesResponse{
		Xmlns:        xmlns,
		RequestID:    service.RequestID(),
		Reservations: reservations,
	})
}

func describeRegions(w http.ResponseWriter) {
	resp := describeRegionsResponse{Xmlns: xmlns, RequestID: service.RequestID()}
	for _, name := range []string{region, "us-east-1"} {
		resp.Regions = append(resp.Regions, struct {
			RegionName     string `xml:"regionName"`
			RegionEndpoint string `xml:"regionEndpoint"`
		}{RegionName: name, RegionEndpoint: "ec2." + name + ".amazonaws.com"})
	}
	service.WriteXML(w, http.StatusOK, resp)
}

// randomHexID returns a 17-hex-character suffix matching EC2's long
// resource ID format (i-0123456789abcdef0).
func randomHexID() string {
	var b [9]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])[:17]
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	service.WriteXML(w, status, errorResponse{
		Code:      code,
		Message:   message,
		RequestID: service.RequestID(),
	})
}
