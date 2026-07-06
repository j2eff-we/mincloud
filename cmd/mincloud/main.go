package main

import (
	"cmp"
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/rolestore"
	"github.com/j2eff-we/mincloud/internal/service/iam"
	"github.com/j2eff-we/mincloud/internal/service/mgmt"
	"github.com/j2eff-we/mincloud/internal/service/sts"
)

func main() {
	// The admin subcommand is the out-of-band bootstrap plane (account
	// creation); everything else starts the SigV4 service plane.
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		runAdmin(os.Args[2:])
		return
	}
	runServer()
}

func runServer() {
	stsAddr := flag.String("addr", cmp.Or(os.Getenv("MINCLOUD_STS_ADDR"), os.Getenv("MINCLOUD_ADDR"), ":9900"),
		"STS listen address (env: MINCLOUD_STS_ADDR, legacy: MINCLOUD_ADDR)")
	iamAddr := flag.String("iam-addr", cmp.Or(os.Getenv("MINCLOUD_IAM_ADDR"), ":9910"),
		"IAM listen address (env: MINCLOUD_IAM_ADDR)")
	mgmtAddr := flag.String("mgmt-addr", cmp.Or(os.Getenv("MINCLOUD_MGMT_ADDR"), ":9930"),
		"mincloud control service listen address (env: MINCLOUD_MGMT_ADDR)")
	dynamoEndpoint := flag.String("dynamodb-endpoint", os.Getenv("MINCLOUD_DYNAMODB_ENDPOINT"),
		"DynamoDB endpoint to persist credentials in; empty keeps them in memory (env: MINCLOUD_DYNAMODB_ENDPOINT)")
	verbose := flag.Bool("v", false, "log full request dumps")
	flag.Parse()

	store, err := openStore(*dynamoEndpoint)
	if err != nil {
		log.Fatalf("open credstore: %v", err)
	}
	accessKeyID := loadManagementRoot(store)
	roles := rolestore.New()

	stsLn, err := net.Listen("tcp", *stsAddr)
	if err != nil {
		log.Fatal(err)
	}
	iamLn, err := net.Listen("tcp", *iamAddr)
	if err != nil {
		log.Fatal(err)
	}
	mgmtLn, err := net.Listen("tcp", *mgmtAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mincloud sts on %s, iam on %s, control on %s (management access key %s)",
		stsLn.Addr(), iamLn.Addr(), mgmtLn.Addr(), accessKeyID)

	errc := make(chan error, 3)
	go func() { errc <- http.Serve(stsLn, sts.Handler(store, roles, *verbose)) }()
	go func() { errc <- http.Serve(iamLn, iam.Handler(store, roles, *verbose)) }()
	go func() { errc <- http.Serve(mgmtLn, mgmt.Handler(store, *verbose)) }()
	log.Fatal(<-errc)
}

// openStore selects the credential backing: DynamoDB when an endpoint is set,
// so credentials survive restarts, otherwise an in-memory map. The rest of the
// program only ever sees a credstore.Store, unaware of which it got.
func openStore(dynamoEndpoint string) (credstore.Store, error) {
	if dynamoEndpoint == "" {
		return credstore.New(), nil
	}
	region := cmp.Or(os.Getenv("MINCLOUD_DYNAMODB_REGION"), "us-east-1")
	table := cmp.Or(os.Getenv("MINCLOUD_DYNAMODB_TABLE"), "mincloud-credentials")
	log.Printf("persisting credentials in DynamoDB at %s (table %q)", dynamoEndpoint, table)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return credstore.OpenDynamo(ctx, dynamoEndpoint, region, table)
}

// loadManagementRoot seeds the genesis "management account" and its root
// credential — the one account that must exist before any signed request can be
// made, the way an AWS account's root exists the moment you sign up. Everything
// else is created from here. In a real deployment you would generate and guard
// these; the defaults are well-known dev values, overridable via env.
func loadManagementRoot(store credstore.Store) string {
	accessKeyID := cmp.Or(os.Getenv("MINCLOUD_ROOT_ACCESS_KEY_ID"), os.Getenv("MINCLOUD_ACCESS_KEY_ID"), "MINCLOUDTESTKEY0000A")
	account := cmp.Or(os.Getenv("MINCLOUD_MANAGEMENT_ACCOUNT_ID"), "000000000001")
	secret := cmp.Or(os.Getenv("MINCLOUD_ROOT_SECRET_ACCESS_KEY"), os.Getenv("MINCLOUD_SECRET_ACCESS_KEY"), "mincloud-test-secret-not-real")
	store.Put(accessKeyID, credstore.Credential{
		SecretAccessKey: secret,
		Identity: credstore.Identity{
			Account: account,
			UserID:  account, // the root user's UserId is the account id
			ARN:     "arn:aws:iam::" + account + ":root",
		},
	})
	return accessKeyID
}
