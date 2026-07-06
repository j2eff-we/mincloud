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
	"github.com/j2eff-we/mincloud/internal/service/iam"
	"github.com/j2eff-we/mincloud/internal/service/sts"
)

func main() {
	stsAddr := flag.String("addr", cmp.Or(os.Getenv("MINCLOUD_STS_ADDR"), os.Getenv("MINCLOUD_ADDR"), ":9900"),
		"STS listen address (env: MINCLOUD_STS_ADDR, legacy: MINCLOUD_ADDR)")
	iamAddr := flag.String("iam-addr", cmp.Or(os.Getenv("MINCLOUD_IAM_ADDR"), ":9910"),
		"IAM listen address (env: MINCLOUD_IAM_ADDR)")
	dynamoEndpoint := flag.String("dynamodb-endpoint", os.Getenv("MINCLOUD_DYNAMODB_ENDPOINT"),
		"DynamoDB endpoint to persist credentials in; empty keeps them in memory (env: MINCLOUD_DYNAMODB_ENDPOINT)")
	verbose := flag.Bool("v", false, "log full request dumps")
	flag.Parse()

	store, err := openStore(*dynamoEndpoint)
	if err != nil {
		log.Fatalf("open credstore: %v", err)
	}
	accessKeyID := loadDevCredential(store)

	stsLn, err := net.Listen("tcp", *stsAddr)
	if err != nil {
		log.Fatal(err)
	}
	iamLn, err := net.Listen("tcp", *iamAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mincloud sts listening on %s, iam listening on %s (access key %s)",
		stsLn.Addr(), iamLn.Addr(), accessKeyID)

	errc := make(chan error, 2)
	go func() { errc <- http.Serve(stsLn, sts.Handler(store, *verbose)) }()
	go func() { errc <- http.Serve(iamLn, iam.Handler(store, *verbose)) }()
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

// loadDevCredential registers the single development credential, configurable
// via environment variables. Defaults are well-known fake values for local use.
func loadDevCredential(store credstore.Store) string {
	accessKeyID := cmp.Or(os.Getenv("MINCLOUD_ACCESS_KEY_ID"), "MINCLOUDTESTKEY0000A")
	account := cmp.Or(os.Getenv("MINCLOUD_ACCOUNT_ID"), "123456789012")
	user := cmp.Or(os.Getenv("MINCLOUD_USER"), "jeff")
	store.Put(accessKeyID, credstore.Credential{
		SecretAccessKey: cmp.Or(os.Getenv("MINCLOUD_SECRET_ACCESS_KEY"), "mincloud-test-secret-not-real"),
		Identity: credstore.Identity{
			Account: account,
			UserID:  "AIDA" + accessKeyID[4:],
			ARN:     "arn:aws:iam::" + account + ":user/" + user,
		},
	})
	return accessKeyID
}
