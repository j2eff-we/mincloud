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
	"github.com/j2eff-we/mincloud/internal/router"
	"github.com/j2eff-we/mincloud/internal/service/ec2"
	"github.com/j2eff-we/mincloud/internal/service/iam"
	"github.com/j2eff-we/mincloud/internal/service/sts"
)

func main() {
	addr := flag.String("addr", cmp.Or(os.Getenv("MINCLOUD_ADDR"), ":9900"),
		"listen address for all services (env: MINCLOUD_ADDR)")
	dynamoEndpoint := flag.String("dynamodb-endpoint", os.Getenv("MINCLOUD_DYNAMODB_ENDPOINT"),
		"DynamoDB endpoint to persist credentials in; empty keeps them in memory (env: MINCLOUD_DYNAMODB_ENDPOINT)")
	verbose := flag.Bool("v", false, "log full request dumps")
	flag.Parse()

	store, err := openStore(*dynamoEndpoint)
	if err != nil {
		log.Fatalf("open credstore: %v", err)
	}
	accessKeyID := loadDevCredential(store)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mincloud listening on %s — services: sts, iam, ec2 (access key %s)",
		ln.Addr(), accessKeyID)

	log.Fatal(http.Serve(ln, router.New(map[string]http.Handler{
		"sts": sts.Handler(store, *verbose),
		"iam": iam.Handler(store, *verbose),
		"ec2": ec2.Handler(store, *verbose),
	})))
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
