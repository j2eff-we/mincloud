package main

import (
	"cmp"
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/router"
	"github.com/j2eff-we/mincloud/internal/service/ec2"
	"github.com/j2eff-we/mincloud/internal/service/iam"
	"github.com/j2eff-we/mincloud/internal/service/sts"
)

func main() {
	addr := flag.String("addr", cmp.Or(os.Getenv("MINCLOUD_ADDR"), ":9900"),
		"listen address for all services (env: MINCLOUD_ADDR)")
	verbose := flag.Bool("v", false, "log full request dumps")
	flag.Parse()

	store := credstore.New()
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
