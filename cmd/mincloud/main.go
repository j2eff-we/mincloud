package main

import (
	"cmp"
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/service/ec2"
	"github.com/j2eff-we/mincloud/internal/service/iam"
	"github.com/j2eff-we/mincloud/internal/service/sts"
)

func main() {
	stsAddr := flag.String("addr", cmp.Or(os.Getenv("MINCLOUD_STS_ADDR"), os.Getenv("MINCLOUD_ADDR"), ":9900"),
		"STS listen address (env: MINCLOUD_STS_ADDR, legacy: MINCLOUD_ADDR)")
	iamAddr := flag.String("iam-addr", cmp.Or(os.Getenv("MINCLOUD_IAM_ADDR"), ":9910"),
		"IAM listen address (env: MINCLOUD_IAM_ADDR)")
	ec2Addr := flag.String("ec2-addr", cmp.Or(os.Getenv("MINCLOUD_EC2_ADDR"), ":9920"),
		"EC2 listen address (env: MINCLOUD_EC2_ADDR)")
	verbose := flag.Bool("v", false, "log full request dumps")
	flag.Parse()

	store := credstore.New()
	accessKeyID := loadDevCredential(store)

	stsLn, err := net.Listen("tcp", *stsAddr)
	if err != nil {
		log.Fatal(err)
	}
	iamLn, err := net.Listen("tcp", *iamAddr)
	if err != nil {
		log.Fatal(err)
	}
	ec2Ln, err := net.Listen("tcp", *ec2Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mincloud sts listening on %s, iam listening on %s, ec2 listening on %s (access key %s)",
		stsLn.Addr(), iamLn.Addr(), ec2Ln.Addr(), accessKeyID)

	errc := make(chan error, 3)
	go func() { errc <- http.Serve(stsLn, sts.Handler(store, *verbose)) }()
	go func() { errc <- http.Serve(iamLn, iam.Handler(store, *verbose)) }()
	go func() { errc <- http.Serve(ec2Ln, ec2.Handler(store, *verbose)) }()
	log.Fatal(<-errc)
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
