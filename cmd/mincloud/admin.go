package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/j2eff-we/mincloud/internal/credgen"
	"github.com/j2eff-we/mincloud/internal/credstore"
)

// runAdmin handles the out-of-band admin plane: operations that create the very
// things the SigV4 API needs before it can authenticate anyone. It is
// deliberately NOT part of the signed service API — you cannot sign a request
// to mint the first credential, so account creation lives here instead. The
// trust boundary is "who may run this binary against the store," not a
// signature.
func runAdmin(args []string) {
	fs := flag.NewFlagSet("mincloud admin", flag.ExitOnError)
	endpoint := fs.String("dynamodb-endpoint", os.Getenv("MINCLOUD_DYNAMODB_ENDPOINT"),
		"DynamoDB endpoint holding the accounts (env: MINCLOUD_DYNAMODB_ENDPOINT)")
	fs.Parse(args)

	switch fs.Arg(0) {
	case "create-account":
		createAccount(*endpoint)
	default:
		log.Fatal("usage: mincloud admin create-account [--dynamodb-endpoint URL]")
	}
}

// createAccount mints a new account with its own root user and root access key,
// the way signing up for AWS yields a root account. The store must be
// persistent (DynamoDB): an in-memory account would vanish the moment this
// command exits.
func createAccount(endpoint string) {
	if endpoint == "" {
		log.Fatal("create-account needs a persistent store: set MINCLOUD_DYNAMODB_ENDPOINT")
	}
	store, err := openStore(endpoint)
	if err != nil {
		log.Fatalf("open credstore: %v", err)
	}

	accountID := credgen.AccountID()
	accessKeyID := credgen.AccessKeyID()
	secret, err := credgen.SecretAccessKey()
	if err != nil {
		log.Fatalf("generate secret: %v", err)
	}
	store.Put(accessKeyID, credstore.Credential{
		SecretAccessKey: secret,
		Identity: credstore.Identity{
			Account: accountID,
			UserID:  accountID, // the root user's UserId is the account id
			ARN:     "arn:aws:iam::" + accountID + ":root",
		},
	})

	fmt.Println("account created — hand the root credential to the account owner:")
	fmt.Printf("  Account:          %s\n", accountID)
	fmt.Printf("  Root AccessKeyId: %s\n", accessKeyID)
	fmt.Printf("  Root SecretKey:   %s\n", secret)
}
