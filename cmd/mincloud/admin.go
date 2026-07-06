package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/j2eff-we/mincloud/internal/credgen"
)

// runAdmin handles the out-of-band admin plane — the few operations that live
// outside the signed API. Account creation used to live here, but now that the
// genesis management root is seeded at startup, member accounts are created via
// the signed control service (mincloud:CreateAccount). What remains here is
// whoami, a purely offline helper.
func runAdmin(args []string) {
	fs := flag.NewFlagSet("mincloud admin", flag.ExitOnError)
	fs.Parse(args)

	switch fs.Arg(0) {
	case "whoami":
		whoami(fs.Arg(1))
	default:
		log.Fatal("usage: mincloud admin whoami <accessKeyId>")
	}
}

// whoami recovers the account ID encoded in an access key ID, offline — no
// store lookup, no signature. It shows that a mincloud key carries its account
// the same way a real AWS key does.
func whoami(accessKeyID string) {
	if accessKeyID == "" {
		log.Fatal("usage: mincloud admin whoami <accessKeyId>")
	}
	account, ok := credgen.AccountFromAccessKeyID(accessKeyID)
	if !ok {
		log.Fatalf("%s: not an account-encoded access key id", accessKeyID)
	}
	fmt.Printf("%s -> account %s\n", accessKeyID, account)
}
