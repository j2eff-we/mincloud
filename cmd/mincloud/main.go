package main

import (
	"cmp"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/j2eff-we/mincloud/internal/credstore"
	"github.com/j2eff-we/mincloud/internal/sigv4"
	"github.com/j2eff-we/mincloud/internal/sts"
)

func main() {
	addr := flag.String("addr", ":9900", "listen address")
	verbose := flag.Bool("v", false, "log full request dumps")
	flag.Parse()

	store := credstore.New()
	accessKeyID := loadDevCredential(store)

	log.Printf("mincloud listening on %s (access key %s)", *addr, accessKeyID)
	log.Fatal(http.ListenAndServe(*addr, handler(store, *verbose)))
}

// loadDevCredential registers the single development credential, configurable
// via environment variables. Defaults are well-known fake values for local use.
func loadDevCredential(store *credstore.Store) string {
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

func handler(store *credstore.Store, verbose bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if verbose {
			if dump, err := httputil.DumpRequest(r, true); err == nil {
				log.Printf("request:\n%s", dump)
			}
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			sts.WriteError(w, http.StatusBadRequest, "InvalidRequest", "unable to read request body")
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sts.WriteError(w, http.StatusForbidden, "MissingAuthenticationToken", "Request is missing Authentication Token")
			return
		}
		auth, err := sigv4.ParseAuthorization(authHeader)
		if err != nil {
			sts.WriteError(w, http.StatusForbidden, "IncompleteSignature", err.Error())
			return
		}
		cred, ok := store.Lookup(auth.AccessKeyID)
		if !ok {
			sts.WriteError(w, http.StatusForbidden, "InvalidClientTokenId", "The security token included in the request is invalid.")
			return
		}
		if err := sigv4.Verify(r, auth, body, cred.SecretAccessKey); err != nil {
			sts.WriteError(w, http.StatusForbidden, "SignatureDoesNotMatch",
				"The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method.")
			return
		}

		form, err := url.ParseQuery(string(body))
		if err != nil {
			sts.WriteError(w, http.StatusBadRequest, "InvalidRequest", "unable to parse request body")
			return
		}
		action := form.Get("Action")
		log.Printf("%s %s by %s", auth.Service, action, cred.Identity.ARN)

		switch action {
		case "GetCallerIdentity":
			sts.WriteGetCallerIdentity(w, sts.CallerIdentity{
				Account: cred.Identity.Account,
				UserID:  cred.Identity.UserID,
				ARN:     cred.Identity.ARN,
			})
		default:
			sts.WriteError(w, http.StatusBadRequest, "InvalidAction", "Could not find operation "+action)
		}
	}
}
