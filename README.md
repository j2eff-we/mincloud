# mincloud

AWS API-compatible cloud for learning — built from scratch in Go.

The goal: let anyone practice the AWS CLI, SDKs, and Terraform against a local endpoint, without a bill. Starting with IAM/STS — the first milestone is making this work:

```sh
aws sts get-caller-identity --endpoint-url http://localhost:9900
```

## Status

Early development. The first milestone works: the aws CLI can sign a request, mincloud verifies the SigV4 signature, and STS returns the caller's identity.

## Roadmap

### Milestone 1 — aws CLI gets an identity ✅

- [x] SigV4 signature verification
- [x] Credential store (access key / secret key)
- [x] STS `GetCallerIdentity`
- [x] IAM `CreateAccessKey`

### Milestone 2 — Terraform manages an IAM user

`terraform apply` / `plan` / `destroy` work against mincloud for `aws_iam_user` + `aws_iam_access_key`:

- [ ] IAM `CreateUser` / `GetUser` / `DeleteUser`
- [ ] IAM `ListAccessKeys` / `DeleteAccessKey`
- [ ] Proper IAM error responses (`NoSuchEntity` etc.) so refresh/plan behave correctly
- [ ] Example Terraform config in `examples/terraform/`

## License

Apache-2.0
