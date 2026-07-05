# mincloud

AWS API-compatible cloud for learning — built from scratch in Go.

The goal: let anyone practice the AWS CLI, SDKs, and Terraform against a local endpoint, without a bill. Starting with IAM/STS — the first milestone is making this work:

```sh
aws sts get-caller-identity --endpoint-url http://localhost:9900
```

## Status

Early development. Nothing works yet.

## Roadmap

- [ ] SigV4 signature verification
- [ ] Credential store (access key / secret key)
- [ ] STS `GetCallerIdentity`
- [ ] IAM users & access keys

## License

Apache-2.0
