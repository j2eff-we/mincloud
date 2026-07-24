#!/usr/bin/env bash
# End-to-end test: boots mincloud and drives it with the real aws CLI.
# Passing means genuine AWS tooling accepts our wire responses.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v aws >/dev/null || { echo "SKIP: aws CLI not installed"; exit 0; }

go build -o mincloud ./cmd/mincloud

# Ports offset from the dev defaults so e2e can run alongside a dev server.
STS_PORT=19900 IAM_PORT=19910 EC2_PORT=19920

export AWS_ACCESS_KEY_ID=MINCLOUDTESTKEY0000A
export AWS_SECRET_ACCESS_KEY=mincloud-test-secret-not-real
export AWS_DEFAULT_REGION=ap-northeast-2
export AWS_ENDPOINT_URL_STS="http://localhost:$STS_PORT"
export AWS_ENDPOINT_URL_IAM="http://localhost:$IAM_PORT"
export AWS_ENDPOINT_URL_EC2="http://localhost:$EC2_PORT"

MINCLOUD_STS_ADDR=":$STS_PORT" MINCLOUD_IAM_ADDR=":$IAM_PORT" MINCLOUD_EC2_ADDR=":$EC2_PORT" \
  ./mincloud &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -s -o /dev/null "$AWS_ENDPOINT_URL_EC2" && break
  sleep 0.1
done

pass=0
fail() { echo "FAIL: $*"; exit 1; }
ok()   { pass=$((pass + 1)); echo "ok $pass - $*"; }

# --- STS: the dev credential resolves to the expected identity ---
account=$(aws sts get-caller-identity --query Account --output text)
[ "$account" = "123456789012" ] || fail "sts account = $account"
ok "sts get-caller-identity returns account 123456789012"

# --- IAM: a freshly created access key authenticates as its user ---
read -r alice_key alice_secret < <(aws iam create-access-key --user-name alice \
  --query '[AccessKey.AccessKeyId,AccessKey.SecretAccessKey]' --output text)
[ -n "$alice_key" ] || fail "iam create-access-key returned no key"
ok "iam create-access-key issues a key for alice"

alice_arn=$(AWS_ACCESS_KEY_ID="$alice_key" AWS_SECRET_ACCESS_KEY="$alice_secret" \
  aws sts get-caller-identity --query Arn --output text)
[ "$alice_arn" = "arn:aws:iam::123456789012:user/alice" ] || fail "alice arn = $alice_arn"
ok "new key authenticates as arn:...:user/alice"

# --- EC2: run-instances returns pending, then shows up as running ---
run_state=$(aws ec2 run-instances --image-id ami-e2e-test --instance-type t3.micro \
  --query 'Instances[0].State.Name' --output text)
[ "$run_state" = "pending" ] || fail "run-instances state = $run_state"
ok "ec2 run-instances reports pending"

iid=$(aws ec2 describe-instances \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)
state=$(aws ec2 describe-instances \
  --query 'Reservations[0].Instances[0].State.Name' --output text)
[ "$iid" != "None" ] || fail "describe-instances found no instance"
[ "$state" = "running" ] || fail "describe-instances state = $state"
ok "ec2 describe-instances shows $iid as running"

# --- Auth: a bad secret must be rejected ---
if AWS_SECRET_ACCESS_KEY=wrong-secret aws sts get-caller-identity >/dev/null 2>&1; then
  fail "request with wrong secret was accepted"
fi
ok "wrong secret is rejected"

echo "PASS: $pass e2e checks"
