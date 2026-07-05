#!/bin/bash
# SigV4 서명을 손으로 만들어 curl에 싣는 데모.
# aws CLI / curl --aws-sigv4 가 자동으로 해주는 일을 openssl로 재현한다.
set -euo pipefail

access_key="MINCLOUDTESTKEY0000A"
secret="mincloud-test-secret-not-real"
region="ap-northeast-2"
service="sts"
host="localhost:9900"
body='Action=GetCallerIdentity&Version=2011-06-15'

amz_date=$(date -u +%Y%m%dT%H%M%SZ) # 예: 20260705T114641Z
date_only=${amz_date:0:8}

# ── 1. 본문 해시 ─────────────────────────────────────────────
payload_hash=$(printf '%s' "$body" | shasum -a 256 | cut -d' ' -f1)

# ── 2. Canonical Request ───────────────────────────────────
canonical_request="POST
/

content-type:application/x-www-form-urlencoded; charset=utf-8
host:$host
x-amz-date:$amz_date

content-type;host;x-amz-date
$payload_hash"

# ── 3. String to Sign ──────────────────────────────────────
scope="$date_only/$region/$service/aws4_request"
string_to_sign="AWS4-HMAC-SHA256
$amz_date
$scope
$(printf '%s' "$canonical_request" | shasum -a 256 | cut -d' ' -f1)"

# ── 4. 서명 키 파생 체인 (시크릿 → kDate → kRegion → kService → kSigning) ──
hmac_hex() { # $1=hex key, $2=data → hex mac
  printf '%s' "$2" | openssl dgst -sha256 -mac hmac -macopt "hexkey:$1" | sed 's/^.* //'
}
k_date=$(printf '%s' "$date_only" | openssl dgst -sha256 -hmac "AWS4$secret" | sed 's/^.* //')
k_region=$(hmac_hex "$k_date" "$region")
k_service=$(hmac_hex "$k_region" "$service")
k_signing=$(hmac_hex "$k_service" "aws4_request")

# ── 5. 최종 서명 ────────────────────────────────────────────
signature=$(hmac_hex "$k_signing" "$string_to_sign")
echo "signature: $signature" >&2

# ── 6. 헤더에 실어 전송 ─────────────────────────────────────
curl -s "http://$host/" \
  -H "X-Amz-Date: $amz_date" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=utf-8" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=$access_key/$scope, SignedHeaders=content-type;host;x-amz-date, Signature=$signature" \
  -d "$body"
