# Day-to-day commands; CI runs the same ones.
export CARGO_BUILD_JOBS := "2"

default: check

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

# Offline: the SDK-calling adapter files are excluded; `just coverage-all` counts them.
coverage:
    cargo llvm-cov --workspace --all-features --ignore-filename-regex 'crates/lambdas/.*/src/main\.rs|crates/adapters/(dynamodb|s3|lambda)/src/(dynamo_|s3_|lambda_|table|bucket).*\.rs' --fail-under-lines 80

# Start DynamoDB Local and MinIO in Docker for the integration tests.
services:
    docker run -d --name registry-dynamodb -p 8000:8000 amazon/dynamodb-local:latest
    docker run -d --name registry-minio -p 9000:9000 -e MINIO_ROOT_USER=test -e MINIO_ROOT_PASSWORD=testtest bitnamilegacy/minio:latest

services-stop:
    docker rm -f registry-dynamodb registry-minio

# Every test, the integration ones included (needs `just services`).
integration:
    DYNAMODB_ENDPOINT=http://localhost:8000 S3_ENDPOINT=http://localhost:9000 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=testtest AWS_REGION=eu-west-1 cargo test --workspace --all-features -- --include-ignored

# The CI gate: every test under llvm-cov, nothing excluded but the Lambda entry points.
coverage-all:
    DYNAMODB_ENDPOINT=http://localhost:8000 S3_ENDPOINT=http://localhost:9000 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=testtest AWS_REGION=eu-west-1 cargo llvm-cov --workspace --all-features --ignore-filename-regex 'crates/lambdas/.*/src/main\.rs' --fail-under-lines 80 -- --include-ignored

lambdas:
    cargo lambda build --release --arm64 --workspace

deploy stage="staging":
    sam build --template-file infra/template.yaml
    sam deploy --stack-name axlr-registry-{{stage}} --guided
