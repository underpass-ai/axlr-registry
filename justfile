# Day-to-day commands; CI runs the same ones.
export CARGO_BUILD_JOBS := "2"

default: check

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

# Offline: the SDK-calling adapter files are excluded; `just coverage-all` counts them.
coverage:
    cargo llvm-cov --workspace --all-features --ignore-filename-regex 'crates/lambdas/.*/src/main\.rs|crates/adapters/(dynamodb|s3|lambda)/src/(dynamo_|s3_|lambda_|table|bucket).*\.rs|crates/local/src/main\.rs' --fail-under-lines 80

# Start DynamoDB Local and MinIO in Docker for the integration tests.
services:
    docker run -d --name registry-dynamodb -p 8000:8000 amazon/dynamodb-local:latest
    docker run -d --name registry-minio -p 9000:9000 -e MINIO_ROOT_USER=test -e MINIO_ROOT_PASSWORD=testtest bitnamilegacy/minio:latest

services-stop:
    docker rm -f registry-dynamodb registry-minio

# Every test, the integration ones included (needs `just services`).
integration:
    DYNAMODB_ENDPOINT=http://localhost:8000 S3_ENDPOINT=http://localhost:9000 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=testtest AWS_REGION=eu-west-1 cargo test --workspace --all-features -- --include-ignored

# The CI gate: every test under llvm-cov, nothing excluded but the Lambda and harness entry points.
coverage-all:
    DYNAMODB_ENDPOINT=http://localhost:8000 S3_ENDPOINT=http://localhost:9000 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=testtest AWS_REGION=eu-west-1 cargo llvm-cov --workspace --all-features --ignore-filename-regex 'crates/lambdas/.*/src/main\.rs|crates/local/src/main\.rs' --fail-under-lines 80 -- --include-ignored

# The registry from memory on the loopback, for end-to-end runs without AWS (docs/operations.md).
local *args:
    cargo run -p registry-local -- {{args}}

lambdas:
    cargo lambda build --release --arm64 --workspace

# Local deploy, the same steps the release job runs: binaries, the runner image (pushed only
# when its tag is new) and sam deploy with prebuilt artifacts. Needs cargo-lambda, docker, sam.
deploy stage="staging" region="eu-south-2" account="203918869295":
    cargo lambda build --release --arm64 --workspace
    cp target/lambda/test-runner/bootstrap infra/test-runner/bootstrap
    aws ecr get-login-password --region {{region}} | docker login --username AWS --password-stdin {{account}}.dkr.ecr.{{region}}.amazonaws.com
    TAG=$(cat infra/test-runner/Dockerfile infra/test-runner/bootstrap | sha256sum | cut -c1-32); \
    REPO={{account}}.dkr.ecr.{{region}}.amazonaws.com/axlr-registry/test-runner; \
    aws ecr describe-images --region {{region}} --repository-name axlr-registry/test-runner --image-ids imageTag=$TAG >/dev/null 2>&1 \
      || (docker build --platform linux/arm64 -t $REPO:$TAG infra/test-runner && docker push $REPO:$TAG); \
    DIGEST=$(aws ecr describe-images --region {{region}} --repository-name axlr-registry/test-runner --image-ids imageTag=$TAG --query 'imageDetails[0].imageDigest' --output text); \
    sam deploy --template-file infra/template.yaml --stack-name axlr-registry-{{stage}} --region {{region}} --resolve-s3 --image-repositories TestRunnerFunction=$REPO \
      --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset --guided \
      --parameter-overrides Stage={{stage}} TestRunnerImageUri=$REPO@$DIGEST
