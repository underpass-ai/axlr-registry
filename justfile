# Day-to-day commands; CI runs the same ones.
export CARGO_BUILD_JOBS := "2"

default: check

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

coverage:
    cargo llvm-cov --workspace --ignore-filename-regex 'crates/lambdas/.*/src/main\.rs' --fail-under-lines 80

lambdas:
    cargo lambda build --release --arm64 --workspace

deploy stage="staging":
    sam build --template-file infra/template.yaml
    sam deploy --stack-name axlr-registry-{{stage}} --guided
