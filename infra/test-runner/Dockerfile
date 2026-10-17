# The test runner: the Rust binary plus the interpreters a tool may name.
# Built by `sam build` from the repository root (DockerContext ../).
FROM public.ecr.aws/lambda/provided:al2023 AS runtime
RUN dnf install -y python3 bash nodejs && dnf clean all

# The bootstrap binary is produced by `cargo lambda build --release --arm64 -p test-runner`
# in CI and copied in; locally, run that first.
COPY target/lambda/test-runner/bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap
CMD ["bootstrap"]
