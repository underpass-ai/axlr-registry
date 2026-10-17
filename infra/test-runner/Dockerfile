# The test runner: the Rust binary plus the interpreters a tool may name
# (manifest `program`: python3, bash or node). Built by `sam build` from the
# repository root (DockerContext ../).
FROM public.ecr.aws/lambda/provided:al2023 AS runtime
RUN dnf install -y python3 bash nodejs && dnf clean all

# The runner gives the tool under test exactly PATH and HOME. /tmp is the
# only writable path in a Lambda, and versions are unpacked under
# /tmp/axlr-registry/<name>/<version>/ (crates/lambdas/test-runner).
ENV HOME=/tmp

COPY bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap
CMD ["bootstrap"]
