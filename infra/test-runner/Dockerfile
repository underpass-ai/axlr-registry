# The test runner: the Rust binary plus the interpreters a tool may name
# (manifest `program`: python3, bash or node). Built by `sam build` from the
# repository root (DockerContext ../). The catalog's tiers promise Python 3.10+
# and Node 22: AL2023's default python3 is 3.9 and its nodejs 18, so python3
# names python3.12 and node is nodejs22. openssl is there for bash tools.
FROM public.ecr.aws/lambda/provided:al2023 AS runtime
RUN dnf install -y python3.12 python3.12-pip nodejs22 bash openssl && dnf clean all \
    && ln -sf /usr/bin/python3.12 /usr/bin/python3

# Packages a tier-2 catalog tool may declare in `requires.packages`. Pinned, so
# a tool's tests mean the same on every build; the catalog doc lists them.
RUN python3.12 -m pip install --no-cache-dir --root-user-action=ignore sympy==1.13.3 \
    && python3.12 -c "import sympy; print(sympy.__version__)"

# The runner gives the tool under test exactly PATH and HOME. /tmp is the
# only writable path in a Lambda, and versions are unpacked under
# /tmp/axlr-registry/<name>/<version>/ (crates/lambdas/test-runner).
ENV HOME=/tmp

# --chmod: the binary arrives through a workflow artifact, which drops the executable bit.
COPY --chmod=755 bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap
CMD ["bootstrap"]
