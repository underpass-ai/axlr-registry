# Operations: the private CA, client certificates, the truststore and the CloudFront certificate

Status: written 17 Oct 2026, before any deployment. These are the steps the operator runs once per environment, before the first `sam deploy`, and again when something rotates. The architecture that needs them is in [`architecture.md`](architecture.md) (bootstrap order, security). The local parts are scripted in [`scripts/ca.sh`](../scripts/ca.sh); the AWS parts are plain `aws` commands, listed here and never run by the script. Nothing below has been run against an AWS account yet.

Placeholders: `DOMAIN` is the registered domain, `REGION` the deployment region, `TRUSTSTORE_BUCKET` the name of the tiny versioned bucket, `STACK` the stack name (`axlr-registry-staging` or `axlr-registry-production`).

## What the CA is for

`admin.DOMAIN` is an API Gateway HTTP API custom domain with mutual TLS. API Gateway accepts a request only when the client presents a certificate chained to one in the truststore object pinned by the stack (`TruststoreBucket` and `TruststoreVersion` parameters), then passes the certificate to `admin-api` in `requestContext.authentication.clientCert`. The Lambda computes the SHA-256 of the certificate and looks it up in the principals table to learn who is calling and whether they are a `reviewer` or an `operator`. So:

- the CA's private key never enters AWS: the truststore holds only its certificate;
- a reviewer or operator is a client certificate issued by that CA plus a principals row keyed by the certificate's SHA-256;
- revoking a person is deleting their row (immediate) or rotating the CA (everyone).

The CA directory (`ca.key`, the clients' keys) lives on the operator's machine, encrypted at rest, with a backup; the script refuses to overwrite an existing CA.

## 1. Create the CA (offline)

```bash
scripts/ca.sh init ~/axlr-registry-ca "AXLR registry CA"
```

Which runs, in that directory:

```bash
# P-256 key in PKCS#8 (openssl's default output; what rustls and reqwest read)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
chmod 600 ca.key
# A ten-year, self-signed CA certificate that can only sign end-entity certificates
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=AXLR registry CA" -out ca.pem \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
mkdir -p truststore && cp ca.pem truststore/ca.pem
```

`ca.pem` is public; `ca.key` is the one secret of the admin plane.

## 2. Issue a reviewer or operator certificate (offline)

```bash
scripts/ca.sh issue ~/axlr-registry-ca ana 365
```

`ana` is the principal id the audit log will show. The script writes `clients/ana/key.pem`, `clients/ana/cert.pem` and `clients/ana/identity.pem` (the certificate followed by the key, the file the CLI's `--cert` takes), and prints the SHA-256. The commands:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem
openssl req -new -key key.pem -subj "/CN=ana" -out request.csr
openssl x509 -req -in request.csr -CA ../../ca.pem -CAkey ../../ca.key -CAserial ../../serial \
    -sha256 -days 365 -out cert.pem \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
cat cert.pem key.pem > identity.pem && chmod 600 identity.pem
```

Hand `identity.pem` to the person over a channel you trust (it contains their private key; better still, have them generate `key.pem` and send you the CSR). One certificate per person; a shared certificate makes the audit log worthless.

## 3. The SHA-256 for the principals table

```bash
scripts/ca.sh fingerprint ~/axlr-registry-ca/clients/ana/cert.pem
# equivalent to
openssl x509 -in cert.pem -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
```

The definition, so `admin-api` computes the same bytes: **SHA-256 over the DER encoding of the certificate, as lowercase hex without colons** (what `openssl x509 -noout -fingerprint -sha256` prints after lower-casing and removing the colons). API Gateway hands the Lambda the certificate as PEM in `clientCertPem`; the Lambda decodes the PEM body to DER and hashes that.

The principal row is written outside the API, because the first operator exists before anyone can call it. The item follows the data model in `architecture.md` (`PK = PRINCIPAL#<sha256>`, `SK = META`); the attribute names are those of the DynamoDB adapter (`crates/adapters/dynamodb`), check them there before writing:

```bash
aws dynamodb put-item --region REGION --table-name "$(aws cloudformation describe-stacks --stack-name STACK \
      --query "Stacks[0].Outputs[?OutputKey=='TableName'].OutputValue" --output text)" \
    --item '{"PK": {"S": "PRINCIPAL#e645f84f…d564"}, "SK": {"S": "META"}, "id": {"S": "ana"}, "role": {"S": "reviewer"}}' \
    --condition-expression 'attribute_not_exists(PK)'
```

Removing the row removes the person's access at the next request; the certificate itself is not revoked (there is no CRL or OCSP in API Gateway mTLS), which is why a lost key with no row is harmless and a lost CA key is a rotation.

## 4. Build the truststore and create its bucket

The truststore is the concatenation of the CA certificates API Gateway should accept (one, or two during a rotation):

```bash
scripts/ca.sh truststore ~/axlr-registry-ca       # writes truststore/ca.pem
```

The bucket is created before the stack, because the custom domain pins an object version in it. Versioned, private, in the deployment region:

```bash
aws s3api create-bucket --bucket TRUSTSTORE_BUCKET --region REGION \
    --create-bucket-configuration LocationConstraint=REGION     # omit this line in us-east-1
aws s3api put-public-access-block --bucket TRUSTSTORE_BUCKET --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-versioning --bucket TRUSTSTORE_BUCKET --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket TRUSTSTORE_BUCKET --server-side-encryption-configuration \
    '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
```

Upload the truststore and read the object version id, which is the stack's `TruststoreVersion` parameter:

```bash
aws s3api put-object --bucket TRUSTSTORE_BUCKET --key truststore/ca.pem --body ~/axlr-registry-ca/truststore/ca.pem \
    --query VersionId --output text
# later, to read it again
aws s3api list-object-versions --bucket TRUSTSTORE_BUCKET --prefix truststore/ca.pem \
    --query "Versions[?IsLatest].VersionId" --output text
```

Deploy with `TruststoreBucket=TRUSTSTORE_BUCKET TruststoreVersion=<that id>`. API Gateway reads the object once, when the domain is created or the version parameter changes; uploading a new object without changing the parameter changes nothing.

## 5. The CloudFront certificate in us-east-1

CloudFront only serves certificates held in ACM in `us-east-1`, whatever the stack's region. Request it with DNS validation and publish the validation record in the hosted zone:

```bash
ARN=$(aws acm request-certificate --region us-east-1 --domain-name registry.DOMAIN \
    --validation-method DNS --query CertificateArn --output text)
aws acm describe-certificate --region us-east-1 --certificate-arn "$ARN" \
    --query "Certificate.DomainValidationOptions[0].ResourceRecord"
# returns {Name, Type: CNAME, Value}; create that record
aws route53 change-resource-record-sets --hosted-zone-id HOSTED_ZONE_ID --change-batch '{
  "Changes": [{"Action": "UPSERT", "ResourceRecordSet": {
    "Name": "<Name>", "Type": "CNAME", "TTL": 300, "ResourceRecords": [{"Value": "<Value>"}]}}]}'
aws acm wait certificate-validated --region us-east-1 --certificate-arn "$ARN"
```

`$ARN` is the stack's `CloudFrontCertificateArn` parameter. ACM renews it as long as the CNAME stays in the zone. The `api.` and `admin.` certificates are the stack's own, in the deployment region.

## 6. Rotate the CA

Rotate on a schedule (before the ten years) or at once if `ca.key` may have leaked. The rotation keeps the admin API reachable throughout, because the truststore holds both CAs until every client has a new certificate:

1. `scripts/ca.sh rotate ~/axlr-registry-ca` creates `ca-next.key` and `ca-next.pem` and rebuilds `truststore/ca.pem` with the old and the new certificate.
2. Upload the truststore (step 4) and redeploy with the new `TruststoreVersion`. Old certificates still work.
3. Issue every reviewer and operator a new certificate: `scripts/ca.sh issue` signs with `ca-next` while a rotation is in progress. Write each new SHA-256 to the principals table and delete the old rows as people switch.
4. `scripts/ca.sh retire ~/axlr-registry-ca` moves the old CA to `retired/` and rebuilds the truststore with the new one only. Upload it, redeploy with the new version id. Certificates from the old CA are refused from then on.
5. Delete `retired/ca-*.key` once nothing depends on it; keep `retired/ca-*.pem` for the record.

In a compromise, skip the overlap: go straight to step 4 with the new CA, accept the outage until the new certificates are handed out, and delete every principal row that was keyed by an old certificate.

## Follow-ups

- A `register-principal` command over the admin API would replace the `put-item` in step 3 once the first operator exists; today `PrincipalRepository` is read-only.
- API Gateway's mTLS checks the chain only; expired client certificates are refused but there is no revocation list. The principals table is the revocation list.
