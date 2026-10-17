package domain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxFileBytes bounds one bundle file.
	MaxFileBytes = 256 * 1024
	// MaxFiles is the forged-tool limit.
	MaxFiles = 8
	// bundleSignaturePrefix separates bundle signatures from any other use
	// of a publisher key.
	bundleSignaturePrefix = "axlr-tool-bundle-v1\n"
)

var (
	toolNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,47}$`)
	fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	programPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
)

// ToolName is a forged-tool name: the console's own rule.
type ToolName string

// NewToolName validates a tool name.
func NewToolName(raw string) (ToolName, error) {
	if !toolNamePattern.MatchString(raw) {
		return "", errors.New("invalid tool name: [a-z][a-z0-9_]{1,47}")
	}
	return ToolName(raw), nil
}

// Manifest is manifest.json: a forged tool plus its catalog block.
type Manifest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	Program     string          `json:"program"`
	Args        []string        `json:"args"`
	Files       []string        `json:"files"`
	Catalog     CatalogBlock    `json:"catalog"`
}

// CatalogBlock is the catalog metadata of a manifest.
type CatalogBlock struct {
	Version  string          `json:"version"`
	Category string          `json:"category"`
	Tags     []string        `json:"tags"`
	License  string          `json:"license"`
	Requires Requires        `json:"requires"`
	Network  bool            `json:"network"`
	Example  json.RawMessage `json:"example,omitempty"`
	Source   string          `json:"source,omitempty"`
}

// Requires is what a tool needs beside its program.
type Requires struct {
	ProgramMinVersion string   `json:"program_min_version,omitempty"`
	Packages          []string `json:"packages"`
}

// Bundle is what a publisher uploads: the manifest and the tool's files.
type Bundle struct {
	Manifest []byte
	Files    map[string][]byte
}

// ValidBundle is a bundle that passed validation, with its parsed manifest
// and digests.
type ValidBundle struct {
	Bundle
	Parsed         Manifest
	Name           ToolName
	Version        Version
	ManifestDigest Digest
	FileDigests    map[string]Digest
	BundleDigest   Digest
}

// Validate checks a bundle against the forged-tool and registry rules and
// computes its digests.
func (b Bundle) Validate() (ValidBundle, error) {
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(b.Manifest))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return ValidBundle{}, errors.New("manifest.json: " + err.Error())
	}
	name, err := NewToolName(m.Name)
	if err != nil {
		return ValidBundle{}, err
	}
	version, err := NewVersion(m.Catalog.Version)
	if err != nil {
		return ValidBundle{}, err
	}
	if strings.TrimSpace(m.Description) == "" || len(m.Description) > 1024 {
		return ValidBundle{}, errors.New("description is empty or over 1024 characters")
	}
	if !programPattern.MatchString(m.Program) || strings.ContainsAny(m.Program, "/\\") {
		return ValidBundle{}, errors.New("program must be a bare command on PATH")
	}
	if len(m.InputSchema) == 0 || !json.Valid(m.InputSchema) {
		return ValidBundle{}, errors.New("input_schema must be a JSON Schema object")
	}
	if len(m.Files) == 0 || len(m.Files) > MaxFiles || len(b.Files) != len(m.Files) {
		return ValidBundle{}, errors.New("a tool has one to eight files, each uploaded with the manifest")
	}
	if m.Catalog.Category == "" || m.Catalog.License == "" {
		return ValidBundle{}, errors.New("catalog.category and catalog.license are required")
	}
	digests := map[string]Digest{}
	for _, f := range m.Files {
		if !fileNamePattern.MatchString(f) || f == "." || f == ".." {
			return ValidBundle{}, errors.New("file name " + f + " must be a bare name without a path")
		}
		content, ok := b.Files[f]
		if !ok {
			return ValidBundle{}, errors.New("file " + f + " named in the manifest was not uploaded")
		}
		if len(content) == 0 || len(content) > MaxFileBytes {
			return ValidBundle{}, errors.New("file " + f + " is empty or over 256 KiB")
		}
		if bytes.IndexByte(content, 0) >= 0 {
			return ValidBundle{}, errors.New("file " + f + " is binary; tools are text")
		}
		digests[f] = DigestOf(content)
	}
	if len(digests) != len(m.Files) {
		return ValidBundle{}, errors.New("files lists a name twice")
	}
	named := false
	for _, a := range m.Args {
		if _, ok := digests[a]; ok {
			named = true
		}
	}
	if !named {
		return ValidBundle{}, errors.New("args must name one of the tool's files")
	}
	v := ValidBundle{Bundle: b, Parsed: m, Name: name, Version: version, ManifestDigest: DigestOf(b.Manifest), FileDigests: digests}
	v.BundleDigest = DigestOf(v.canonicalListing())
	return v, nil
}

// canonicalListing is what the bundle digest covers: the manifest digest and
// every file's name and digest, sorted.
func (v ValidBundle) canonicalListing() []byte {
	var sb strings.Builder
	sb.WriteString("manifest " + string(v.ManifestDigest) + "\n")
	names := make([]string, 0, len(v.FileDigests))
	for n := range v.FileDigests {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sb.WriteString("file " + n + " " + string(v.FileDigests[n]) + "\n")
	}
	return []byte(sb.String())
}

// signedMessage is the bytes a publisher signs for a bundle digest.
func signedMessage(digest Digest) []byte {
	return []byte(bundleSignaturePrefix + string(digest))
}

// PublisherSignature is a publisher's Ed25519 signature over a bundle digest.
type PublisherSignature struct {
	KeyID     KeyID
	Signature []byte
}

// SignBundle signs a bundle digest with a publisher's private key (for the
// publisher's CLI and the tests).
func SignBundle(private ed25519.PrivateKey, digest Digest) PublisherSignature {
	public := private.Public().(ed25519.PublicKey)
	return PublisherSignature{KeyID: KeyIDOf(public), Signature: ed25519.Sign(private, signedMessage(digest))}
}

// Verify checks the signature over digest with key.
func (s PublisherSignature) Verify(key PublisherKey, digest Digest) error {
	if s.KeyID != key.ID {
		return errors.New("signature key id does not match the key")
	}
	if len(s.Signature) != ed25519.SignatureSize || !ed25519.Verify(key.Key, signedMessage(digest), s.Signature) {
		return errors.New("bundle signature does not verify")
	}
	return nil
}
