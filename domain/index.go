package domain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IndexEntry is one tool version in index.json. The fields through
// updated_at are the ones the AXLR console's catalog client reads (it
// decodes leniently); the rest add provenance the client may ignore today.
type IndexEntry struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	Category       string            `json:"category"`
	Tags           []string          `json:"tags"`
	Summary        string            `json:"summary"`
	Program        string            `json:"program"`
	Requires       Requires          `json:"requires"`
	Network        bool              `json:"network"`
	License        string            `json:"license"`
	Manifest       string            `json:"manifest"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	Files          map[string]string `json:"files"`
	UpdatedAt      string            `json:"updated_at"`
	Publisher      string            `json:"publisher"`
	PublisherKeyID string            `json:"publisher_key_id"`
	BundleSHA256   string            `json:"bundle_sha256"`
	Signature      string            `json:"signature"`
	ReviewedAt     string            `json:"reviewed_at"`
	Reviewer       string            `json:"reviewer"`
	Warnings       []string          `json:"warnings,omitempty"`
}

// Revocation is a yanked version the console must mark broken.
type Revocation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Reason  string `json:"reason"`
	At      string `json:"at"`
}

// RevokedKey is a publisher key the console must not trust any more.
type RevokedKey struct {
	Publisher string `json:"publisher"`
	KeyID     string `json:"key_id"`
	At        string `json:"at"`
}

// Index is index.json before signing.
type Index struct {
	SchemaVersion int          `json:"schema_version"`
	Catalog       string       `json:"catalog"`
	GeneratedAt   string       `json:"generated_at"`
	Tools         []IndexEntry `json:"tools"`
	Revocations   []Revocation `json:"revocations"`
	RevokedKeys   []RevokedKey `json:"revoked_keys"`
}

// BuildIndex lists every approved, non-yanked version, the yanked ones as
// revocations and the publishers' revoked keys. Tools and versions come out
// sorted so the canonical bytes depend only on the state.
func BuildIndex(catalog string, tools []*Tool, publishers []*Publisher, now time.Time) Index {
	index := Index{SchemaVersion: 1, Catalog: catalog, GeneratedAt: now.UTC().Format(time.RFC3339), Tools: []IndexEntry{}, Revocations: []Revocation{}, RevokedKeys: []RevokedKey{}}
	sorted := append([]*Tool(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, t := range sorted {
		versions := append([]*ToolVersion(nil), t.Versions...)
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version.Less(versions[j].Version) })
		for _, v := range versions {
			switch v.Status {
			case Approved:
				index.Tools = append(index.Tools, entryOf(v))
			case Yanked:
				index.Revocations = append(index.Revocations, Revocation{Name: string(v.Name), Version: string(v.Version), Reason: v.Yank.Reason, At: v.Yank.At.UTC().Format(time.RFC3339)})
			}
		}
	}
	for _, p := range publishers {
		for _, k := range p.Keys {
			if !k.RevokedAt.IsZero() {
				index.RevokedKeys = append(index.RevokedKeys, RevokedKey{Publisher: string(p.ID), KeyID: string(k.ID), At: k.RevokedAt.UTC().Format(time.RFC3339)})
			}
		}
	}
	sort.Slice(index.RevokedKeys, func(i, j int) bool {
		return index.RevokedKeys[i].Publisher+index.RevokedKeys[i].KeyID < index.RevokedKeys[j].Publisher+index.RevokedKeys[j].KeyID
	})
	return index
}

func entryOf(v *ToolVersion) IndexEntry {
	files := map[string]string{}
	for n, d := range v.FileDigests {
		files[n] = string(d)
	}
	tags := v.Manifest.Catalog.Tags
	if tags == nil {
		tags = []string{}
	}
	requires := v.Manifest.Catalog.Requires
	if requires.Packages == nil {
		requires.Packages = []string{}
	}
	var warnings []string
	if v.Scan != nil {
		for _, f := range v.Scan.Findings {
			if f.Severity == Warn {
				warnings = append(warnings, f.Rule+" in "+f.File+":"+itoa(f.Line))
			}
		}
	}
	return IndexEntry{
		Name: string(v.Name), Version: string(v.Version), Category: v.Manifest.Catalog.Category, Tags: tags,
		Summary: summaryOf(v.Manifest.Description), Program: v.Manifest.Program, Requires: requires,
		Network: v.Manifest.Catalog.Network, License: v.Manifest.Catalog.License,
		Manifest: "tools/" + string(v.Name) + "/" + string(v.Version) + "/manifest.json", ManifestSHA256: string(v.ManifestDigest),
		Files: files, UpdatedAt: v.Review.At.UTC().Format("2006-01-02"),
		Publisher: string(v.Publisher), PublisherKeyID: string(v.Signature.KeyID), BundleSHA256: string(v.BundleDigest),
		Signature:  base64.StdEncoding.EncodeToString(v.Signature.Signature),
		ReviewedAt: v.Review.At.UTC().Format(time.RFC3339), Reviewer: string(v.Review.Reviewer), Warnings: warnings,
	}
}

// FilePath is where the registry serves a version's file, beside its
// manifest.
func FilePath(name ToolName, version Version, file string) string {
	return "tools/" + string(name) + "/" + string(version) + "/" + file
}

func summaryOf(description string) string {
	first, _, _ := strings.Cut(description, ". ")
	return strings.TrimSuffix(first, ".") + "."
}

func itoa(n int) string { return strconv.Itoa(n) }

// Canonical is the bytes the registry key signs and index.json carries:
// two-space indented JSON with sorted map keys and a final newline, so the
// same state always gives the same bytes.
func (i Index) Canonical() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
