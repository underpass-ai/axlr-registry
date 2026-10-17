package domain

import (
	"errors"
	"time"
)

// Status of a tool version.
type Status string

const (
	Submitted Status = "submitted"
	Scanned   Status = "scanned"
	Approved  Status = "approved"
	Rejected  Status = "rejected"
	Yanked    Status = "yanked"
)

// TestReport is what the sandbox adapter records after running tests.json
// with the axlr_run_tool contract.
type TestReport struct {
	Cases  int       `json:"cases"`
	Passed int       `json:"passed"`
	Failed []string  `json:"failed,omitempty"`
	RanAt  time.Time `json:"ran_at"`
}

// AllPassed says whether the tests allow approval.
func (t TestReport) AllPassed() bool { return t.Cases > 0 && t.Passed == t.Cases && len(t.Failed) == 0 }

// ReviewerID names a human reviewer; it is never a publisher id of the
// version's own publisher.
type ReviewerID string

// Review is a reviewer's decision.
type Review struct {
	Reviewer ReviewerID `json:"reviewer"`
	Decision Status     `json:"decision"` // Approved or Rejected
	Reason   string     `json:"reason,omitempty"`
	At       time.Time  `json:"at"`
}

// Yank records a withdrawal.
type Yank struct {
	By     string    `json:"by"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// ToolVersion is one immutable submission of a tool.
type ToolVersion struct {
	Name           ToolName
	Version        Version
	Publisher      PublisherID
	Manifest       Manifest
	ManifestDigest Digest
	FileDigests    map[string]Digest
	BundleDigest   Digest
	Signature      PublisherSignature
	SubmittedAt    time.Time
	Status         Status
	Scan           *ScanReport
	Tests          *TestReport
	Review         *Review
	Yank           *Yank
	RejectedReason string
}

// Submit creates a version from a validated bundle signed by the publisher.
// The caller has authorised the publisher's token for the name.
func Submit(v ValidBundle, p *Publisher, signature PublisherSignature, now time.Time) (*ToolVersion, error) {
	if !p.Owns(v.Name) {
		return nil, errors.New("publisher " + string(p.ID) + " does not own " + string(v.Name))
	}
	key, ok := p.ActiveKey(signature.KeyID, now)
	if !ok {
		return nil, errors.New("signature key " + string(signature.KeyID) + " is unknown or revoked")
	}
	if err := signature.Verify(key, v.BundleDigest); err != nil {
		return nil, err
	}
	return &ToolVersion{Name: v.Name, Version: v.Version, Publisher: p.ID, Manifest: v.Parsed, ManifestDigest: v.ManifestDigest,
		FileDigests: v.FileDigests, BundleDigest: v.BundleDigest, Signature: signature, SubmittedAt: now, Status: Submitted}, nil
}

// RecordScan attaches the policy scan; a blocking scan rejects the version.
func (t *ToolVersion) RecordScan(report ScanReport, now time.Time) error {
	if t.Status != Submitted {
		return errors.New("scan is recorded once, on a submitted version")
	}
	t.Scan = &report
	if report.Blocking() {
		t.Status = Rejected
		t.RejectedReason = "policy scan: " + report.Findings[firstBlocking(report)].Rule + " in " + report.Findings[firstBlocking(report)].File
		return nil
	}
	t.Status = Scanned
	return nil
}

func firstBlocking(r ScanReport) int {
	for i, f := range r.Findings {
		if f.Severity == Block {
			return i
		}
	}
	return 0
}

// RecordTests attaches the sandbox test report.
func (t *ToolVersion) RecordTests(report TestReport) error {
	if t.Status != Scanned {
		return errors.New("tests are recorded on a scanned version")
	}
	t.Tests = &report
	return nil
}

// Approve publishes the version: a clean scan, passing tests and a reviewer
// who is not the publisher.
func (t *ToolVersion) Approve(reviewer ReviewerID, reason string, now time.Time) error {
	if t.Status != Scanned {
		return errors.New("only a scanned version can be approved")
	}
	if t.Scan == nil || t.Scan.Blocking() {
		return errors.New("the scan blocks the version")
	}
	if t.Tests == nil || !t.Tests.AllPassed() {
		return errors.New("the tests have not passed")
	}
	if string(reviewer) == "" || string(reviewer) == string(t.Publisher) {
		return errors.New("the reviewer is not the publisher")
	}
	t.Review = &Review{Reviewer: reviewer, Decision: Approved, Reason: reason, At: now}
	t.Status = Approved
	return nil
}

// Reject refuses a scanned version with a reason.
func (t *ToolVersion) Reject(reviewer ReviewerID, reason string, now time.Time) error {
	if t.Status != Scanned {
		return errors.New("only a scanned version can be rejected")
	}
	if reason == "" {
		return errors.New("a rejection carries a reason")
	}
	t.Review = &Review{Reviewer: reviewer, Decision: Rejected, Reason: reason, At: now}
	t.Status = Rejected
	t.RejectedReason = reason
	return nil
}

// Withdraw yanks an approved version; the record stays and the next index
// carries the revocation.
func (t *ToolVersion) Withdraw(by, reason string, now time.Time) error {
	if t.Status != Approved {
		return errors.New("only an approved version can be yanked")
	}
	if reason == "" {
		return errors.New("a yank carries a reason")
	}
	t.Yank = &Yank{By: by, Reason: reason, At: now}
	t.Status = Yanked
	return nil
}

// Tool is a name and its versions, owned by one publisher for life.
type Tool struct {
	Name     ToolName
	Owner    PublisherID
	Versions []*ToolVersion
}

// Add accepts a new version: the owner's, and greater than every existing
// version whatever its status, so a version string is never reused.
func (t *Tool) Add(v *ToolVersion) error {
	if v.Name != t.Name {
		return errors.New("version is of another tool")
	}
	if v.Publisher != t.Owner {
		return errors.New(string(t.Name) + " is owned by " + string(t.Owner))
	}
	for _, existing := range t.Versions {
		if !existing.Version.Less(v.Version) {
			return errors.New("version " + string(v.Version) + " is not greater than " + string(existing.Version))
		}
	}
	t.Versions = append(t.Versions, v)
	return nil
}

// Latest is the newest approved version, or nil.
func (t *Tool) Latest() *ToolVersion {
	var latest *ToolVersion
	for _, v := range t.Versions {
		if v.Status == Approved && (latest == nil || latest.Version.Less(v.Version)) {
			latest = v
		}
	}
	return latest
}
