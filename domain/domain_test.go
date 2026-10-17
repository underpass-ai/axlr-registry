package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func publisher(t *testing.T) (*Publisher, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := keyPair(t)
	p, err := NewPublisher("acme", pub, []Scope{"acme_*"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.IssueToken(strings.Repeat("t", 40), []Scope{"acme_*"}, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return p, priv
}

func manifest(name, program, file string, network bool) []byte {
	m := Manifest{Name: name, Description: "Count things. Exactly.", InputSchema: json.RawMessage(`{"type":"object"}`), Program: program,
		Args: []string{file}, Files: []string{file}, Catalog: CatalogBlock{Version: "1.0.0", Category: "data", License: "MIT", Network: network, Requires: Requires{Packages: []string{}}}}
	b, _ := json.Marshal(m)
	return b
}

func bundle(t *testing.T, program, file, code string, network bool) ValidBundle {
	t.Helper()
	v, err := Bundle{Manifest: manifest("acme_count", program, file, network), Files: map[string][]byte{file: []byte(code)}}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTokenScopeExpiryAndRevocation(t *testing.T) {
	p, _ := publisher(t)
	digest := DigestToken(strings.Repeat("t", 40))
	if err := p.Authorize(digest, "acme_count", now); err != nil {
		t.Fatal(err)
	}
	if err := p.Authorize(digest, "other_count", now); err == nil {
		t.Fatal("a scope outside the token authorised")
	}
	if err := p.Authorize(digest, "acme_count", now.Add(48*time.Hour)); err == nil {
		t.Fatal("an expired token authorised")
	}
	if err := p.Authorize(DigestToken("nope"), "acme_count", now); err == nil {
		t.Fatal("an unknown token authorised")
	}
	if err := p.IssueToken(strings.Repeat("u", 40), []Scope{"other_*"}, time.Time{}); err == nil {
		t.Fatal("a token was issued outside the publisher's namespaces")
	}
	if err := p.RevokeToken(digest, now); err != nil {
		t.Fatal(err)
	}
	if err := p.Authorize(digest, "acme_count", now); err == nil {
		t.Fatal("a revoked token authorised")
	}
}

func TestSubmitVerifiesSignatureAndKeyStatus(t *testing.T) {
	p, priv := publisher(t)
	v := bundle(t, "python3", "count.py", "import json\nprint(json.dumps({'n': 1}))\n", false)
	sig := SignBundle(priv, v.BundleDigest)
	version, err := Submit(v, p, sig, now)
	if err != nil || version.Status != Submitted {
		t.Fatalf("submit: %v %v", err, version)
	}
	tampered := sig
	tampered.Signature = append([]byte(nil), sig.Signature...)
	tampered.Signature[0] ^= 1
	if _, err := Submit(v, p, tampered, now); err == nil {
		t.Fatal("a tampered signature was accepted")
	}
	other := bundle(t, "python3", "count.py", "import json\nprint(json.dumps({'n': 2}))\n", false)
	if _, err := Submit(other, p, sig, now); err == nil {
		t.Fatal("a signature over another bundle was accepted")
	}
	if err := p.RevokeKey(sig.KeyID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(v, p, sig, now.Add(2*time.Hour)); err == nil {
		t.Fatal("a revoked key verified")
	}
	_, strangerPriv := keyPair(t)
	if _, err := Submit(v, p, SignBundle(strangerPriv, v.BundleDigest), now); err == nil {
		t.Fatal("an unregistered key verified")
	}
}

func TestBundleValidation(t *testing.T) {
	ok := map[string][]byte{"count.py": []byte("print(1)\n")}
	cases := map[string]Bundle{
		"args outside files":   {Manifest: []byte(strings.Replace(string(manifest("acme_count", "python3", "count.py", false)), `"args":["count.py"]`, `"args":["-c","x"]`, 1)), Files: ok},
		"path in file name":    {Manifest: manifest("acme_count", "python3", "../count.py", false), Files: map[string][]byte{"../count.py": []byte("x")}},
		"binary file":          {Manifest: manifest("acme_count", "python3", "count.py", false), Files: map[string][]byte{"count.py": []byte("a\x00b")}},
		"program with a path":  {Manifest: manifest("acme_count", "/usr/bin/python3", "count.py", false), Files: ok},
		"bad name":             {Manifest: manifest("Acme", "python3", "count.py", false), Files: ok},
		"bad version":          {Manifest: []byte(strings.Replace(string(manifest("acme_count", "python3", "count.py", false)), `"version":"1.0.0"`, `"version":"1.0"`, 1)), Files: ok},
		"file not uploaded":    {Manifest: manifest("acme_count", "python3", "count.py", false), Files: map[string][]byte{}},
		"duplicate file name":  {Manifest: []byte(strings.Replace(string(manifest("acme_count", "python3", "count.py", false)), `"files":["count.py"]`, `"files":["count.py","count.py"]`, 1)), Files: map[string][]byte{"count.py": []byte("x\n"), "stray.py": []byte("import socket\n")}},
		"unknown manifest key": {Manifest: []byte(strings.Replace(string(manifest("acme_count", "python3", "count.py", false)), `"name"`, `"x":1,"name"`, 1)), Files: ok},
	}
	for name, b := range cases {
		if _, err := b.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	files := map[string][]byte{}
	names := []string{}
	for i := 0; i < 9; i++ {
		n := "f" + string(rune('0'+i)) + ".py"
		files[n] = []byte("x\n")
		names = append(names, n)
	}
	m := Manifest{Name: "acme_count", Description: "d", InputSchema: json.RawMessage(`{}`), Program: "python3", Args: []string{"f0.py"}, Files: names, Catalog: CatalogBlock{Version: "1.0.0", Category: "c", License: "MIT"}}
	raw, _ := json.Marshal(m)
	if _, err := (Bundle{Manifest: raw, Files: files}).Validate(); err == nil {
		t.Error("nine files accepted")
	}
	v := bundle(t, "python3", "count.py", "print(1)\n", false)
	again := bundle(t, "python3", "count.py", "print(1)\n", false)
	if v.BundleDigest != again.BundleDigest {
		t.Error("the bundle digest is not deterministic")
	}
}

func TestScanRules(t *testing.T) {
	cases := []struct {
		program, file, code string
		network             bool
		rule                string
		severity            Severity
	}{
		{"python3", "t.py", "import socket\n", false, "network", Block},
		{"python3", "t.py", "import urllib.request\n", true, "network", Warn},
		{"python3", "t.py", "import json, socket\n", false, "network", Block},
		{"python3", "t.py", "from urllib import request\n", false, "network", Block},
		{"python3", "t.py", "import subprocess\n", false, "process", Block},
		{"python3", "t.py", "x = eval(s)\n", false, "dynamic-code", Block},
		{"python3", "t.py", "import base64\nbase64.b64decode(s)\n", false, "obfuscation", Block},
		{"python3", "t.py", "p = os.path.expanduser('~')\n", false, "escape", Warn},
		{"python3", "t.py", "s = '" + strings.Repeat("A", 220) + "'\n", false, "obfuscation", Block},
		{"bash", "t.sh", "curl https://x\n", false, "network", Block},
		{"bash", "t.sh", "wget -O - https://x\n", true, "network", Warn},
		{"bash", "t.sh", "eval \"$cmd\"\n", false, "dynamic-code", Block},
		{"bash", "t.sh", "echo $b | base64 -d | sh\n", false, "obfuscation", Block},
		{"bash", "t.sh", "rm -rf \"$HOME/x\"\n", false, "escape", Warn},
		{"node", "t.js", "const net = require('net')\n", false, "network", Block},
		{"node", "t.js", "fetch(url)\n", true, "network", Warn},
		{"node", "t.js", "require('child_process')\n", false, "process", Block},
		{"node", "t.js", "new Function('return 1')()\n", false, "dynamic-code", Block},
		{"node", "t.js", "Buffer.from(s, 'base64')\n", false, "obfuscation", Block},
		{"node", "t.js", "const h = process.env.HOME\n", false, "escape", Warn},
	}
	for _, c := range cases {
		report := Scan(bundle(t, c.program, c.file, c.code, c.network))
		found := false
		for _, f := range report.Findings {
			if f.Rule == c.rule && f.Severity == c.severity && f.File == c.file {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %q (network=%v): want %s %s, got %+v", c.program, c.code, c.network, c.rule, c.severity, report.Findings)
		}
	}
	kmeans := Scan(bundle(t, "node", "k.js", "const cluster = points.filter(p => p.cluster === 1)\nconst { Worker } = require('worker_threads')\n", false))
	if len(kmeans.Findings) != 1 || kmeans.Findings[0].Line != 2 || kmeans.Findings[0].Rule != "process" {
		t.Errorf("a cluster variable is not a process rule hit; worker_threads is: %+v", kmeans.Findings)
	}
	clean := Scan(bundle(t, "python3", "count.py", "#!/usr/bin/env python3\n# import socket (a comment)\nimport json, sys\nfrom fractions import Fraction\nprint(json.dumps({'n': Fraction(1, 3).numerator}))\n", false))
	if len(clean.Findings) != 0 {
		t.Errorf("clean tool has findings: %+v", clean.Findings)
	}
	if Scan(bundle(t, "python3", "t.py", "import socket\n", false)).Blocking() != true {
		t.Error("blocking not reported")
	}
}

func submitted(t *testing.T, code string) (*ToolVersion, *Publisher) {
	t.Helper()
	p, priv := publisher(t)
	v := bundle(t, "python3", "count.py", code, false)
	version, err := Submit(v, p, SignBundle(priv, v.BundleDigest), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := version.RecordScan(Scan(v), now); err != nil {
		t.Fatal(err)
	}
	return version, p
}

func TestVersionLifecycle(t *testing.T) {
	v, _ := submitted(t, "import socket\n")
	if v.Status != Rejected || !strings.Contains(v.RejectedReason, "network") {
		t.Fatalf("a blocking scan did not reject: %s %q", v.Status, v.RejectedReason)
	}
	if err := v.Approve("ana", "", now); err == nil {
		t.Fatal("a rejected version was approved")
	}

	v, _ = submitted(t, "print(1)\n")
	if v.Status != Scanned {
		t.Fatalf("status %s", v.Status)
	}
	if err := v.Approve("ana", "", now); err == nil {
		t.Fatal("approved without tests")
	}
	if err := v.RecordTests(TestReport{Cases: 3, Passed: 2, Failed: []string{"tie"}, RanAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := v.Approve("ana", "", now); err == nil {
		t.Fatal("approved with a failing test")
	}
	if err := v.RecordTests(TestReport{Cases: 3, Passed: 3, RanAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := v.Approve("acme", "", now); err == nil {
		t.Fatal("the publisher approved its own version")
	}
	if err := v.Withdraw("ana", "x", now); err == nil {
		t.Fatal("yanked before approval")
	}
	if err := v.Approve("ana", "looks right", now); err != nil {
		t.Fatal(err)
	}
	if err := v.Withdraw("ana", "", now); err == nil {
		t.Fatal("yanked without a reason")
	}
	if err := v.Withdraw("ana", "bug in ties", now.Add(time.Hour)); err != nil || v.Status != Yanked {
		t.Fatalf("yank: %v %s", err, v.Status)
	}
	if err := v.RecordScan(ScanReport{}, now); err == nil {
		t.Fatal("a scan was recorded twice")
	}

	v, _ = submitted(t, "print(1)\n")
	if err := v.Reject("ana", "", now); err == nil {
		t.Fatal("rejected without a reason")
	}
	if err := v.Reject("ana", "not useful", now); err != nil || v.Status != Rejected {
		t.Fatalf("reject: %v %s", err, v.Status)
	}
}

func TestToolOwnershipAndVersionOrder(t *testing.T) {
	v1, p := submitted(t, "print(1)\n")
	tool := &Tool{Name: v1.Name, Owner: p.ID}
	if err := tool.Add(v1); err != nil {
		t.Fatal(err)
	}
	v1b, _ := submitted(t, "print(2)\n")
	if err := tool.Add(v1b); err == nil {
		t.Fatal("the same version string was reused")
	}
	other := &Tool{Name: v1.Name, Owner: "mallory"}
	if err := other.Add(v1); err == nil {
		t.Fatal("another owner's tool accepted the version")
	}
	v1b.Version = "0.9.0"
	if err := tool.Add(v1b); err == nil {
		t.Fatal("an older version was accepted")
	}
	v1b.Version = "1.0.1"
	if err := tool.Add(v1b); err != nil {
		t.Fatal(err)
	}
	if tool.Latest() != nil {
		t.Fatal("an unapproved version is latest")
	}
}

func TestIndexCarriesOnlyApprovedAndRevocations(t *testing.T) {
	v1, p := submitted(t, "print(1)\n")
	v1.RecordTests(TestReport{Cases: 1, Passed: 1, RanAt: now})
	if err := v1.Approve("ana", "", now); err != nil {
		t.Fatal(err)
	}
	v2, _ := submitted(t, "print(2)\nx = os.path.expanduser('~')\n")
	v2.Version = "1.1.0"
	v2.RecordTests(TestReport{Cases: 1, Passed: 1, RanAt: now})
	if err := v2.Approve("ana", "", now); err != nil {
		t.Fatal(err)
	}
	v3, _ := submitted(t, "print(3)\n")
	v3.Version = "1.2.0"
	tool := &Tool{Name: v1.Name, Owner: p.ID, Versions: []*ToolVersion{v3, v2, v1}}
	if err := v1.Withdraw("ana", "superseded", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	p.RevokeKey(p.Keys[0].ID, now.Add(2*time.Hour))
	index := BuildIndex("axlr", []*Tool{tool}, []*Publisher{p}, now.Add(3*time.Hour))
	if len(index.Tools) != 1 || index.Tools[0].Version != "1.1.0" {
		t.Fatalf("tools: %+v", index.Tools)
	}
	entry := index.Tools[0]
	if entry.Publisher != "acme" || entry.Reviewer != "ana" || entry.BundleSHA256 != string(v2.BundleDigest) || entry.Signature == "" || len(entry.Warnings) != 1 {
		t.Fatalf("entry: %+v", entry)
	}
	if len(index.Revocations) != 1 || index.Revocations[0].Version != "1.0.0" || index.Revocations[0].Reason != "superseded" {
		t.Fatalf("revocations: %+v", index.Revocations)
	}
	if len(index.RevokedKeys) != 1 || index.RevokedKeys[0].Publisher != "acme" {
		t.Fatalf("revoked keys: %+v", index.RevokedKeys)
	}
	a, _ := index.Canonical()
	b, _ := BuildIndex("axlr", []*Tool{tool}, []*Publisher{p}, now.Add(3*time.Hour)).Canonical()
	if string(a) != string(b) {
		t.Fatal("canonical bytes differ between builds of the same state")
	}
	// The console's client reads these keys from every entry.
	var generic map[string]any
	if err := json.Unmarshal(a, &generic); err != nil {
		t.Fatal(err)
	}
	first := generic["tools"].([]any)[0].(map[string]any)
	for _, key := range []string{"name", "version", "category", "tags", "summary", "program", "requires", "network", "license", "manifest", "manifest_sha256", "files"} {
		if _, ok := first[key]; !ok {
			t.Errorf("entry lacks %s", key)
		}
	}
	if first["files"].(map[string]any)["count.py"] != string(v2.FileDigests["count.py"]) {
		t.Error("file digest missing from the entry")
	}
}
