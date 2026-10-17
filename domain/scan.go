package domain

import (
	"regexp"
	"sort"
	"strings"
)

// Severity of a scan finding: a block finding rejects the version; a warn
// finding is shown to the reviewer and on the install card.
type Severity string

const (
	Block Severity = "block"
	Warn  Severity = "warn"
)

// Finding is one policy hit in one file.
type Finding struct {
	Rule     string   `json:"rule"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// ScanReport is the deterministic policy scan of a bundle.
type ScanReport struct {
	Findings []Finding `json:"findings"`
}

// Blocking says whether any finding blocks the version.
func (r ScanReport) Blocking() bool {
	for _, f := range r.Findings {
		if f.Severity == Block {
			return true
		}
	}
	return false
}

type rule struct {
	name     string
	pattern  *regexp.Regexp
	severity Severity
	network  bool // a network rule: block unless the manifest declares network
}

// Rules per program family. A family is chosen from the manifest's program
// (python3, python; bash, sh; node, nodejs); files of an unknown program
// get the generic rules only.
var (
	genericRules = []rule{
		{"obfuscation", regexp.MustCompile(`[A-Za-z0-9+/=]{200,}`), Block, false},
		{"obfuscation", regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){24,}`), Block, false},
		{"escape", regexp.MustCompile(`(^|[^A-Za-z0-9_])(/home/|/etc/|/root/|/var/|\.\./)`), Warn, false},
	}
	pythonRules = []rule{
		{"network", regexp.MustCompile(`^\s*(import|from)\s+.*\b(socket|urllib|http\.client|requests|ftplib|smtplib|ssl|websockets?)\b`), Block, true},
		{"process", regexp.MustCompile(`\b(subprocess|multiprocessing|ctypes)\b|\bos\.(system|exec[lvpe]*|popen|spawn[lvpe]*|fork)\s*\(`), Block, false},
		{"dynamic-code", regexp.MustCompile(`(^|[^A-Za-z0-9_.])(eval|exec|compile|__import__)\s*\(|\bimportlib\b`), Block, false},
		{"obfuscation", regexp.MustCompile(`\bbase64\.(b64|b32|b16|a85|b85)decode\b|\bcodecs\.decode\b|\bmarshal\.loads\b|\bpickle\.loads?\b`), Block, false},
		{"escape", regexp.MustCompile(`\bos\.environ\b|\bexpanduser\s*\(|\bPath\.home\s*\(`), Warn, false},
	}
	bashRules = []rule{
		{"network", regexp.MustCompile(`(^|[^A-Za-z0-9_-])(curl|wget|nc|ncat|netcat|ssh|scp|sftp|telnet)\s|/dev/(tcp|udp)/`), Block, true},
		{"dynamic-code", regexp.MustCompile(`(^|[^A-Za-z0-9_])eval\s|source\s+<\(|\.\s+<\(|\$\(\s*(curl|wget)`), Block, false},
		{"obfuscation", regexp.MustCompile(`base64\s+(-d|--decode)|\bopenssl\s+enc\b|\bxxd\s+-r\b`), Block, false},
		{"escape", regexp.MustCompile(`\$HOME\b|(^|[\s=])~[/\s]|\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|\bsudo\b|\bchmod\s+[0-7]*[s]`), Warn, false},
	}
	nodeRules = []rule{
		{"network", regexp.MustCompile(`require\(\s*["'](net|http|https|dns|tls|dgram|http2|ws)["']\s*\)|from\s+["'](net|http|https|dns|tls|dgram|http2)["']|\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b`), Block, true},
		{"process", regexp.MustCompile(`require\(\s*["'](child_process|worker_threads|cluster)["']\s*\)|from\s+["'](child_process|worker_threads|cluster)["']`), Block, false},
		{"dynamic-code", regexp.MustCompile(`(^|[^A-Za-z0-9_.])eval\s*\(|new\s+Function\s*\(|\bvm\.(runIn|compile|Script)|require\(\s*["']vm["']`), Block, false},
		{"obfuscation", regexp.MustCompile(`Buffer\.from\s*\([^)]*["']base64["']|\batob\s*\(`), Block, false},
		{"escape", regexp.MustCompile(`\bprocess\.env\b|\bos\.homedir\s*\(`), Warn, false},
	}
)

func rulesFor(program string) []rule {
	family := strings.ToLower(program)
	switch {
	case strings.HasPrefix(family, "python"):
		return append(append([]rule{}, pythonRules...), genericRules...)
	case family == "bash" || family == "sh" || family == "zsh":
		return append(append([]rule{}, bashRules...), genericRules...)
	case strings.HasPrefix(family, "node"):
		return append(append([]rule{}, nodeRules...), genericRules...)
	}
	return genericRules
}

// Scan runs the policy rules over every file of a validated bundle. It is a
// pure function of the bundle: the same bundle always yields the same
// report, so a reviewer can reproduce it.
func Scan(v ValidBundle) ScanReport {
	rules := rulesFor(v.Parsed.Program)
	var findings []Finding
	names := make([]string, 0, len(v.Files))
	for n := range v.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		for i, line := range strings.Split(string(v.Files[name]), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isComment(trimmed, v.Parsed.Program) {
				continue
			}
			for _, r := range rules {
				if !r.pattern.MatchString(line) {
					continue
				}
				severity := r.severity
				if r.network && v.Parsed.Catalog.Network {
					severity = Warn
				}
				findings = append(findings, Finding{Rule: r.name, File: name, Line: i + 1, Severity: severity, Detail: bounded(trimmed, 120)})
			}
		}
	}
	return ScanReport{Findings: findings}
}

func isComment(line, program string) bool {
	switch {
	case strings.HasPrefix(strings.ToLower(program), "node"):
		return strings.HasPrefix(line, "//")
	default:
		return strings.HasPrefix(line, "#")
	}
}

func bounded(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
