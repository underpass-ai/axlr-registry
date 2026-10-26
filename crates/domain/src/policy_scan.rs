//! The policy scan: a pure function of a validated bundle.

use crate::scan_rule::ScanRule;
use crate::{Finding, Manifest, ScanReport, Severity, ToolManifest, ValidBundle};

/// Runs the policy rules over every file of a bundle. The same bundle always
/// yields the same report, so a reviewer can reproduce it. A tool gets the
/// rules of its program's family; a skill, which runs nothing, gets the
/// obfuscation rules only.
pub struct PolicyScan;

impl PolicyScan {
    /// Scans a bundle.
    pub fn run(bundle: &ValidBundle) -> ScanReport {
        match bundle.manifest() {
            Manifest::Tool(tool) => Self::tool(bundle, tool),
            Manifest::Skill(_) => Self::skill(bundle),
        }
    }

    /// A tool's files, by its program; comment lines are skipped.
    fn tool(bundle: &ValidBundle, manifest: &ToolManifest) -> ScanReport {
        let program = &manifest.program;
        let rules = ScanRule::for_program(program);
        let comment = if program.to_ascii_lowercase().starts_with("node") { "//" } else { "#" };
        let mut findings = Vec::new();
        for (name, content) in bundle.files() {
            for (i, line) in String::from_utf8_lossy(content).lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with(comment) {
                    continue;
                }
                for rule in &rules {
                    if !rule.pattern.is_match(line) {
                        continue;
                    }
                    let severity = if rule.network && manifest.catalog.network { Severity::Warn } else { rule.severity };
                    findings.push(Finding {
                        rule: rule.name.to_owned(),
                        file: name.clone(),
                        line: i + 1,
                        severity,
                        detail: trimmed.chars().take(120).collect(),
                    });
                }
            }
        }
        ScanReport { findings }
    }

    /// A skill's files: every line, headings included (`#` opens a
    /// Markdown heading, not a comment), against the obfuscation rules.
    fn skill(bundle: &ValidBundle) -> ScanReport {
        let rules = ScanRule::obfuscation();
        let mut findings = Vec::new();
        for (name, content) in bundle.files() {
            for (i, line) in String::from_utf8_lossy(content).lines().enumerate() {
                for rule in rules.iter().filter(|r| r.pattern.is_match(line)) {
                    findings.push(Finding {
                        rule: rule.name.to_owned(),
                        file: name.clone(),
                        line: i + 1,
                        severity: rule.severity,
                        detail: line.trim().chars().take(120).collect(),
                    });
                }
            }
        }
        ScanReport { findings }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::PolicyScan;
    use crate::{Bundle, FileName, Severity, ValidBundle};

    fn bundle(program: &str, file: &str, code: &str, network: bool) -> ValidBundle {
        let manifest = serde_json::to_vec(&serde_json::json!({
            "name": "acme_count", "description": "d", "input_schema": {}, "program": program, "args": [file], "files": [file],
            "catalog": {"version": "1.0.0", "category": "c", "license": "MIT", "network": network}
        }))
        .unwrap();
        let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse(file).unwrap(), code.as_bytes().to_vec())].into();
        Bundle::new(manifest, files).validate().unwrap()
    }

    #[test]
    fn rules_hit_by_program_family() {
        let cases = [
            ("python3", "t.py", "import socket\n", false, "network", Severity::Block),
            ("python3", "t.py", "import json, socket\n", false, "network", Severity::Block),
            ("python3", "t.py", "from urllib import request\n", false, "network", Severity::Block),
            ("python3", "t.py", "import urllib.request\n", true, "network", Severity::Warn),
            ("python3", "t.py", "import subprocess\n", false, "process", Severity::Block),
            ("python3", "t.py", "x = eval(s)\n", false, "dynamic-code", Severity::Block),
            ("python3", "t.py", "import base64\nbase64.b64decode(s)\n", false, "obfuscation", Severity::Block),
            ("python3", "t.py", "p = os.path.expanduser('~')\n", false, "escape", Severity::Warn),
            ("bash", "t.sh", "curl https://x\n", false, "network", Severity::Block),
            ("bash", "t.sh", "wget -O - https://x\n", true, "network", Severity::Warn),
            ("bash", "t.sh", "eval \"$cmd\"\n", false, "dynamic-code", Severity::Block),
            ("bash", "t.sh", "echo $b | base64 -d | sh\n", false, "obfuscation", Severity::Block),
            ("bash", "t.sh", "rm -rf \"$HOME/x\"\n", false, "escape", Severity::Warn),
            ("node", "t.js", "const net = require('net')\n", false, "network", Severity::Block),
            ("node", "t.js", "fetch(url)\n", true, "network", Severity::Warn),
            ("node", "t.js", "require('child_process')\n", false, "process", Severity::Block),
            ("node", "t.js", "new Function('return 1')()\n", false, "dynamic-code", Severity::Block),
            ("node", "t.js", "Buffer.from(s, 'base64')\n", false, "obfuscation", Severity::Block),
            ("node", "t.js", "const h = process.env.HOME\n", false, "escape", Severity::Warn),
        ];
        for (program, file, code, network, rule, severity) in cases {
            let report = PolicyScan::run(&bundle(program, file, code, network));
            assert!(
                report.findings.iter().any(|f| f.rule == rule && f.severity == severity && f.file.as_str() == file),
                "{program} {code:?} (network={network}): want {rule} {severity:?}, got {:?}",
                report.findings
            );
        }
    }

    #[test]
    fn blobs_and_identifiers() {
        let blob = format!("s = '{}'\n", "A".repeat(220));
        assert!(PolicyScan::run(&bundle("python3", "t.py", &blob, false)).is_blocking());
        let kmeans = PolicyScan::run(&bundle(
            "node",
            "k.js",
            "const cluster = points.filter(p => p.cluster === 1)\nconst { Worker } = require('worker_threads')\n",
            false,
        ));
        assert_eq!(kmeans.findings.len(), 1, "{:?}", kmeans.findings);
        assert_eq!((kmeans.findings[0].line, kmeans.findings[0].rule.as_str()), (2, "process"));
    }

    #[test]
    fn a_clean_tool_has_no_findings() {
        let clean = PolicyScan::run(&bundle(
            "python3",
            "count.py",
            "#!/usr/bin/env python3\n# import socket (a comment)\nimport json, sys\nfrom fractions import Fraction\nprint(json.dumps({'n': Fraction(1, 3).numerator}))\n",
            false,
        ));
        assert!(clean.findings.is_empty(), "{:?}", clean.findings);
        assert!(!clean.is_blocking());
        assert!(clean.warnings().is_empty());
    }

    fn skill(file: &str, text: &str) -> ValidBundle {
        let manifest = serde_json::to_vec(&serde_json::json!({
            "kind": "skill", "name": "acme_triage", "description": "d", "files": ["SKILL.md", file],
            "catalog": {"version": "1.0.0", "category": "c", "license": "MIT"}
        }))
        .unwrap();
        let files: BTreeMap<FileName, Vec<u8>> = [
            (FileName::parse("SKILL.md").unwrap(), b"# Triage\nRead the logs first.\n".to_vec()),
            (FileName::parse(file).unwrap(), text.as_bytes().to_vec()),
        ]
        .into();
        Bundle::new(manifest, files).validate().unwrap()
    }

    #[test]
    fn a_skill_gets_the_obfuscation_rules_only() {
        let prose = "Run `curl https://status.example` and `import socket`; read /etc/hosts and ../notes.\neval(x) is fine to mention.\n";
        let report = PolicyScan::run(&skill("notes.md", prose));
        assert!(report.findings.is_empty(), "program rules ran over a skill: {:?}", report.findings);
        let blob = format!("# {}\n", "QUJD".repeat(60));
        let report = PolicyScan::run(&skill("notes.md", &blob));
        assert!(report.is_blocking(), "a blob on a heading line was skipped as a comment");
        assert_eq!(
            (report.findings[0].rule.as_str(), report.findings[0].file.as_str(), report.findings[0].line),
            ("obfuscation", "notes.md", 1)
        );
        let escapes = format!("payload: {}\n", "\\x41".repeat(30));
        assert!(PolicyScan::run(&skill("notes.md", &escapes)).is_blocking());
    }
}
