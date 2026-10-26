//! What a publisher uploads: the manifest and the files of a tool or a skill.

use std::collections::BTreeMap;

use crate::{Digest, DomainError, FileName, Manifest, ValidBundle};

/// Bytes per file, at most.
pub const MAX_FILE_BYTES: usize = 256 * 1024;

/// An uploaded bundle, not yet validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    manifest: Vec<u8>,
    files: BTreeMap<FileName, Vec<u8>>,
}

impl Bundle {
    /// Assembles a bundle from its bytes.
    pub fn new(manifest: Vec<u8>, files: BTreeMap<FileName, Vec<u8>>) -> Self {
        Self { manifest, files }
    }

    /// Checks the bundle against the manifest's rules (a forged tool's or
    /// a skill's) and the registry's, and computes its digests.
    pub fn validate(self) -> Result<ValidBundle, DomainError> {
        let manifest = Manifest::parse(&self.manifest)?;
        let mut distinct = manifest.files().to_vec();
        distinct.sort();
        distinct.dedup();
        if distinct.len() != manifest.files().len() {
            return Err(DomainError::invalid("bundle", "files lists a name twice"));
        }
        if self.files.len() != manifest.files().len() {
            return Err(DomainError::invalid("bundle", "every file named in the manifest is uploaded, and no other"));
        }
        let mut digests = BTreeMap::new();
        for name in manifest.files() {
            let content =
                self.files.get(name).ok_or_else(|| DomainError::invalid("bundle", format!("file {} was not uploaded", name.as_str())))?;
            if content.is_empty() || content.len() > MAX_FILE_BYTES {
                return Err(DomainError::invalid("bundle", format!("file {} is empty or over 256 KiB", name.as_str())));
            }
            if content.contains(&0) {
                return Err(DomainError::invalid("bundle", format!("file {} is binary; a bundle is text", name.as_str())));
            }
            digests.insert(name.clone(), Digest::of(content));
        }
        Ok(ValidBundle::new(manifest, self.manifest, self.files, digests))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::Bundle;
    use crate::FileName;

    pub(crate) fn manifest_json(name: &str, program: &str, file: &str, network: bool) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "name": name, "description": "Count things. Exactly.", "input_schema": {"type": "object"},
            "program": program, "args": [file], "files": [file],
            "catalog": {"version": "1.0.0", "category": "data", "license": "MIT", "network": network, "requires": {"packages": []}}
        }))
        .unwrap()
    }

    fn files(pairs: &[(&str, &[u8])]) -> BTreeMap<FileName, Vec<u8>> {
        pairs.iter().map(|(n, c)| (FileName::parse(n).unwrap(), c.to_vec())).collect()
    }

    #[test]
    fn accepts_a_tool_and_digests_deterministically() {
        let a = Bundle::new(manifest_json("acme_count", "python3", "count.py", false), files(&[("count.py", b"print(1)\n")]))
            .validate()
            .unwrap();
        let b = Bundle::new(manifest_json("acme_count", "python3", "count.py", false), files(&[("count.py", b"print(1)\n")]))
            .validate()
            .unwrap();
        assert_eq!(a.bundle_digest(), b.bundle_digest());
        assert_eq!(a.manifest().summary(), "Count things.");
    }

    #[test]
    fn refuses_bad_bundles() {
        let ok = files(&[("count.py", b"print(1)\n")]);
        let base = String::from_utf8(manifest_json("acme_count", "python3", "count.py", false)).unwrap();
        type Case = (&'static str, Vec<u8>, BTreeMap<FileName, Vec<u8>>);
        let cases: Vec<Case> = vec![
            ("args outside files", base.replace(r#""args":["count.py"]"#, r#""args":["-c","x"]"#).into_bytes(), ok.clone()),
            ("binary file", base.clone().into_bytes(), files(&[("count.py", b"a\x00b")])),
            ("program with a path", manifest_json("acme_count", "/usr/bin/python3", "count.py", false), ok.clone()),
            ("bad name", manifest_json("Acme", "python3", "count.py", false), ok.clone()),
            ("bad version", base.replace(r#""version":"1.0.0""#, r#""version":"1.0""#).into_bytes(), ok.clone()),
            ("file not uploaded", base.clone().into_bytes(), BTreeMap::new()),
            ("unknown manifest key", base.replace(r#""name""#, r#""x":1,"name""#).into_bytes(), ok.clone()),
            ("stray file", base.clone().into_bytes(), files(&[("count.py", b"x\n"), ("stray.py", b"import socket\n")])),
            (
                "duplicate file name",
                base.replace(r#""files":["count.py"]"#, r#""files":["count.py","count.py"]"#).into_bytes(),
                files(&[("count.py", b"x\n"), ("stray.py", b"import socket\n")]),
            ),
        ];
        for (label, manifest, files) in cases {
            assert!(Bundle::new(manifest, files).validate().is_err(), "{label} was accepted");
        }
        let nine: Vec<String> = (0..9).map(|i| format!("f{i}.py")).collect();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "name": "acme_count", "description": "d", "input_schema": {}, "program": "python3", "args": ["f0.py"], "files": nine,
            "catalog": {"version": "1.0.0", "category": "c", "license": "MIT"}
        }))
        .unwrap();
        assert!(Bundle::new(manifest, BTreeMap::new()).validate().is_err(), "nine files accepted");
        assert!(FileName::parse("../count.py").is_err());
    }

    #[test]
    fn a_skill_is_a_bundle_of_text_files_with_the_same_digests() {
        let manifest = serde_json::to_vec(&serde_json::json!({
            "kind": "skill", "name": "acme_triage", "description": "Triage an incident.", "files": ["SKILL.md", "checklist.md"],
            "catalog": {"version": "1.0.0", "category": "programming", "license": "MIT"}
        }))
        .unwrap();
        let ok = files(&[("SKILL.md", b"# Triage\nSee [the list](checklist.md).\n"), ("checklist.md", b"- logs\n")]);
        let bundle = Bundle::new(manifest.clone(), ok.clone()).validate().unwrap();
        assert_eq!((bundle.name().as_str(), bundle.version().to_string().as_str()), ("acme_triage", "1.0.0"));
        assert_eq!(bundle.manifest().kind(), crate::Kind::Skill);
        assert_eq!(bundle.file_digests().len(), 2);
        let big = vec![b'x'; super::MAX_FILE_BYTES + 1];
        let refused: Vec<(&str, BTreeMap<FileName, Vec<u8>>)> = vec![
            ("binary", files(&[("SKILL.md", b"a\x00b"), ("checklist.md", b"x")])),
            ("oversized", files(&[("SKILL.md", big.as_slice()), ("checklist.md", b"x")])),
            ("empty", files(&[("SKILL.md", b""), ("checklist.md", b"x")])),
            ("missing", files(&[("SKILL.md", b"x")])),
        ];
        for (label, files) in refused {
            assert!(Bundle::new(manifest.clone(), files).validate().is_err(), "{label} skill file was accepted");
        }
    }
}
