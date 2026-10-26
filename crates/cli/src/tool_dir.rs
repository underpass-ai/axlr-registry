//! A tool's directory on the publisher's machine: `manifest.json`, the
//! files it lists and, beside them, `tests.json`.

use std::collections::BTreeMap;
use std::path::Path;

use registry_domain::{Bundle, FileName, Manifest, ValidBundle};

use crate::{read_file, CliError};

/// The bundle read from a directory, validated by the domain, and its tests.
#[derive(Debug, Clone)]
pub struct ToolDir {
    bundle: ValidBundle,
    manifest: Vec<u8>,
    files: BTreeMap<FileName, Vec<u8>>,
    tests: Option<Vec<u8>>,
}

impl ToolDir {
    /// Reads the directory. The manifest's `files` says what to read; a
    /// file it does not list stays out of the bundle. `tests.json` is read
    /// when present and travels beside the bundle.
    pub fn load(dir: &Path) -> Result<Self, CliError> {
        let manifest = read_file(&dir.join("manifest.json"))?;
        let parsed = Manifest::parse(&manifest)?;
        let mut files = BTreeMap::new();
        for name in parsed.files() {
            files.insert(name.clone(), read_file(&dir.join(name.as_str()))?);
        }
        let tests_path = dir.join("tests.json");
        let tests = if tests_path.exists() { Some(read_file(&tests_path)?) } else { None };
        let bundle = Bundle::new(manifest.clone(), files.clone()).validate()?;
        Ok(Self { bundle, manifest, files, tests })
    }

    /// The validated bundle.
    pub fn bundle(&self) -> &ValidBundle {
        &self.bundle
    }

    /// The manifest bytes as read.
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// The files as read.
    pub fn files(&self) -> &BTreeMap<FileName, Vec<u8>> {
        &self.files
    }

    /// `tests.json`, if the directory has one.
    pub fn tests(&self) -> Option<&[u8]> {
        self.tests.as_deref()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use super::ToolDir;

    pub(crate) const MANIFEST: &str = r#"{"name": "acme_count", "description": "Count items. Exactly.", "input_schema": {"type": "object"},
        "program": "python3", "args": ["count.py"], "files": ["count.py"],
        "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}}"#;
    pub(crate) const TESTS: &str = r#"[{"name": "one", "input": {"items": [1]}, "expect": {"stdout_json": {"n": 1}}}]"#;

    pub(crate) fn write_tool(dir: &Path, with_tests: bool) {
        std::fs::write(dir.join("manifest.json"), MANIFEST).unwrap();
        std::fs::write(dir.join("count.py"), "import json, sys\nprint(json.dumps({'n': len(json.load(sys.stdin)['items'])}))\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "not part of the bundle").unwrap();
        if with_tests {
            std::fs::write(dir.join("tests.json"), TESTS).unwrap();
        }
    }

    #[test]
    fn reads_only_what_the_manifest_lists() {
        let dir = tempfile::tempdir().unwrap();
        write_tool(dir.path(), true);
        let tool = ToolDir::load(dir.path()).unwrap();
        assert_eq!(tool.files().len(), 1);
        assert_eq!(tool.tests(), Some(TESTS.as_bytes()));
        assert_eq!(tool.bundle().name().as_str(), "acme_count");
        std::fs::remove_file(dir.path().join("tests.json")).unwrap();
        assert!(ToolDir::load(dir.path()).unwrap().tests().is_none());
        std::fs::remove_file(dir.path().join("count.py")).unwrap();
        assert!(ToolDir::load(dir.path()).is_err(), "a missing file loaded");
        std::fs::write(dir.path().join("manifest.json"), "{}").unwrap();
        assert!(ToolDir::load(dir.path()).is_err(), "an invalid manifest loaded");
    }
}
