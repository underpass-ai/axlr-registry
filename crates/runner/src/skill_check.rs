//! The tests of a skill: deterministic checks over its files, with no
//! program, no network and no model.

use std::collections::BTreeMap;

use registry_domain::{FileName, SkillManifest, ToolReference};

use crate::{CaseResult, FrontMatter, MarkdownLink, SkillSuite, TestRun};

/// Checks a skill version and reports one case per check: `SKILL.md`
/// (present, UTF-8), `front_matter` (its `name`, when present, is the
/// manifest's), `links` (every relative link names a bundle file), `tools`
/// (every entry a well-formed tool reference) and `tests.json` (optional;
/// when present, well formed). Its model cases are not run here.
pub struct SkillCheck;

impl SkillCheck {
    /// Runs the checks over the files read from quarantine (`tests.json`
    /// among them when the publisher sent one).
    pub fn run(manifest: &SkillManifest, files: &BTreeMap<FileName, Vec<u8>>) -> TestRun {
        let skill_md = files.iter().find(|(n, _)| n.as_str() == SkillManifest::SKILL_FILE).map(|(_, c)| c);
        let text = skill_md.map(|bytes| std::str::from_utf8(bytes));
        let unreadable = || vec!["SKILL.md cannot be read".to_owned()];
        let skill_problems = match text {
            None => vec!["missing".to_owned()],
            Some(Err(e)) => vec![format!("not valid UTF-8: {e}")],
            Some(Ok(_)) => Vec::new(),
        };
        let text = text.and_then(Result::ok);
        let front_matter = text.map_or_else(unreadable, |t| Self::front_matter(manifest, t));
        let links = text.map_or_else(unreadable, |t| Self::links(manifest, t));
        let tools =
            manifest.tools.iter().filter_map(|t| ToolReference::parse(t.as_str()).err().map(|e| format!("{}: {e}", t.as_str()))).collect();
        let tests = match files.iter().find(|(n, _)| n.as_str() == "tests.json") {
            None => Vec::new(),
            Some((_, bytes)) => SkillSuite::parse(bytes).err().map(|e| e.to_string()).into_iter().collect(),
        };
        TestRun::new(vec![
            CaseResult { name: SkillManifest::SKILL_FILE.to_owned(), problems: skill_problems },
            CaseResult { name: "front_matter".to_owned(), problems: front_matter },
            CaseResult { name: "links".to_owned(), problems: links },
            CaseResult { name: "tools".to_owned(), problems: tools },
            CaseResult { name: "tests.json".to_owned(), problems: tests },
        ])
    }

    fn front_matter(manifest: &SkillManifest, text: &str) -> Vec<String> {
        let Some(front_matter) = FrontMatter::of(text) else { return Vec::new() };
        let mut problems = Vec::new();
        if !front_matter.closed() {
            problems.push("the front matter opened by --- has no closing --- line".to_owned());
        }
        if let Some(name) = front_matter.name().filter(|n| *n != manifest.name.as_str()) {
            problems.push(format!("front matter name {name:?} is not the manifest's {:?}", manifest.name.as_str()));
        }
        problems
    }

    fn links(manifest: &SkillManifest, text: &str) -> Vec<String> {
        MarkdownLink::all(text)
            .iter()
            .filter_map(|link| link.local_file().map(|file| (link, file)))
            .filter(|(_, file)| !manifest.files.iter().any(|f| f.as_str() == *file))
            .map(|(link, _)| format!("link to {} names none of the bundle's files", link.target()))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use registry_domain::{FileName, Manifest, SkillManifest};

    use super::SkillCheck;

    pub(crate) const SKILL_MD: &str =
        "---\nname: acme_triage\ndescription: Triage an incident.\n---\n# Triage\nWork through [the checklist](checklist.md#first), \
         then see [the runbook](https://example.com/runbook) and [below](#notes).\n";

    pub(crate) fn manifest() -> SkillManifest {
        let json = serde_json::json!({
            "kind": "skill", "name": "acme_triage", "description": "Triage an incident.", "files": ["SKILL.md", "checklist.md"],
            "tools": ["local_read"], "catalog": {"version": "1.0.0", "category": "programming", "license": "MIT"}
        });
        match Manifest::parse(&serde_json::to_vec(&json).unwrap()).unwrap() {
            Manifest::Skill(skill) => skill,
            Manifest::Tool(_) => unreachable!("a skill manifest"),
        }
    }

    fn files(skill_md: &[u8], tests: Option<&str>) -> BTreeMap<FileName, Vec<u8>> {
        let mut files: BTreeMap<FileName, Vec<u8>> = [
            (FileName::parse("SKILL.md").unwrap(), skill_md.to_vec()),
            (FileName::parse("checklist.md").unwrap(), b"- timeline\n".to_vec()),
            (FileName::parse("manifest.json").unwrap(), b"{}".to_vec()),
        ]
        .into();
        if let Some(tests) = tests {
            files.insert(FileName::parse("tests.json").unwrap(), tests.as_bytes().to_vec());
        }
        files
    }

    fn failed(skill_md: &[u8], tests: Option<&str>) -> Vec<String> {
        let run = SkillCheck::run(&manifest(), &files(skill_md, tests));
        run.results().iter().filter(|r| !r.passed()).flat_map(|r| r.problems.iter().map(move |p| format!("{}: {p}", r.name))).collect()
    }

    #[test]
    fn a_well_formed_skill_passes_with_or_without_tests() {
        let run = SkillCheck::run(&manifest(), &files(SKILL_MD.as_bytes(), None));
        assert_eq!(run.passed(), 5, "{}", run.summary());
        let names: Vec<&str> = run.results().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["SKILL.md", "front_matter", "links", "tools", "tests.json"]);
        let tests =
            r#"[{"name": "logs", "prompt": "502 since 10:00", "expect": {"tools": ["local_read"], "answer_contains": ["timeline"]}}]"#;
        assert!(failed(SKILL_MD.as_bytes(), Some(tests)).is_empty());
        assert!(failed(b"# Triage\nNo front matter, no links.\n", None).is_empty());
    }

    #[test]
    fn each_check_fails_on_its_own() {
        assert_eq!(failed(&[0xff, 0xfe], None)[0], "SKILL.md: not valid UTF-8: invalid utf-8 sequence of 1 bytes from index 0");
        assert_eq!(failed(&[0xff], None).len(), 3, "front matter and links cannot be read either");
        assert_eq!(
            failed(b"---\nname: other_skill\n---\n", None),
            [r#"front_matter: front matter name "other_skill" is not the manifest's "acme_triage""#]
        );
        assert_eq!(failed(b"---\nname: acme_triage\n", None), ["front_matter: the front matter opened by --- has no closing --- line"]);
        assert_eq!(
            failed(b"See [notes](notes.md) and [list](./checklist.md).\n", None),
            ["links: link to notes.md names none of the bundle's files"]
        );
        assert_eq!(failed(SKILL_MD.as_bytes(), Some("[]")), ["tests.json: tests.json: no cases"]);
        let mut without = files(SKILL_MD.as_bytes(), None);
        without.retain(|n, _| n.as_str() != "SKILL.md");
        let run = SkillCheck::run(&manifest(), &without);
        assert_eq!(run.report(time::macros::datetime!(2026-10-26 12:00 UTC)).failed(), ["SKILL.md", "front_matter", "links"]);
    }
}
