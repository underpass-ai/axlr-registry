//! A link in Markdown text: `[text](target)` or `![alt](target)`.

/// One inline link's target, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownLink {
    target: String,
}

impl MarkdownLink {
    /// Every inline link outside fenced code blocks, in order. A target may
    /// be wrapped in `<…>` and followed by a title, which is dropped.
    pub fn all(text: &str) -> Vec<Self> {
        let mut links = Vec::new();
        let mut fenced = false;
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
                fenced = !fenced;
                continue;
            }
            if fenced {
                continue;
            }
            let mut rest = line;
            while let Some(start) = rest.find("](") {
                let after = &rest[start + 2..];
                let Some(end) = after.find(')') else { break };
                let raw = after[..end].trim();
                let target = match raw.strip_prefix('<').and_then(|r| r.split_once('>')) {
                    Some((inner, _)) => inner,
                    None => raw.split_whitespace().next().unwrap_or(""),
                };
                links.push(Self { target: target.to_owned() });
                rest = &after[end + 1..];
            }
        }
        links
    }

    /// The target as written.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The bundle file a relative link names: the target without its
    /// `#anchor` or `?query` and without a leading `./`. `None` for an
    /// empty target, a pure anchor, an absolute path, or a target with a
    /// scheme (`https:`, `mailto:`), which name nothing in the bundle.
    pub fn local_file(&self) -> Option<&str> {
        let target = self.target.as_str();
        let scheme = target.split_once(':').is_some_and(|(s, _)| {
            s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-')
        });
        if scheme || target.starts_with('/') {
            return None;
        }
        let path = target.split(['#', '?']).next().unwrap_or("");
        let path = path.strip_prefix("./").unwrap_or(path);
        (!path.is_empty()).then_some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::MarkdownLink;

    fn files(text: &str) -> Vec<Option<String>> {
        MarkdownLink::all(text).iter().map(|l| l.local_file().map(str::to_owned)).collect()
    }

    #[test]
    fn finds_relative_targets_and_skips_the_rest() {
        let text = "See [the list](checklist.md) and [step 2](./checklist.md#step-2 \"Step\").\n\
                    ![diagram](<flow chart.svg>) [site](https://example.com/x.md) [mail](mailto:a@b.c)\n\
                    [top](#triage) [abs](/etc/passwd) [empty]() [query](notes.md?plain=1)\n\
                    ```\n[in code](code.md)\n```\n[after](after.md) and a ] ( not a link\n";
        let found = files(text);
        let expected: Vec<Option<String>> = vec![
            Some("checklist.md".into()),
            Some("checklist.md".into()),
            Some("flow chart.svg".into()),
            None,
            None,
            None,
            None,
            None,
            Some("notes.md".into()),
            Some("after.md".into()),
        ];
        assert_eq!(found, expected);
        let links = MarkdownLink::all("[a](b.md)");
        assert_eq!(links[0].target(), "b.md");
        assert!(MarkdownLink::all("[unclosed](x.md").is_empty());
        assert_eq!(files("[dir](docs/x.md)"), [Some("docs/x.md".into())], "a path is kept, so it names no flat file");
    }
}
