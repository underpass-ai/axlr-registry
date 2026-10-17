//! One policy rule: a pattern, a name and a severity.

use regex::Regex;

use crate::Severity;

/// A rule over one source line.
pub(crate) struct ScanRule {
    pub(crate) name: &'static str,
    pub(crate) pattern: Regex,
    pub(crate) severity: Severity,
    /// A network rule blocks unless the manifest declares `network: true`.
    pub(crate) network: bool,
}

impl ScanRule {
    fn new(name: &'static str, pattern: &str, severity: Severity, network: bool) -> Self {
        Self { name, pattern: Regex::new(pattern).expect("a rule pattern compiles"), severity, network }
    }

    /// Rules every program gets.
    pub(crate) fn generic() -> Vec<Self> {
        vec![
            Self::new("obfuscation", r"[A-Za-z0-9+/=]{200,}", Severity::Block, false),
            Self::new("obfuscation", r"(\\x[0-9a-fA-F]{2}){24,}", Severity::Block, false),
            Self::new("escape", r"(^|[^A-Za-z0-9_])(/home/|/etc/|/root/|/var/|\.\./)", Severity::Warn, false),
        ]
    }

    pub(crate) fn python() -> Vec<Self> {
        vec![
            Self::new(
                "network",
                r"^\s*(import|from)\s+.*\b(socket|urllib|http\.client|requests|ftplib|smtplib|ssl|websockets?)\b",
                Severity::Block,
                true,
            ),
            Self::new(
                "process",
                r"\b(subprocess|multiprocessing|ctypes)\b|\bos\.(system|exec[lvpe]*|popen|spawn[lvpe]*|fork)\s*\(",
                Severity::Block,
                false,
            ),
            Self::new("dynamic-code", r"(^|[^A-Za-z0-9_.])(eval|exec|compile|__import__)\s*\(|\bimportlib\b", Severity::Block, false),
            Self::new(
                "obfuscation",
                r"\bbase64\.(b64|b32|b16|a85|b85)decode\b|\bcodecs\.decode\b|\bmarshal\.loads\b|\bpickle\.loads?\b",
                Severity::Block,
                false,
            ),
            Self::new("escape", r"\bos\.environ\b|\bexpanduser\s*\(|\bPath\.home\s*\(", Severity::Warn, false),
        ]
    }

    pub(crate) fn bash() -> Vec<Self> {
        vec![
            Self::new(
                "network",
                r"(^|[^A-Za-z0-9_-])(curl|wget|nc|ncat|netcat|ssh|scp|sftp|telnet)\s|/dev/(tcp|udp)/",
                Severity::Block,
                true,
            ),
            Self::new("dynamic-code", r"(^|[^A-Za-z0-9_])eval\s|source\s+<\(|\.\s+<\(|\$\(\s*(curl|wget)", Severity::Block, false),
            Self::new("obfuscation", r"base64\s+(-d|--decode)|\bopenssl\s+enc\b|\bxxd\s+-r\b", Severity::Block, false),
            Self::new("escape", r"\$HOME\b|(^|[\s=])~[/\s]|\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|\bsudo\b", Severity::Warn, false),
        ]
    }

    pub(crate) fn node() -> Vec<Self> {
        vec![
            Self::new(
                "network",
                r#"require\(\s*["'](net|http|https|dns|tls|dgram|http2|ws)["']\s*\)|from\s+["'](net|http|https|dns|tls|dgram|http2)["']|\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b"#,
                Severity::Block,
                true,
            ),
            Self::new(
                "process",
                r#"require\(\s*["'](child_process|worker_threads|cluster)["']\s*\)|from\s+["'](child_process|worker_threads|cluster)["']"#,
                Severity::Block,
                false,
            ),
            Self::new(
                "dynamic-code",
                r#"(^|[^A-Za-z0-9_.])eval\s*\(|new\s+Function\s*\(|\bvm\.(runIn|compile|Script)|require\(\s*["']vm["']"#,
                Severity::Block,
                false,
            ),
            Self::new("obfuscation", r#"Buffer\.from\s*\([^)]*["']base64["']|\batob\s*\("#, Severity::Block, false),
            Self::new("escape", r"\bprocess\.env\b|\bos\.homedir\s*\(", Severity::Warn, false),
        ]
    }

    /// The rules for a program: its family's plus the generic ones.
    pub(crate) fn for_program(program: &str) -> Vec<Self> {
        let family = program.to_ascii_lowercase();
        let mut rules = if family.starts_with("python") {
            Self::python()
        } else if matches!(family.as_str(), "bash" | "sh" | "zsh") {
            Self::bash()
        } else if family.starts_with("node") {
            Self::node()
        } else {
            Vec::new()
        };
        rules.extend(Self::generic());
        rules
    }
}
