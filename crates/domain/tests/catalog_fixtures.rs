//! The two reference entries the AXLR catalog actually publishes
//! (`catalog/tools/*/*/` in the AXLR repository) must validate as bundles
//! and pass the policy scan: this is the only test that touches the real
//! contract between the registry and the catalog.

use std::collections::BTreeMap;
use std::path::Path;

use registry_domain::{Bundle, FileName, PolicyScan};

fn fixture(name: &str) -> Bundle {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    let manifest = std::fs::read(dir.join("manifest.json")).expect("manifest.json");
    let file = FileName::parse(&format!("{name}.py")).unwrap();
    let files: BTreeMap<FileName, Vec<u8>> = [(file.clone(), std::fs::read(dir.join(file.as_str())).expect("tool file"))].into();
    Bundle::new(manifest, files)
}

#[test]
fn the_published_reference_tools_validate_and_scan_clean() {
    for name in ["seat_allocation", "business_days"] {
        let bundle = fixture(name).validate().unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(bundle.name().as_str(), name);
        assert_eq!(bundle.version().to_string(), "1.0.0");
        assert!(!bundle.manifest().catalog().network);
        let report = PolicyScan::run(&bundle);
        assert!(!report.is_blocking(), "{name}: {:?}", report.findings);
        assert!(report.warnings().is_empty(), "{name}: {:?}", report.findings);
    }
}
