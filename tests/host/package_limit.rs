//! Run in the pinned host's registry crate; this verifies the actual native
//! packer refuses the real probe rather than guessing from a source constant.
use serde_json::json;
use srelens_registry::extension_package::digest_list;

#[test]
fn the_current_host_refuses_the_trivy_probe_package() {
    let binary = std::env::var_os("TRIVY_PROOF_BINARY").expect("set TRIVY_PROOF_BINARY");
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("bin/linux-arm64/trivy-probe");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::copy(binary, target).unwrap();
    std::fs::write(root.path().join("extension.json"), serde_json::to_vec(&json!({
        "id": "com.example.trivy-proof", "name": "Trivy feasibility", "version": "0.1.0",
        "srelensApiVersion": "^0.7", "kind": "executable", "permissions": [], "capabilities": [],
        "contributions": {"pages": [], "detailTabs": [], "detailLinks": []},
        "sidecar": {"binaries": {"linux-arm64": "bin/linux-arm64/trivy-probe"},
                    "operations": [{"name": "scan", "title": "Scan"}]}
    })).unwrap()).unwrap();
    let reason = digest_list(root.path()).expect_err("the feasibility blocker unexpectedly disappeared");
    assert!(reason.contains("larger") || reason.contains("64 MiB"), "unexpected rejection: {reason}");
    println!("native package refusal: {reason}");
}
