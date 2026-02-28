use std::process::Command;

#[test]
#[ignore = "requires local socket permissions in test environment"]
fn api_smoke_script_passes() {
    let script = format!("{}/../../scripts/api_smoke.sh", env!("CARGO_MANIFEST_DIR"));

    let output = Command::new("bash")
        .arg(script)
        .output()
        .expect("failed to execute smoke script");

    assert!(
        output.status.success(),
        "script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
