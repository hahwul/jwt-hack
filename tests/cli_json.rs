use std::process::Command;

#[test]
fn json_mode_returns_a_structured_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "default_algorithm =").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_jwt-hack"))
        .args(["--json", "--config"])
        .arg(config)
        .arg("version")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["success"], false);
    let message = error["error"].as_str().unwrap();
    assert!(message.contains("Failed to parse config file"), "{message}");
    assert!(output.stderr.is_empty());
}
