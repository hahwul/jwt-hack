use std::process::Command;

#[cfg(unix)]
#[test]
fn reports_errors_resolving_the_default_config_path() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join("jwt-hack");
    std::fs::create_dir(&config_dir).unwrap();
    std::os::unix::fs::symlink("config.toml", config_dir.join("config.toml")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_jwt-hack"))
        .env("XDG_CONFIG_HOME", dir.path())
        .arg("version")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Failed to read config file"), "{stderr}");
}

#[test]
fn missing_default_config_still_uses_builtin_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jwt-hack"))
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["--json", "encode", "{}"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["algorithm"], "HS256");
}
