#[cfg(unix)]
#[test]
fn native_config_path_reaches_config_loader() {
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let config = dir
        .path()
        .join(std::ffi::OsStr::from_bytes(b"config-\xff.toml"));
    let output = Command::new(env!("CARGO_BIN_EXE_jwt-hack"))
        .arg("--config")
        .arg(config)
        .arg("version")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Failed to read config file"), "{stderr}");
}
