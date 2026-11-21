use serde_json::Value;
use std::net::{Ipv4Addr, TcpListener};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn server_command(port: u16, config_dir: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jwt-hack"));
    command.env("XDG_CONFIG_HOME", config_dir).args([
        "--json",
        "server",
        "--port",
        &port.to_string(),
    ]);
    command
}

#[test]
fn json_server_reports_bind_failure_without_success() {
    let config_dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let output = server_command(port, config_dir.path()).output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["success"], false);
    assert!(response["error"]
        .as_str()
        .unwrap()
        .contains("Failed to bind"));
}

#[test]
fn json_server_reports_the_assigned_port() {
    let config_dir = tempfile::tempdir().unwrap();
    let mut child = server_command(0, config_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let reply = serde_json::Deserializer::from_reader(stdout)
            .into_iter::<Value>()
            .next();
        let _ = send.send(reply);
    });
    let reply = receive.recv_timeout(Duration::from_secs(15));
    let _ = child.kill();
    child.wait().unwrap();
    reader.join().unwrap();

    let response = reply.unwrap().unwrap().unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(response["mode"], "server");
    assert_eq!(response["host"], "127.0.0.1");
    assert_ne!(response["port"].as_u64().unwrap(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn server_json_output_write_failure_is_reported_on_stderr() {
    let config_dir = tempfile::tempdir().unwrap();
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let output = server_command(0, config_dir.path())
        .stdout(Stdio::from(sink))
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Failed to print JSON output"), "{stderr}");
}
