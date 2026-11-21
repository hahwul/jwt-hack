use anyhow::Result;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: error.into(),
        }
    }
}

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = serde_json::to_writer_pretty(&mut handle, value) {
        if e.io_error_kind() == Some(io::ErrorKind::BrokenPipe) {
            return Ok(());
        }
        return Err(e.into());
    }

    if let Err(e) = writeln!(&mut handle) {
        if e.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(e.into());
    }
    Ok(())
}

pub fn print_json_or_exit<T: Serialize>(value: &T) {
    if let Err(error) = print_json(value) {
        log::error!("Failed to print JSON output: {error}");
        std::process::exit(1);
    }
}
