//! One-shot stdio adapter: read one framed request from stdin, write one framed response to stdout.
//!
//! Used by the Elixir host shim (`impl/elixir-shim`) for local integration tests before real vsock.
//! Build: `cargo build --bin enclave-stdio-bridge`

use enclave_protocol::process_framed_bytes;
use std::io::{self, Read, Write};

fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-stdio-bridge: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = io::stdin().lock();
    let mut len_buf = [0u8; 4];
    stdin.read_exact(&mut len_buf)?;
    let total_len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; total_len];
    stdin.read_exact(&mut body)?;

    let mut frame = Vec::with_capacity(4 + total_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&body);

    let response = process_framed_bytes(&frame)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&response)?;
    stdout.flush()?;
    Ok(())
}