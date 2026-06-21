//! One-shot stdio adapter: read one framed request from stdin, write one framed response to stdout.
//!
//! Used by the Elixir host shim (`impl/elixir-shim`) for local integration tests before real vsock.
//! Build: `cargo build --bin enclave-stdio-bridge`

use enclave_protocol::{process_framed_bytes, read_framed_message};
use std::io::{self, Write};

fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-stdio-bridge: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = io::stdin().lock();
    let frame = read_framed_message(&mut stdin)?;
    let response = process_framed_bytes(&frame)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&response)?;
    stdout.flush()?;
    Ok(())
}
