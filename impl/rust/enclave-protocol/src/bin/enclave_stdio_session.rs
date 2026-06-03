//! Multi-frame stdio session: reference host↔enclave transport for integration tests.
//!
//! Reads framed requests until EOF; maintains `HostSession` state in-process.
//! Requires `test-support` (+ `demo-mock-sign` for mock PQ signatures on SIGN).
//!
//! Export fixtures (stdout, one line hex):
//!   enclave-stdio-session export-arm-frame
//!   enclave-stdio-session export-recovery-sign-frame

use enclave_protocol::{
    process_framed_with_session, read_framed_message, sample_arm_for_production_frame,
    sample_recovery_sign_frame, write_framed_message, HostSession,
};
use std::env;
use std::io::{self, BufReader, Write};

fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-stdio-session: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        return export_fixture(&args[1]);
    }

    let mut session = HostSession::reference_test();
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = io::stdout().lock();

    loop {
        let frame = match read_framed_message(&mut reader) {
            Ok(f) => f,
            Err(enclave_protocol::ProtocolError::Io(e))
                if e.kind() == io::ErrorKind::UnexpectedEof =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        };
        let response = process_framed_with_session(&frame, &mut session)?;
        write_framed_message(&mut stdout, &response)?;
    }
    Ok(())
}

fn export_fixture(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let frame = match name {
        "export-arm-frame" => sample_arm_for_production_frame(),
        "export-recovery-sign-frame" => sample_recovery_sign_frame(),
        other => {
            eprintln!("unknown export: {other}");
            std::process::exit(2);
        }
    };
    println!("{}", hex::encode(frame));
    Ok(())
}