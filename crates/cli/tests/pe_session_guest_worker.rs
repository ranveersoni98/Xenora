// SPDX-License-Identifier: GPL-3.0-or-later

//! Keep a guest worker and its journal live across authored PE input boundaries.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const INPUTS: [u32; 3] = [10, 0x8123_4715, 10];
const REPORT_DEADLINE: Duration = Duration::from_secs(20);

fn guest() -> &'static Path {
    static GUEST: OnceLock<PathBuf> = OnceLock::new();
    GUEST.get_or_init(|| {
        let output = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("authored-session-worker-{}", std::process::id()));
        let builder = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/pe/authored-session-worker/build.sh");
        let build = Command::new("sh")
            .arg(builder)
            .arg(&output)
            .output()
            .unwrap();
        assert!(build.status.success(), "{build:?}");
        output.join("authored-session-worker.exe")
    })
}

fn expected_frame(sequence: u8, input: u32) -> String {
    let [red, second, third, fourth] = input.to_le_bytes();
    let blue = (0x40 + sequence) ^ second ^ third ^ fourth;
    let clear = [red, sequence, blue, 255];
    let mut row = [clear; 4];
    row[if input & 1 == 0 { 0 } else { 3 }] = [255, 0, 0, 255];
    let rgba = [row; 3];
    let bytes = rgba.as_flattened().as_flattened();
    let digest = Sha256::digest(bytes);
    let mut line = format!("frame {sequence} width=4 height=3 sha256={digest:x} rgba=");
    for byte in bytes {
        write!(line, "{byte:02x}").unwrap();
    }
    line
}

fn expect_report(reports: &Receiver<String>, expected: &str) -> Result<(), String> {
    let report = reports
        .recv_timeout(REPORT_DEADLINE)
        .map_err(|error| format!("waiting for {expected}: {error}"))?;
    if report != expected {
        return Err(format!("expected {expected:?}, got {report:?}"));
    }
    Ok(())
}

fn exercise_session(backend: &str, inputs: &[u32]) {
    let image = guest();
    let digest = format!("{:x}", Sha256::digest(std::fs::read(image).unwrap()));
    let mut session = Command::new(env!("CARGO_BIN_EXE_xenora-pe-session"))
        .args([
            "--experimental",
            "--deterministic-clock",
            "--pixels",
            "--pe",
        ])
        .arg(image)
        .args(["--sha256", &digest, "--graphics-backend", backend])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = session.stdin.take().unwrap();
    let stdout = session.stdout.take().unwrap();
    let mut stderr = session.stderr.take().unwrap();
    let (report_tx, reports) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if report_tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let diagnostics = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });

    let result = (move || {
        expect_report(&reports, "ready")?;
        for (index, &value) in inputs.iter().enumerate() {
            writeln!(&mut input, "{value}").map_err(|error| error.to_string())?;
            expect_report(&reports, &expected_frame((index + 1) as u8, value))?;
        }
        drop(input);
        expect_report(&reports, &format!("done frames={}", inputs.len()))?;
        Ok::<_, String>(reports)
    })();

    if result.is_err() {
        let _ = session.kill();
    }
    let status = session.wait().unwrap();
    reader.join().unwrap();
    let diagnostics = diagnostics.join().unwrap();
    let stderr = String::from_utf8_lossy(&diagnostics);
    let reports = result.unwrap_or_else(|error| panic!("{backend}: {error}\n{stderr}"));
    assert!(status.success(), "{backend}: {status}\n{stderr}");
    assert!(
        reports.try_recv().is_err(),
        "reports followed the terminal done"
    );
}

#[test]
fn guest_worker_journals_and_supplies_pixels_across_inputs() {
    exercise_session("reference", &INPUTS);
    exercise_session("reference", &INPUTS);
    exercise_session("reference", &[]);
}

#[test]
#[ignore = "requires native Metal on Apple Silicon"]
fn guest_worker_pixels_match_on_native_metal() {
    exercise_session("metal", &INPUTS);
}
