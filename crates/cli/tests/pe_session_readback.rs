// SPDX-License-Identifier: GPL-3.0-or-later

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

fn readback_fixture() -> &'static Path {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let output = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("authored-session-readback-{}", std::process::id()));
        let builder = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/pe/authored-session-readback/build.sh");
        let build = Command::new("sh")
            .arg(builder)
            .arg(&output)
            .output()
            .expect("build authored readback fixture");
        assert!(build.status.success(), "{build:?}");
        output.join("authored-session-readback.exe")
    })
}

fn check_readback(backend: &str) {
    let guest = readback_fixture();
    let pin = format!("{:x}", Sha256::digest(std::fs::read(guest).unwrap()));
    let mut command = Command::new(env!("CARGO_BIN_EXE_xenora-pe-session"));
    command
        .arg("--pe")
        .arg(guest)
        .args(["--experimental", "--sha256", &pin, "--pixels"])
        .args(["--graphics-backend", backend]);
    let mut session = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start authored readback session");
    {
        let mut input = session.stdin.take().unwrap();
        input.write_all(b"10\n").expect("send frame input");
    }
    let outcome = session.wait_with_output().expect("wait for clean EOF");
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&outcome.stderr)
    );

    let red = [255, 0, 0, 255];
    let clear = [0x11, 0x22, 0x33, 255];
    let rgba = [red, clear, clear, clear].concat().repeat(3);
    let mut pixels = String::new();
    for byte in &rgba {
        write!(&mut pixels, "{byte:02x}").unwrap();
    }
    let digest = Sha256::digest(&rgba);
    assert_eq!(
        String::from_utf8(outcome.stdout).unwrap(),
        format!("ready\nframe 1 width=4 height=3 sha256={digest:x} rgba={pixels}\ndone frames=1\n")
    );
}

#[test]
fn authored_readback_requires_the_exact_requested_span() {
    check_readback("reference");
}

#[test]
#[ignore = "requires native Metal on Apple Silicon"]
fn authored_readback_matches_reference_on_native_metal() {
    check_readback("metal");
}
