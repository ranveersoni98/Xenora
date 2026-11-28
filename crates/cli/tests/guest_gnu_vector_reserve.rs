// SPDX-License-Identifier: GPL-3.0-or-later

//! Run `cargo test --locked --target aarch64-apple-darwin -p xenora --test
//! guest_gnu_vector_reserve` on Apple Silicon with native MinGW-w64 GCC.
//! `sh fixtures/pe/gnu-vector-reserve/build.sh OUTPUT -O1` builds the original
//! guest and records its installed libgcc path. Repeat with `-O2`.
//!
//! A copy constructor throws during vector growth. The C++ [reserve contract]
//! requires the original elements and storage to survive. The guest checks
//! rollback and retry before printing its final lifetime counts. Omitting the
//! unwinder gives an independent pre-entry startup control.
//!
//! [reserve contract]: https://eel.is/c++draft/vector.capacity

use std::path::Path;
use std::process::{Command, Output};

const EXPECTED: &[u8] = b"vector: throw rollback, retry, 7 constructions and 7 destructions\r\n";

fn run(guest: &Path, unwinder: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xenora"));
    command
        .args([
            "run",
            "--experimental",
            "--startup-report",
            "--max-steps",
            "1000000",
            "--wall-seconds",
            "8",
            "--pe",
        ])
        .arg(guest);
    if let Some(unwinder) = unwinder {
        command.arg("--package").arg(unwinder);
    }
    command.output().expect("run the original GNU C++ guest")
}

#[test]
fn compiled_vector_retains_its_elements_after_a_throwing_copy() {
    let builder =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pe/gnu-vector-reserve/build.sh");
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("gnu-vector-reserve-{}", std::process::id()));

    for optimization in ["-O1", "-O2"] {
        let output = directory.join(optimization);
        let build = Command::new("sh")
            .arg(&builder)
            .arg(&output)
            .arg(optimization)
            .output()
            .expect("build GNU C++ fixture with native tools");
        assert!(
            build.status.success(),
            "{optimization} build failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr),
        );
        let guest = output.join("gnu-vector-reserve.exe");
        let runtime_path = std::fs::read_to_string(output.join("unwinder-path.txt"))
            .expect("read the installed GNU unwinder path");
        let unwinder = Path::new(runtime_path.trim_end_matches(['\r', '\n']));
        for dependency in [Some(unwinder), None, Some(unwinder)] {
            let run = run(&guest, dependency);
            let diagnostics = String::from_utf8(run.stderr).expect("CLI emits UTF-8 diagnostics");
            let report = diagnostics
                .lines()
                .find_map(|line| line.strip_prefix("xenora-startup "))
                .unwrap_or_else(|| panic!("{optimization}: missing startup report: {diagnostics}"));
            if dependency.is_some() {
                assert_eq!(run.status.code(), Some(0), "{optimization}: {diagnostics}");
                assert_eq!(run.stdout, EXPECTED, "{optimization}");
                assert!(report.contains(r#""last_completed_stage":"entry_returned""#));
                assert!(report.contains(r#""kind":"guest_exit","guest_status":0"#));
            } else {
                assert_eq!(
                    run.status.code(),
                    Some(125),
                    "{optimization}: {diagnostics}"
                );
                assert!(run.stdout.is_empty(), "{optimization}");
                assert!(report.contains(
                    "unresolved import dependency: libgcc_s_seh-1.dll!_GCC_specific_handler"
                ));
                assert!(report.contains(r#""last_completed_stage":"relocated""#));
                assert!(report.contains(r#""kind":"known_failure","phase":"startup""#));
                assert!(!report.contains(r#""stage":"entry_started""#));
            }
        }
    }
}
