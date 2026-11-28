// SPDX-License-Identifier: GPL-3.0-or-later

//! Build and run the original A/W console cell fixture at -O1 and -O2.
//! Run `cargo test --locked --target aarch64-apple-darwin -p xenora-loader
//! --test guest_console_ansi_cell`.
//! The [CHAR_INFO] union contains a one-byte ANSI character and a two-byte
//! wide character. The test seeds the second byte before the ANSI write and
//! reads through the wide API so the character and attributes are independent.
//!
//! [CHAR_INFO]: https://learn.microsoft.com/en-us/windows/console/char-info-str

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use xenora_loader::probe::{ProbeConfig, probe_pe_bytes};
use xenora_loader::startup::{StartupLayout, run_synthetic_startup};
use xenora_loader::{
    ExitReason, ImportRegistry, MockClock, ServicesState, register_standard_services,
};

#[test]
fn ansi_console_write_uses_only_the_character_byte() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("console-ansi-cell-{}", std::process::id()));
    let builder =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pe/console-ansi-cell/build.sh");
    let build = Command::new("sh").arg(&builder).arg(&out).output().unwrap();
    assert!(
        build.status.success(),
        "{} failed:\n{}\n{}",
        builder.display(),
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let mut outcomes = Vec::new();
    for optimization in ["O1", "O2"] {
        let image = out.join(format!("console-ansi-cell-{optimization}.exe"));
        let bytes = std::fs::read(image).unwrap();
        let probe = probe_pe_bytes(&bytes, &ProbeConfig::default()).unwrap();
        assert_eq!(probe.import_error, None);
        for symbol in [
            "CreateConsoleScreenBuffer",
            "WriteConsoleOutputA",
            "WriteConsoleOutputW",
            "ReadConsoleOutputW",
            "CloseHandle",
            "ExitProcess",
        ] {
            assert!(probe.imports.iter().any(|import| {
                import.dll.eq_ignore_ascii_case("kernel32.dll") && import.symbol == symbol
            }));
        }
        let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
        let mut imports = ImportRegistry::new();
        register_standard_services(&mut imports, Arc::clone(&state));
        let result = run_synthetic_startup(
            &bytes,
            StartupLayout {
                image_base: 0x2_5000_0000,
                stack_top: 0x2_0001_0000,
                tls_base: 0x3_0000_0000,
            },
            imports,
            1_000_000,
        )
        .unwrap_or_else(|error| panic!("{optimization}: {error}"));
        assert!(result.dbt_metrics.native_bytes_emitted > 0);
        outcomes.push((
            optimization,
            result.execution.exit_reason,
            state.exit_status(),
        ));
    }
    assert_eq!(
        outcomes,
        [
            ("O1", ExitReason::ProcessExit(0), Some(0)),
            ("O2", ExitReason::ProcessExit(0), Some(0)),
        ]
    );
}
