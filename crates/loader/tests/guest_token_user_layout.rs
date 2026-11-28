// SPDX-License-Identifier: GPL-3.0-or-later

//! Run `cargo test --locked --target aarch64-apple-darwin -p xenora-loader
//! --test guest_token_user_layout` on Apple Silicon. The original fixture
//! queries [TOKEN_USER] at two optimization levels and checks exact bounds.
//!
//! [TOKEN_USER]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_user

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use xenora_loader::probe::{ProbeConfig, probe_pe_bytes};
use xenora_loader::startup::{StartupLayout, run_synthetic_startup};
use xenora_loader::{
    ExitReason, ImportRegistry, MockClock, ServicesState, register_standard_services,
};

#[test]
fn token_user_reports_a_complete_amd64_header_and_sid() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("token-user-layout-{}", std::process::id()));
    let builder =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pe/token-user-layout/build.sh");
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
        let image = out.join(format!("token-user-layout-{optimization}.exe"));
        let bytes = std::fs::read(image).unwrap();
        let probe = probe_pe_bytes(&bytes, &ProbeConfig::default()).unwrap();
        assert_eq!(probe.import_error, None);
        for (module, symbol) in [
            ("advapi32.dll", "OpenProcessToken"),
            ("advapi32.dll", "GetTokenInformation"),
            ("kernel32.dll", "GetCurrentProcess"),
            ("kernel32.dll", "GetLastError"),
        ] {
            assert!(
                probe.imports.iter().any(|import| {
                    import.dll.eq_ignore_ascii_case(module) && import.symbol == symbol
                }),
                "{optimization}: missing {module}!{symbol}"
            );
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
