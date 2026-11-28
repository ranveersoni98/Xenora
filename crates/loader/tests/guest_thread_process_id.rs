// SPDX-License-Identifier: GPL-3.0-or-later

//! Run `cargo test --locked --target aarch64-apple-darwin -p xenora-loader
//! --test guest_thread_process_id` on Apple Silicon. The original Win64
//! fixture checks [GetProcessIdOfThread] through normal guest imports at
//! two optimization levels, with real scheduled guest thread handles.
//!
//! [GetProcessIdOfThread]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessidofthread

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use xenora_loader::probe::{ProbeConfig, probe_pe_bytes};
use xenora_loader::startup::{StartupLayout, run_synthetic_startup_scheduled};
use xenora_loader::{
    ExitReason, ImportRegistry, MockClock, ServicesState, register_standard_services,
};

#[test]
fn get_process_id_of_thread_resolves_owned_handles_and_checks_rights() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("thread-process-id-{}", std::process::id()));
    let builder =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pe/thread-process-id/build.sh");
    let build = Command::new("sh").arg(&builder).arg(&out).output().unwrap();
    assert!(
        build.status.success(),
        "{} failed:\n{}\n{}",
        builder.display(),
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    for (optimization, process_id) in [("O1", 0x51a0), ("O2", 0x52a0)] {
        let image = format!("thread-process-id-{optimization}.exe");
        let bytes = std::fs::read(out.join(&image)).unwrap();
        let probe = probe_pe_bytes(&bytes, &ProbeConfig::default()).unwrap();
        assert_eq!(probe.import_error, None);
        assert!(probe.imports.iter().any(|import| {
            import.dll.eq_ignore_ascii_case("kernel32.dll")
                && import.symbol == "GetProcessIdOfThread"
        }));

        let mut state = ServicesState::new(Arc::new(MockClock::new(0)));
        state.process_id = process_id;
        let state = Arc::new(state);
        state.set_program_arguments(&[&image]).unwrap();
        let mut imports = ImportRegistry::new();
        register_standard_services(&mut imports, Arc::clone(&state));
        let result = run_synthetic_startup_scheduled(
            &bytes,
            StartupLayout {
                image_base: 0x2_5000_0000,
                stack_top: 0x2_0001_0000,
                tls_base: 0x3_0000_0000,
            },
            imports,
            Arc::clone(&state),
            1_000_000,
            64,
            |_| {},
        )
        .unwrap_or_else(|error| panic!("{image}: {error}"));
        assert_eq!(
            result.execution.exit_reason,
            ExitReason::ProcessExit(0),
            "{image}"
        );
        assert!(result.dbt_metrics.native_bytes_emitted > 0);
        assert_eq!(state.exit_status(), Some(0), "{image}");
        assert!(state.standard_error().is_empty(), "{image}");
        assert_eq!(state.open_handle_count(), 0, "{image}");
    }
}
