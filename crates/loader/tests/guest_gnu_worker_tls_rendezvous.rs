// SPDX-License-Identifier: GPL-3.0-or-later

//! Build on Apple Silicon with MinGW-w64 GCC and run with
//! `cargo test --locked --target aarch64-apple-darwin -p xenora-loader
//! --test guest_gnu_worker_tls_rendezvous`.
//!
//! Each thread has its own [C++ thread-local object]. A condition-variable
//! [sleep] releases the critical section and owns it again on return, even
//! after a timeout. The fixture uses GCC emulated storage for a scalar with
//! a dynamic initializer and exercises Xenora's scheduled guest threads.
//!
//! [C++ thread-local object]: https://eel.is/c++draft/basic.stc.thread
//! [sleep]: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepconditionvariablecs

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use xenora_loader::probe::{ProbeConfig, probe_pe_bytes};
use xenora_loader::startup::{StartupLayout, run_synthetic_startup_scheduled};
use xenora_loader::{
    Clock, ExitReason, ImportRegistry, MockClock, ServicesState, register_standard_services,
};

#[test]
fn gnu_workers_keep_their_compiler_initialized_tls_through_condition_waits() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("worker-tls-rendezvous-{}", std::process::id()));
    let builder = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pe/gnu-worker-tls-rendezvous/build.sh");
    let build = Command::new("sh").arg(&builder).arg(&out).output().unwrap();
    assert!(
        build.status.success(),
        "{} failed:\n{}\n{}",
        builder.display(),
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    for optimization in ["O1", "O2"] {
        let image = format!("worker-tls-{optimization}.exe");
        let bytes = std::fs::read(out.join(&image)).unwrap();
        let symbols =
            std::fs::read_to_string(out.join(format!("worker-tls-{optimization}.symbols")))
                .unwrap();
        for symbol in [
            "_ZTH5value",
            "__emutls_v.__tls_guard",
            "__emutls_v.value",
            "__emutls_get_address",
        ] {
            assert!(
                symbols
                    .lines()
                    .any(|line| line.split_whitespace().last() == Some(symbol)),
                "{image}: missing compiler-emitted {symbol}"
            );
        }
        let probe = probe_pe_bytes(&bytes, &ProbeConfig::default()).unwrap();
        assert_eq!(probe.import_error, None);
        for (module, symbol) in [
            ("libgcc_s_seh-1.dll", "__emutls_get_address"),
            ("kernel32.dll", "CreateThread"),
            ("kernel32.dll", "SleepConditionVariableCS"),
            ("kernel32.dll", "WakeConditionVariable"),
            ("kernel32.dll", "WakeAllConditionVariable"),
            ("kernel32.dll", "GetLastError"),
        ] {
            assert!(
                probe.imports.iter().any(|import| {
                    import.dll.eq_ignore_ascii_case(module) && import.symbol == symbol
                }),
                "{image}: missing {module}!{symbol}"
            );
        }

        let mut completed = Vec::new();
        for quantum in [64, 1024] {
            let clock = Arc::new(MockClock::new(0));
            let state = Arc::new(ServicesState::new(clock.clone()));
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
                20_000_000,
                quantum,
                |_| {},
            )
            .unwrap_or_else(|error| panic!("{image} quantum {quantum}: {error}"));
            assert_eq!(
                result.execution.exit_reason,
                ExitReason::ProcessExit(0),
                "{image} quantum {quantum}, stderr {:?}",
                String::from_utf8_lossy(&state.standard_error())
            );
            assert!(result.dbt_metrics.native_bytes_emitted > 0);
            // Both finite waits start before the scheduler advances the
            // clock. Five milliseconds is 50,000 ticks of 100 ns each.
            assert_eq!(
                clock.performance_count(),
                50_000,
                "{image} quantum {quantum}"
            );
            completed.push(state);
        }

        for state in completed {
            assert_eq!(state.exit_status(), Some(0));
            assert_eq!(
                state.standard_output(),
                b"tls: 17->101 29->202 43->303\r\nrendezvous: 2 workers, 2 timeouts\r\n"
            );
            assert!(state.standard_error().is_empty());
            assert_eq!(state.open_handle_count(), 0);
        }
    }
}
