// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use xenora_loader::cpu::ExitReason;
use xenora_loader::imports::ImportRegistry;
use xenora_loader::probe::{ProbeConfig, probe_pe_bytes};
use xenora_loader::services::{MockClock, ServicesState, register_standard_services};
use xenora_loader::startup::{StartupLayout, run_synthetic_startup};

const PE: &[u8] = include_bytes!("../../../fixtures/pe/rtl-unwind-abi/rtl-unwind-abi.exe");

#[test]
fn compiled_guest_captures_and_unwinds_one_relocated_frame() {
    let report = probe_pe_bytes(PE, &ProbeConfig::default()).unwrap();
    assert_eq!(report.import_error, None);
    for symbol in [
        "RtlCaptureContext",
        "RtlLookupFunctionEntry",
        "RtlVirtualUnwind",
    ] {
        assert_eq!(
            report
                .imports
                .iter()
                .filter(|entry| entry.dll == "kernel32.dll" && entry.symbol == symbol)
                .count(),
            1,
            "exact import kernel32.dll!{symbol}"
        );
    }

    for image_base in [0x1_5000_0000, 0x2_5000_0000] {
        let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
        let mut registry = ImportRegistry::new();
        register_standard_services(&mut registry, state);
        let layout = StartupLayout {
            image_base,
            stack_top: 0x2_0001_0000,
            tls_base: 0x3_0000_0000,
        };
        let run = run_synthetic_startup(PE, layout, registry, 100_000).unwrap();
        assert_eq!(run.bound_imports, 4);
        assert_ne!(run.relocations.delta, 0);
        assert!(run.relocations.applied_dir64 > 0);
        assert_eq!(
            run.execution.exit_reason,
            ExitReason::ProcessExit(0),
            "guest unwind check failed at image base {image_base:#x}"
        );
    }
}
