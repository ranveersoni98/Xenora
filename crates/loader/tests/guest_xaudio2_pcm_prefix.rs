// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use xenora_loader::cpu::ExitReason;
use xenora_loader::imports::ImportRegistry;
use xenora_loader::probe::{ProbeConfig, probe_pe_bytes};
use xenora_loader::services::{MockClock, ServicesState, register_standard_services};
use xenora_loader::startup::{StartupLayout, run_synthetic_startup};

const PE: &[u8] = include_bytes!("../../../fixtures/pe/xaudio2-pcm-prefix/xaudio2-pcm-prefix.exe");

#[test]
fn source_voice_reads_only_the_format_bytes_required_by_its_tag() {
    let report = probe_pe_bytes(PE, &ProbeConfig::default()).unwrap();
    assert_eq!(report.import_error, None);
    for (dll, symbol) in [
        ("xaudio2_9.dll", "XAudio2Create"),
        ("kernel32.dll", "VirtualAlloc"),
        ("kernel32.dll", "VirtualFree"),
    ] {
        assert_eq!(
            report
                .imports
                .iter()
                .filter(|entry| entry.dll == dll && entry.symbol == symbol)
                .count(),
            1,
            "{dll}!{symbol}"
        );
    }

    let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
    let mut registry = ImportRegistry::new();
    register_standard_services(&mut registry, Arc::clone(&state));
    let layout = StartupLayout {
        image_base: 0x2_5000_0000,
        stack_top: 0x2_0001_0000,
        tls_base: 0x3_0000_0000,
    };
    let run = run_synthetic_startup(PE, layout, registry, 100_000).unwrap();
    assert_eq!(
        run.execution.exit_reason,
        ExitReason::ProcessExit(0),
        "a nonzero guest exit identifies the fixture source line"
    );
    let diagnostics = state.xaudio2_diagnostics();
    assert_eq!(diagnostics.engines, 0);
    assert_eq!(diagnostics.mastering_voices, 0);
    assert_eq!(diagnostics.source_voices, 0);
}
