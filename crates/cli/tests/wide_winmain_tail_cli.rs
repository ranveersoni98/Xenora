// SPDX-License-Identifier: GPL-3.0-or-later

//! Verify the ANSI and UTF-16 command tails through an original GUI guest.

use std::path::PathBuf;
use std::process::Command;
use xenora_loader::probe::{ProbeConfig, probe_pe_bytes};

const PE: &[u8] = include_bytes!("../../../fixtures/pe/wide-winmain-tail/wide-winmain-tail.exe");
const GUI_SUBSYSTEM: u16 = 2;
const PE_HEADER_POINTER: usize = 0x3c;
const SUBSYSTEM_FROM_PE_HEADER: usize = 24 + 68;

#[test]
fn gui_guest_receives_both_winmain_command_tails() {
    let report = probe_pe_bytes(PE, &ProbeConfig::default()).expect("inspect GUI fixture");
    assert_eq!(report.import_error, None);
    for symbol in [
        "_get_wide_winmain_command_line",
        "_get_narrow_winmain_command_line",
    ] {
        let imports: Vec<_> = report
            .imports
            .iter()
            .filter(|entry| entry.symbol == symbol)
            .collect();
        assert_eq!(imports.len(), 1, "{symbol}");
        assert_eq!(imports[0].dll, "api-ms-win-crt-runtime-l1-1-0.dll");
    }
    let pe_header = u32::from_le_bytes(
        PE[PE_HEADER_POINTER..PE_HEADER_POINTER + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let subsystem = pe_header + SUBSYSTEM_FROM_PE_HEADER;
    assert_eq!(
        u16::from_le_bytes(PE[subsystem..subsystem + 2].try_into().unwrap()),
        GUI_SUBSYSTEM
    );

    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("wide-winmain-tail-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create fixture directory");
    let guest = directory.join("Wide Root 🧪.exe");
    std::fs::write(&guest, PE).expect("write GUI fixture with non-BMP filename");

    for (arguments, status) in [
        (&[][..], 41),
        (&[""][..], 42),
        (
            &["A 🚀", "", "say\"hello", "path end \\", "a\tb", "--trace"][..],
            43,
        ),
        (&[][..], 41),
    ] {
        let run = Command::new(env!("CARGO_BIN_EXE_xenora"))
            .args(["run", "--experimental", "--startup-report", "--pe"])
            .arg(&guest)
            .arg("--")
            .args(arguments)
            .output()
            .expect("run GUI fixture");
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(run.status.code(), Some(status), "{arguments:?}\n{stderr}");
        assert!(
            stderr.contains(&format!(
                r#""kind":"guest_exit","guest_status":{status},"worker_code":{status}"#
            )),
            "{arguments:?}\n{stderr}"
        );
        assert!(stderr.contains(r#""last_completed_stage":"entry_returned""#));
    }
}
