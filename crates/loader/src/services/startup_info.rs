// SPDX-License-Identifier: GPL-3.0-or-later

//! What a process was started with: its startup information and command line.
//!
//! Documented (Microsoft Learn, "GetStartupInfoW", "STARTUPINFOW",
//! "GetCommandLineW", "GetCommandLineA"): `GetStartupInfo` retrieves the
//! structure given when the process was created, and `GetCommandLine` returns
//! one string that belongs to the system, which a program must not free or
//! change. `GetCommandLineA` is that string converted to the process code page.
//!
//! Xenora's choice, because nothing public describes it: the process code page
//! is UTF-8; the command line is the program's arguments, quoted so that
//! Microsoft's documented rules for parsing C command-line arguments give them
//! back; and the strings live in the process heap. The host takes the place of
//! the creating process. There are no windows, consoles or standard handles, so
//! nothing acts on the startup information.

use super::{KERNEL32, ServicesState};
use crate::cpu::ExitReason;
use crate::imports::{ImportRegistry, ServiceStatus};
use crate::memory::{GuestMemory, MemoryError, PROCESS_HEAP};
use std::fmt;
use std::sync::{Arc, MutexGuard};

/// The API sets Microsoft lists for `GetStartupInfo`, `GetStartupInfoA` and
/// `GetStartupInfoW` together, without saying which holds which.
const STARTUP_APIS: [&str; 17] = [
    "api-ms-win-core-processthreads-l1-1-0.dll",
    "api-ms-win-core-processthreads-l1-1-1.dll",
    "api-ms-win-core-processthreads-l1-1-2.dll",
    "api-ms-win-core-processthreads-l1-1-3.dll",
    "api-ms-win-core-processthreads-l1-1-4.dll",
    "api-ms-win-core-processthreads-l1-1-5.dll",
    "api-ms-win-core-processthreads-l1-1-6.dll",
    "api-ms-win-core-processthreads-l1-1-7.dll",
    "api-ms-win-core-processthreads-l1-1-8.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
    "api-ms-win-downlevel-kernel32-l1-1-0.dll",
    "api-ms-win-downlevel-kernel32-l2-1-0.dll",
];
/// The same for `GetCommandLineA` and `GetCommandLineW`.
const COMMAND_LINE_APIS: [&str; 3] = [
    "api-ms-win-core-processenvironment-l1-1-0.dll",
    "api-ms-win-core-processenvironment-l1-2-0.dll",
    "api-ms-win-downlevel-kernel32-l1-1-0.dll",
];
const UCRT: &str = "ucrtbase.dll";
const UCRT_RUNTIME: &str = "api-ms-win-crt-runtime-l1-1-0.dll";

/// Size of `STARTUPINFOA` and `STARTUPINFOW` on x64, by the field order and
/// types in processthreadsapi.h and natural alignment.
const STARTUP_INFO_SIZE: usize = 104;
/// The UTF-16 unit limit of the `CreateProcessW` command line, including the
/// terminating NUL. Xenora also uses it for the desktop and title.
const MAX_STRING_UNITS: usize = 32_767;
const SW_SHOWDEFAULT: u16 = 10;

/// `STARTF_` flags (STARTUPINFOW documentation).
const USE_SHOW_WINDOW: u32 = 0x1;
const USE_STD_HANDLES: u32 = 0x100;
const USE_HOT_KEY: u32 = 0x200;
const TITLE_IS_LINK_NAME: u32 = 0x800;
const TITLE_IS_APP_ID: u32 = 0x1000;
const PREVENT_PINNING: u32 = 0x2000;
/// Every documented flag.
const KNOWN_FLAGS: u32 = 0xFF
    | USE_STD_HANDLES
    | USE_HOT_KEY
    | TITLE_IS_LINK_NAME
    | TITLE_IS_APP_ID
    | PREVENT_PINNING
    | 0x8000;

/// The startup information of the guest process, as `CreateProcess` would have
/// received it. The default is a process started with no flags and no strings.
///
/// The fields keep the documented names and meanings. The reserved members are
/// not here: they must be zero or null, and the guest sees that.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessStartupInfo {
    pub desktop: Option<String>,
    pub title: Option<String>,
    pub x: u32,
    pub y: u32,
    pub x_size: u32,
    pub y_size: u32,
    pub x_count_chars: u32,
    pub y_count_chars: u32,
    pub fill_attribute: u32,
    pub flags: u32,
    pub show_window: u16,
    /// Passed to the guest as they are. No guest handle table knows them.
    pub std_input: u64,
    pub std_output: u64,
    pub std_error: u64,
}

/// Why [`ServicesState::set_startup_info`] refused its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupInfoError {
    /// A string holds a NUL, which would end it early in the guest.
    ContainsNul,
    TooLong,
    /// A flag that is not documented.
    UnknownFlag,
    /// Flags documented as not usable together, or one without the flag it
    /// must be combined with.
    ConflictingFlags,
    /// `SW_SHOWDEFAULT` is documented as not allowed in `wShowWindow`.
    ShowDefault,
    /// The guest has already read its startup information.
    AlreadyRead,
}

impl fmt::Display for StartupInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContainsNul => "a startup string contains a NUL character",
            Self::TooLong => "a startup string exceeds 32,767 characters",
            Self::UnknownFlag => "the startup flags hold an undocumented flag",
            Self::ConflictingFlags => "the startup flags cannot be combined",
            Self::ShowDefault => "SW_SHOWDEFAULT is not a valid initial show state",
            Self::AlreadyRead => "the guest has already read its startup information",
        })
    }
}

impl std::error::Error for StartupInfoError {}

impl ProcessStartupInfo {
    fn check(&self) -> Result<(), StartupInfoError> {
        for text in [&self.desktop, &self.title].into_iter().flatten() {
            if text.contains('\0') {
                return Err(StartupInfoError::ContainsNul);
            }
            if text.encode_utf16().count() >= MAX_STRING_UNITS {
                return Err(StartupInfoError::TooLong);
            }
        }
        let flags = self.flags;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(StartupInfoError::UnknownFlag);
        }
        let both = |pair: u32| flags & pair == pair;
        if both(USE_STD_HANDLES | USE_HOT_KEY)
            || both(TITLE_IS_LINK_NAME | TITLE_IS_APP_ID)
            || flags & (PREVENT_PINNING | TITLE_IS_APP_ID) == PREVENT_PINNING
        {
            return Err(StartupInfoError::ConflictingFlags);
        }
        if flags & USE_SHOW_WINDOW != 0 && self.show_window == SW_SHOWDEFAULT {
            return Err(StartupInfoError::ShowDefault);
        }
        Ok(())
    }

    fn image(&self, desktop: u64, title: u64) -> [u8; STARTUP_INFO_SIZE] {
        let mut image = [0; STARTUP_INFO_SIZE];
        let mut put = |at: usize, bytes: &[u8]| image[at..at + bytes.len()].copy_from_slice(bytes);
        put(0, &(STARTUP_INFO_SIZE as u32).to_le_bytes());
        put(16, &desktop.to_le_bytes());
        put(24, &title.to_le_bytes());
        let words = [
            self.x,
            self.y,
            self.x_size,
            self.y_size,
            self.x_count_chars,
            self.y_count_chars,
            self.fill_attribute,
            self.flags,
        ];
        for (index, word) in words.into_iter().enumerate() {
            put(32 + 4 * index, &word.to_le_bytes());
        }
        put(64, &self.show_window.to_le_bytes());
        for (index, handle) in [self.std_input, self.std_output, self.std_error]
            .into_iter()
            .enumerate()
        {
            put(80 + 8 * index, &handle.to_le_bytes());
        }
        image
    }
}

/// How a string is stored in guest memory.
#[derive(Clone, Copy)]
enum Encoding {
    Narrow,
    Wide,
}

impl Encoding {
    fn bytes(self, text: &str) -> Vec<u8> {
        match self {
            Self::Narrow => text.bytes().chain([0]).collect(),
            Self::Wide => text
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
}

#[derive(Clone, Copy)]
struct StoredCommandLine {
    start: u64,
    argument_tail: u64,
}

/// Guest addresses of the strings already handed out, per [`Encoding`].
#[derive(Default)]
pub(super) struct StartupState {
    info: ProcessStartupInfo,
    /// Desktop and title. Null for a string that was not given.
    strings: [Option<(u64, u64)>; 2],
    command_line: [Option<StoredCommandLine>; 2],
}

fn store(memory: &mut GuestMemory, bytes: &[u8]) -> Result<u64, MemoryError> {
    let address = memory.map_heap_allocation(PROCESS_HEAP, bytes.len())?;
    memory.write_bytes(address, bytes)?;
    Ok(address)
}

/// Check the string the guest would receive, including escaping and its NUL.
pub(super) fn command_line_fits(arguments: &[&str]) -> bool {
    let (line, _) = command_line(arguments);
    line.encode_utf16().count() < MAX_STRING_UNITS
}

/// The command line whose documented C parse is `arguments`. The program name
/// takes no backslash or quote rules, so a quote in it cannot be represented
/// and is left out; a file name cannot hold one. The returned byte offset
/// marks the WinMain argument tail, or the end of the line when it is empty.
fn command_line(arguments: &[impl AsRef<str>]) -> (String, usize) {
    let Some((program, rest)) = arguments.split_first() else {
        return (String::new(), 0);
    };
    let blank = |text: &str| text.is_empty() || text.contains([' ', '\t']);
    let mut line: String = program
        .as_ref()
        .chars()
        .filter(|unit| *unit != '"')
        .collect();
    if blank(&line) {
        line = format!("\"{line}\"");
    }
    let arguments_offset = line.len() + usize::from(!rest.is_empty());
    for argument in rest {
        let argument = argument.as_ref();
        line.push(' ');
        if !blank(argument) && !argument.contains('"') {
            line.push_str(argument);
            continue;
        }
        line.push('"');
        let mut backslashes = 0;
        for unit in argument.chars() {
            if unit == '"' {
                // 2n+1 backslashes and a quote are n backslashes and a quote.
                line.extend(std::iter::repeat_n('\\', backslashes + 1));
            }
            backslashes = if unit == '\\' { backslashes + 1 } else { 0 };
            line.push(unit);
        }
        // 2n backslashes and the closing quote are n backslashes.
        line.extend(std::iter::repeat_n('\\', backslashes));
        line.push('"');
    }
    (line, arguments_offset)
}

impl ServicesState {
    /// Give the guest process the startup information its creator would have
    /// passed to `CreateProcess`. Call it before running the guest: once the
    /// guest has read it, a change is refused.
    pub fn set_startup_info(&self, info: ProcessStartupInfo) -> Result<(), StartupInfoError> {
        info.check()?;
        let mut startup = self.startup();
        if startup.strings.iter().any(Option::is_some) {
            return Err(StartupInfoError::AlreadyRead);
        }
        startup.info = info;
        Ok(())
    }

    fn startup(&self) -> MutexGuard<'_, StartupState> {
        self.startup.lock().expect("startup information")
    }

    fn get_startup_info(
        &self,
        memory: &mut GuestMemory,
        output: u64,
        encoding: Encoding,
    ) -> Result<(), MemoryError> {
        // Nothing is allocated for a structure that cannot be written.
        memory.check_write(output, STARTUP_INFO_SIZE)?;
        let mut startup = self.startup();
        let index = encoding as usize;
        if let Some((desktop, title)) = startup.strings[index] {
            return memory.write_bytes(output, &startup.info.image(desktop, title));
        }
        let mut place = |text: &Option<String>| match text {
            Some(text) => store(memory, &encoding.bytes(text)),
            None => Ok(0),
        };
        let desktop = place(&startup.info.desktop)?;
        let title = match place(&startup.info.title) {
            Ok(title) => title,
            Err(error) => {
                if desktop != 0 {
                    memory.release_heap_allocation(PROCESS_HEAP, desktop);
                }
                return Err(error);
            }
        };
        // Adding the strings does not change the output range already checked.
        memory.write_bytes(output, &startup.info.image(desktop, title))?;
        startup.strings[index] = Some((desktop, title));
        Ok(())
    }

    fn get_command_line(
        &self,
        memory: &mut GuestMemory,
        encoding: Encoding,
    ) -> Result<StoredCommandLine, MemoryError> {
        let mut startup = self.startup();
        if let Some(cached) = startup.command_line[encoding as usize] {
            return Ok(cached);
        }
        let (line, arguments_offset) = command_line(&self.crt_arguments().for_command_line());
        let offset = match encoding {
            Encoding::Narrow => arguments_offset,
            Encoding::Wide => line[..arguments_offset].encode_utf16().count() * 2,
        };
        let address = store(memory, &encoding.bytes(&line))?;
        let stored = StoredCommandLine {
            start: address,
            argument_tail: address + offset as u64,
        };
        startup.command_line[encoding as usize] = Some(stored);
        Ok(stored)
    }
}

pub(super) fn register(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    for (symbol, encoding) in [
        ("GetStartupInfoA", Encoding::Narrow),
        ("GetStartupInfoW", Encoding::Wide),
    ] {
        // It returns nothing and documents no failure, so a structure that
        // cannot be written stops the guest.
        let s = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, _, memory| {
            s.get_startup_info(memory, args.rcx, encoding)
                .map(|()| 0)
                .map_err(ExitReason::MemoryFault)
        });
        for api_set in STARTUP_APIS {
            registry.alias(api_set, KERNEL32, symbol);
        }
        // Partial: no window, console or handle follows from it.
        registry.set_status(KERNEL32, symbol, ServiceStatus::Partial);
    }
    for (symbol, encoding) in [
        ("GetCommandLineA", Encoding::Narrow),
        ("GetCommandLineW", Encoding::Wide),
    ] {
        let s = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |_, _, memory| {
            s.get_command_line(memory, encoding)
                .map(|line| line.start)
                .map_err(ExitReason::MemoryFault)
        });
        for api_set in COMMAND_LINE_APIS {
            registry.alias(api_set, KERNEL32, symbol);
        }
        // Partial: the process code page is always UTF-8.
        registry.set_status(KERNEL32, symbol, ServiceStatus::Partial);
    }
    let symbol = "_get_narrow_winmain_command_line";
    let s = Arc::clone(state);
    registry.register_with_status(UCRT, symbol, ServiceStatus::Partial, move |_, _, memory| {
        s.get_command_line(memory, Encoding::Narrow)
            .map(|line| line.argument_tail)
            .map_err(ExitReason::MemoryFault)
    });
    registry.alias(UCRT_RUNTIME, UCRT, symbol);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_startup_info_string_allocation_leaves_no_partial_result() {
        use crate::memory::{DYNAMIC_BUDGET, MemoryPermissions};
        use crate::services::MockClock;

        const OUTPUT: u64 = 0x1000;
        const RETRY_OUTPUT: u64 = OUTPUT + STARTUP_INFO_SIZE as u64;
        let variants: [(Encoding, &[u8], &[u8]); 2] = [
            (Encoding::Narrow, b"Desk\0", b"Window\0"),
            (
                Encoding::Wide,
                b"D\0e\0s\0k\0\0\0",
                b"W\0i\0n\0d\0o\0w\0\0\0",
            ),
        ];
        for (encoding, desktop, title) in variants {
            let state = ServicesState::new(Arc::new(MockClock::new(0)));
            state
                .set_startup_info(ProcessStartupInfo {
                    desktop: Some("Desk".into()),
                    title: Some("Window".into()),
                    ..Default::default()
                })
                .unwrap();
            let mut memory = GuestMemory::new();
            let sentinel = [0xA5; 2 * STARTUP_INFO_SIZE];
            memory
                .map_region_with_data(
                    OUTPUT,
                    sentinel.len(),
                    MemoryPermissions::READ_WRITE,
                    &sentinel,
                )
                .unwrap();

            // Leave enough heap space for one string's page, but not both.
            // Heap commits are page granular, so each string costs one page
            // whatever its byte length is.
            let pressure = memory
                .map_heap_allocation(PROCESS_HEAP, DYNAMIC_BUDGET as usize - 4096)
                .unwrap();
            assert_eq!(
                state.get_startup_info(&mut memory, OUTPUT, encoding),
                Err(MemoryError::AllocationFailed)
            );
            let mut unchanged = [0; 2 * STARTUP_INFO_SIZE];
            memory.read_bytes(OUTPUT, &mut unchanged).unwrap();
            assert_eq!(unchanged, sentinel);
            assert_eq!(state.startup().strings, [None, None]);
            let remaining = memory
                .map_heap_allocation(PROCESS_HEAP, desktop.len())
                .expect("the failed call must leave the original heap capacity available");
            assert!(memory.release_heap_allocation(PROCESS_HEAP, remaining));
            assert!(memory.release_heap_allocation(PROCESS_HEAP, pressure));

            state
                .get_startup_info(&mut memory, OUTPUT, encoding)
                .unwrap();
            assert_eq!(memory.read_u32(OUTPUT).unwrap(), STARTUP_INFO_SIZE as u32);
            let desktop_address = memory.read_u64(OUTPUT + 16).unwrap();
            let title_address = memory.read_u64(OUTPUT + 24).unwrap();
            for (address, expected) in [(desktop_address, desktop), (title_address, title)] {
                let mut contents = vec![0; expected.len()];
                memory.read_bytes(address, &mut contents).unwrap();
                assert_eq!(contents, expected);
            }
            state
                .get_startup_info(&mut memory, RETRY_OUTPUT, encoding)
                .unwrap();
            assert_eq!(memory.read_u64(RETRY_OUTPUT + 16).unwrap(), desktop_address);
            assert_eq!(memory.read_u64(RETRY_OUTPUT + 24).unwrap(), title_address);
        }
    }

    #[test]
    fn every_documented_startup_flag_is_known_and_no_other() {
        // STARTUPINFOW, dwFlags.
        let documented = [
            0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x800, 0x1000, 0x2000, 0x8000,
        ];
        assert_eq!(KNOWN_FLAGS, documented.iter().sum::<u32>());
    }
}
