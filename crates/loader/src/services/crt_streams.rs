// SPDX-License-Identifier: GPL-3.0-or-later

//! The streams of a hosted C program, and where their output goes.
//!
//! `__acrt_iob_func` hands out the `FILE` objects for `stdin`, `stdout` and
//! `stderr`. What the guest writes to `stdout` and to `stderr` is kept in two
//! host-side buffers that a host or a test reads through `ServicesState`.
//!
//! The standard streams "always open in text mode by default", and in text
//! mode "each line feed is replaced with a carriage return-line feed pair"
//! that "has no effect on the return value" (Microsoft Learn, "Text and
//! binary mode file I/O" and "fwrite"). The buffers hold the bytes after that
//! replacement, which is what the operating system would be handed.
//!
//! A stream that `fopen` returned is a file on the in-memory drive; its rules
//! are in `crt_files.rs`.
//!
//! Output is never held back: there is no buffering to flush or to configure.
//! A pointer that is no stream, reading `stdin` and closing a standard stream
//! are not modelled and stop the guest with the runtime-limit fault.

use super::crt_files::{self, EACCES, EBADF, EEXIST, EINVAL, ENOENT, ENOSPC, ERANGE, FileStreams};
use super::crt_format::{self, Floats, FormatError, Source};
use super::crt_scan;
use super::files::DriveEntry;
use super::{ObjectState, ServicesState};
use crate::cpu::ExitReason;
use std::sync::Arc;

/// The legacy CRT module that pre-UCRT mingw binaries import directly.
const MSVCRT: &str = "msvcrt.dll";
use crate::imports::{ImportRegistry, Win64Args};
use crate::memory::{GuestMemory, MemoryError, PROCESS_HEAP};

/// The exit for a request the runtime does not model.
const RUNTIME_LIMIT: ExitReason = ExitReason::IllegalInstruction(0xFE);
/// Windows x64 internal standard-stream allocation: the public FILE is its
/// first pointer-sized member. The first three fields are the live unbuffered
/// pointer, base and count; the remaining fields reserve the CRT object layout.
const FILE_BYTES: u64 = 88;
/// The most a format string or one `fwrite` or `fputs` may hold.
const MAX_TRANSFER: u64 = 1 << 20;
/// The longest file name or mode string `fopen` reads, in bytes.
const MAX_NAME: u64 = 260;
/// The most each captured stream keeps. Writing past it stops the guest.
pub const MAX_CAPTURED_OUTPUT: usize = 16 << 20;

/// Option bits of `__stdio_common_vfprintf` (corecrt_stdio_config.h). The
/// wide-specifier bit concerns the wide functions and changes nothing this
/// engine formats. The other two say how floating point is written. Any
/// other bit stops the guest.
const LEGACY_WIDE_SPECIFIERS: u64 = 0x04;
const LEGACY_THREE_DIGIT_EXPONENTS: u64 = 0x10;
const STANDARD_ROUNDING: u64 = 0x20;
/// `__stdio_common_vsprintf` only: which termination and result rules of the
/// buffer forms apply (corecrt_stdio_config.h). The generated code of a
/// mingw-w64 `snprintf` or `sprintf` passes the standard bit, and `_snprintf`
/// the legacy one. Setting both contradicts itself and stops the guest.
const LEGACY_VSPRINTF_NULL_TERMINATION: u64 = 0x01;
const STANDARD_SNPRINTF_BEHAVIOR: u64 = 0x02;
const KNOWN_OPTIONS: u64 = LEGACY_WIDE_SPECIFIERS
    | LEGACY_THREE_DIGIT_EXPONENTS
    | STANDARD_ROUNDING
    | LEGACY_VSPRINTF_NULL_TERMINATION
    | STANDARD_SNPRINTF_BEHAVIOR;

/// `_IOFBF`, `_IOLBF` and `_IONBF` (stdio.h).
const IOFBF: i32 = 0x0000;
const IOLBF: i32 = 0x0040;
const IONBF: i32 = 0x0004;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stream {
    Input,
    Output,
    Error,
    /// A stream `fopen` returned, by the address of its `FILE` object.
    File(u64),
}

#[derive(Default)]
pub(super) struct StandardStreams {
    /// Guest address of the three `FILE` objects, `stdin` first.
    files: Option<u64>,
    /// Guest address of the legacy CRT's `__iob_func` array: three 48-byte
    /// `_iobuf` objects. Allocated on first use, as on Windows.
    legacy_files: Option<u64>,
    output: Vec<u8>,
    error: Vec<u8>,
    /// The streams `fopen` has open.
    opened: FileStreams,
    /// Guest blocks that the services returning memory hand out.
    scratch: Scratch,
    /// What the guest reads from `stdin` (#467).
    input: Input,
    /// The static buffer `tmpnam` uses when its argument is null, allocated
    /// once, as the CRT keeps one.
    temporary_static: u64,
    /// The orientations of the two captured outputs, as on the file
    /// streams: 0 unoriented, 1 byte, 2 wide.
    output_orientation: u8,
    error_orientation: u8,
    /// The process working directory, in the drive's lowercase
    /// backslash-separated key form with the empty string as the volume
    /// root. One process owns one, exactly as Windows shares the current
    /// directory between the CRT and the kernel file surface: `_chdir`
    /// moves it, a spawned child inherits a copy of it, and relative file
    /// paths resolve against it (#1336).
    cwd: String,
}

/// The standard input: bytes the host supplied before the run, after the
/// text-mode replacement of CR LF with LF. It is bounded so that a run stays
/// deterministic; the limit is the CLI's, not the runtime's.
#[derive(Default)]
struct Input {
    bytes: Vec<u8>,
    position: usize,
    /// The C orientation, as on the file streams: 0 unoriented, 1 byte,
    /// 2 wide.
    orientation: u8,
    /// The end-of-file indicator: set when a read meets the end, cleared by
    /// nothing here because there is no `rewind` or `clearerr` yet.
    eof: bool,
}

impl Input {
    /// Up to `limit` bytes, consuming them, for `_read` on descriptor 0.
    /// Meeting the end sets the indicator.
    fn take(&mut self, limit: usize) -> Vec<u8> {
        let count = limit.min(self.bytes.len() - self.position);
        let out = self.bytes[self.position..self.position + count].to_vec();
        self.position += count;
        if count == 0 {
            self.eof = true;
        }
        out
    }

    fn orient(&mut self, wide: bool) -> bool {
        let wanted = if wide { 2 } else { 1 };
        if self.orientation == 0 {
            self.orientation = wanted;
        }
        self.orientation == wanted
    }

    /// One character, or none at the end. Meeting the end sets the
    /// indicator, even when characters came before it in the same read.
    fn character(&mut self) -> Option<u8> {
        match self.bytes.get(self.position) {
            Some(&byte) => {
                self.position += 1;
                Some(byte)
            }
            None => {
                self.eof = true;
                None
            }
        }
    }

    /// `fgets`: at most `limit` characters, stopping after a line feed,
    /// which is kept. Nothing at the end of file.
    fn line(&mut self, limit: usize) -> Option<Vec<u8>> {
        if !self.orient(false) {
            return None;
        }
        let mut line = Vec::new();
        while line.len() < limit {
            match self.character() {
                Some(byte) => {
                    line.push(byte);
                    if byte == b'\n' {
                        break;
                    }
                }
                None => break,
            }
        }
        if line.is_empty() { None } else { Some(line) }
    }
}

/// Guest blocks in the process heap that the C runtime services which return
/// memory write into. A block stays valid until the next call that fills it
/// again, which is what the documentation of `strerror` asks for.
#[derive(Default)]
struct Scratch {
    /// The block `strerror` writes its message into, and its size.
    message: Option<(u64, u64)>,
    /// The block `localeconv` returns.
    locale: Option<u64>,
}

/// What a service returns when it fails with a result and an `errno` value:
/// the handler sets `errno` to the second field and returns the first.
pub(super) struct Failed<T>(pub T, pub u32);

pub(super) type Outcome<T> = Result<Result<T, Failed<T>>, ExitReason>;

pub(super) fn fault(error: MemoryError) -> ExitReason {
    ExitReason::MemoryFault(error)
}

/// The bytes of the C string at `address`, without its terminator.
impl StandardStreams {
    /// A narrow file name resolved against the working directory, exactly
    /// as the CRT resolves relative paths against it on Windows (#1336).
    fn drive_name_resolved(
        &self,
        memory: &GuestMemory,
        name: u64,
    ) -> Result<Option<Option<String>>, ExitReason> {
        if name == 0 {
            return Ok(None);
        }
        let bytes = c_string(memory, name, MAX_NAME + 1).map_err(fault)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_NAME {
            return Ok(None);
        }
        Ok(Some(self.resolve_path(&bytes)))
    }

    /// The wide form of `drive_name_resolved`, ASCII like the wide names
    /// the CRT wide file services take.
    fn drive_name_wide_resolved(
        &self,
        memory: &GuestMemory,
        name: u64,
    ) -> Result<Option<Option<String>>, ExitReason> {
        if name == 0 {
            return Ok(None);
        }
        let mut units = Vec::new();
        for index in 0..MAX_NAME + 1 {
            let unit = memory.read_u16(name + index * 2).map_err(fault)?;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        if units.len() as u64 > MAX_NAME || units.is_empty() {
            return Ok(None);
        }
        if !units.iter().all(|&unit| unit < 0x80) {
            return Ok(Some(None));
        }
        let bytes: Vec<u8> = units.iter().map(|&unit| unit as u8).collect();
        Ok(Some(self.resolve_path(&bytes)))
    }
}

/// The bytes of a wide mode string, ASCII like the narrow one.
fn wide_ascii(memory: &GuestMemory, address: u64, limit: u64) -> Result<Vec<u8>, MemoryError> {
    let mut units = Vec::new();
    for index in 0..limit {
        let unit = memory.read_u16(address + index * 2)?;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if !units.iter().all(|&unit| unit < 0x80) {
        return Err(MemoryError::UnmappedAddress(0));
    }
    Ok(units.iter().map(|&unit| unit as u8).collect())
}

pub(super) fn c_string(
    memory: &GuestMemory,
    address: u64,
    limit: u64,
) -> Result<Vec<u8>, MemoryError> {
    let mut bytes = Vec::new();
    for offset in 0..limit {
        let at = address.checked_add(offset).ok_or(MemoryError::Overflow)?;
        match memory.read_u8(at)? {
            0 => break,
            byte => bytes.push(byte),
        }
    }
    Ok(bytes)
}

/// Arguments from the guest's `va_list`: one 8-byte slot each, in order.
struct VaList<'a> {
    memory: &'a GuestMemory,
    next: u64,
}

impl Source for VaList<'_> {
    fn argument(&mut self) -> Result<u64, MemoryError> {
        let slot = self.memory.read_u64(self.next)?;
        self.next = self.next.checked_add(8).ok_or(MemoryError::Overflow)?;
        Ok(slot)
    }

    fn string(&mut self, address: u64, limit: usize) -> Result<Vec<u8>, MemoryError> {
        c_string(self.memory, address, limit as u64)
    }
}

/// What one format string and its arguments make.
enum Formatted {
    Text(Vec<u8>),
    /// The format itself is invalid: `%n` or a character that has no meaning
    /// as a type. Windows calls the invalid parameter handler; each caller
    /// says what it does when execution continues.
    Invalid,
}

/// Reads the format string and formats it with the arguments at `arguments`,
/// or explains why not. Shared by the stream and the buffer forms.
fn formatted(
    memory: &GuestMemory,
    options: u64,
    format: u64,
    locale: u64,
    arguments: u64,
    buffer_options: bool,
) -> Result<Formatted, ExitReason> {
    let mut source = VaList {
        memory,
        next: arguments,
    };
    format_with(memory, options, format, locale, &mut source, buffer_options)
}

/// [`formatted`] with the argument source the caller supplies: the legacy
/// variadic forms read their arguments from the calling convention rather
/// than a `va_list` in memory.
fn format_with(
    memory: &GuestMemory,
    options: u64,
    format: u64,
    locale: u64,
    source: &mut dyn Source,
    buffer_options: bool,
) -> Result<Formatted, ExitReason> {
    // The behaviour bits belong to the buffer forms; passing them to a
    // stream form stops the guest, as an unknown bit does.
    let known = if buffer_options {
        KNOWN_OPTIONS
    } else {
        KNOWN_OPTIONS & !(LEGACY_VSPRINTF_NULL_TERMINATION | STANDARD_SNPRINTF_BEHAVIOR)
    };
    if options & !known != 0 || locale != 0 {
        return Err(RUNTIME_LIMIT);
    }
    let template = c_string(memory, format, MAX_TRANSFER + 1).map_err(fault)?;
    if template.len() as u64 > MAX_TRANSFER {
        return Err(RUNTIME_LIMIT);
    }
    let floats = Floats {
        three_digit_exponents: options & LEGACY_THREE_DIGIT_EXPONENTS != 0,
        standard_rounding: options & STANDARD_ROUNDING != 0,
    };
    match crt_format::format(&template, source, floats) {
        Ok(text) => Ok(Formatted::Text(text)),
        Err(FormatError::Invalid) => Ok(Formatted::Invalid),
        Err(FormatError::Unsupported | FormatError::TooLong) => Err(RUNTIME_LIMIT),
        Err(FormatError::Fault(error)) => Err(fault(error)),
    }
}

/// `__stdio_common_vsprintf` (#466). Which result and termination rules the
/// option bits select is in the comment at [`STANDARD_SNPRINTF_BEHAVIOR`];
/// the rules themselves are from Microsoft's `snprintf` and `_snprintf`
/// pages:
///
/// - Standard: the result is always the length the text would have, and a
///   terminator is written whenever `count` is not zero, even when the text
///   does not fit. A null buffer with a zero count is the documented size
///   query and writes nothing.
/// - Legacy: an exact fit returns the length without writing a terminator.
///   Truncation returns -1. Both forms support a size query with a null
///   buffer and zero count.
///
/// A null buffer with a nonzero count is an invalid parameter in both. The
/// writes never leave `[buffer, buffer + count)`. A fault inside the buffer
/// stops the guest.
#[allow(clippy::too_many_arguments)]
/// The wide va_list: argument slots as the narrow one reads them, wide
/// strings as units and narrow strings as bytes.
struct WideVaList<'a> {
    memory: &'a GuestMemory,
    next: u64,
}

impl super::crt_wformat::WideSource for WideVaList<'_> {
    fn argument(&mut self) -> Result<u64, MemoryError> {
        let value = self.memory.read_u64(self.next)?;
        self.next += 8;
        Ok(value)
    }

    fn wide_string(&mut self, address: u64, limit: usize) -> Result<Vec<u16>, MemoryError> {
        let mut units = Vec::new();
        for at in 0..limit as u64 {
            let unit = self.memory.read_u16(address + at * 2)?;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        Ok(units)
    }

    fn narrow_string(&mut self, address: u64, limit: usize) -> Result<Vec<u8>, MemoryError> {
        let mut bytes = Vec::new();
        for at in 0..limit as u64 {
            let byte = self.memory.read_u8(address + at)?;
            if byte == 0 {
                break;
            }
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

/// The wide format string read from memory, bounded as the narrow one is.
fn wide_format_string(memory: &GuestMemory, format: u64) -> Result<Vec<u16>, ExitReason> {
    let mut units = Vec::new();
    for at in 0..MAX_TRANSFER + 1 {
        let unit = memory.read_u16(format + at * 2).map_err(fault)?;
        if unit == 0 {
            return Ok(units);
        }
        units.push(unit);
    }
    Err(RUNTIME_LIMIT)
}

/// `__stdio_common_vswprintf` (#459). The result and termination rules are
/// the narrow buffer forms', counted in wide characters: standard behavior
/// always answers the length the text would have and terminates whenever
/// `count` is not zero; legacy truncates without a terminator and answers
/// -1. A null buffer with a zero count is the size query.
#[allow(clippy::too_many_arguments)]
pub(super) fn print_to_wide_buffer(
    memory: &mut GuestMemory,
    options: u64,
    buffer: u64,
    count: u64,
    format: u64,
    locale: u64,
    arguments: u64,
) -> Outcome<i32> {
    let standard = options & STANDARD_SNPRINTF_BEHAVIOR != 0;
    let legacy = options & LEGACY_VSPRINTF_NULL_TERMINATION != 0;
    if standard && legacy {
        return Err(RUNTIME_LIMIT);
    }
    // The size query is the standard behavior's: without the bit a null
    // buffer is an invalid parameter however small the count, which is what
    // a mingw-w64 `swprintf` answers -1 for.
    let invalid = format == 0 || buffer == 0 && (count != 0 || !standard);
    if invalid {
        return Ok(Err(Failed(-1, EINVAL)));
    }
    if options & !KNOWN_OPTIONS != 0 || locale != 0 {
        return Err(RUNTIME_LIMIT);
    }
    let template = wide_format_string(memory, format)?;
    let mut source = WideVaList {
        memory,
        next: arguments,
    };
    let floats = crt_format::Floats {
        three_digit_exponents: options & LEGACY_THREE_DIGIT_EXPONENTS != 0,
        standard_rounding: options & STANDARD_ROUNDING != 0,
    };
    let mut units = match super::crt_wformat::wformat(&template, &mut source, floats) {
        Ok(units) => units,
        Err(crt_format::FormatError::Invalid) => return Ok(Err(Failed(-1, EINVAL))),
        Err(crt_format::FormatError::Unsupported | crt_format::FormatError::TooLong) => {
            return Err(RUNTIME_LIMIT);
        }
        Err(crt_format::FormatError::Fault(error)) => return Err(fault(error)),
    };
    let len = units.len() as u64;
    if buffer == 0 {
        return Ok(Ok(len as i32));
    }
    if count != 0 {
        let capacity = count - u64::from(standard);
        units.truncate(len.min(capacity) as usize);
        if standard || len < count {
            units.push(0);
        }
        let mut stored = Vec::with_capacity(units.len() * 2);
        for unit in &units {
            stored.extend(unit.to_le_bytes());
        }
        memory.write_bytes(buffer, &stored).map_err(fault)?;
    }
    Ok(Ok(if standard || len <= count {
        len as i32
    } else {
        -1
    }))
}

pub(super) fn print_to_buffer(
    memory: &mut GuestMemory,
    options: u64,
    buffer: u64,
    count: u64,
    format: u64,
    locale: u64,
    arguments: u64,
) -> Outcome<i32> {
    let standard = options & STANDARD_SNPRINTF_BEHAVIOR != 0;
    let legacy = options & LEGACY_VSPRINTF_NULL_TERMINATION != 0;
    if standard && legacy {
        return Err(RUNTIME_LIMIT);
    }
    if format == 0 || buffer == 0 && count != 0 {
        return Ok(Err(Failed(-1, EINVAL)));
    }
    let mut text = match formatted(memory, options, format, locale, arguments, true)? {
        // Xenora's choice for when execution continues after the invalid
        // parameter handler: nothing is written and the result is -1.
        Formatted::Invalid => return Ok(Err(Failed(-1, EINVAL))),
        Formatted::Text(text) => text,
    };
    let len = text.len() as u64;
    if buffer == 0 {
        return Ok(Ok(len as i32));
    }
    if count != 0 {
        let capacity = count - u64::from(standard);
        text.truncate(len.min(capacity) as usize);
        if standard || len < count {
            text.push(0);
        }
        memory.write_bytes(buffer, &text).map_err(fault)?;
    }
    // Microsoft's page does not set errno for a truncated legacy write.
    Ok(Ok(if standard || len <= count {
        len as i32
    } else {
        -1
    }))
}

/// `__stdio_common_vsprintf_s` (#466), the secure form. Microsoft's
/// `sprintf_s` page: a null buffer, a zero count or a null format invokes the
/// invalid parameter handler, and so does an invalid format string; a buffer
/// too small for the text and its terminator is set to the empty string and
/// the result is -1. When execution continues the error is `EINVAL`, or
/// `ERANGE` for the small buffer. Xenora does not model the handler, so
/// execution always continues.
#[allow(clippy::too_many_arguments)]
pub(super) fn print_to_buffer_secure(
    memory: &mut GuestMemory,
    options: u64,
    buffer: u64,
    count: u64,
    format: u64,
    locale: u64,
    arguments: u64,
) -> Outcome<i32> {
    if buffer == 0 || count == 0 || format == 0 {
        return Ok(Err(Failed(-1, EINVAL)));
    }
    let mut text = match formatted(memory, options, format, locale, arguments, true)? {
        Formatted::Invalid => {
            memory.write_u8(buffer, 0).map_err(fault)?;
            return Ok(Err(Failed(-1, EINVAL)));
        }
        Formatted::Text(text) => text,
    };
    let len = text.len() as u64;
    if len >= count {
        memory.write_u8(buffer, 0).map_err(fault)?;
        return Ok(Err(Failed(-1, ERANGE)));
    }
    text.push(0);
    memory.write_bytes(buffer, &text).map_err(fault)?;
    Ok(Ok(len as i32))
}

impl StandardStreams {
    /// The streams a spawned child inherits: the descriptor wiring copies,
    /// so the pipes the parent created are the child's own, while the
    /// captured output starts empty for the parent to collect as the CRT
    /// recombines a child's console writes. The input copies its unread
    /// bytes: a console child's stdin is the same console's, and a pipe
    /// rewired onto descriptor 0 already bypasses it either way.
    /// The child's inherited pipe references count, as handle inheritance
    /// adds to the kernel object's count.
    pub(super) fn count_inherited_pipe_references(&self, drive: &mut super::ObjectState) {
        self.opened.count_inherited_pipe_references(drive);
    }

    /// The dead child's pipe ends close, as process exit closes its table.
    pub(super) fn close_pipe_ends_for_exit(&mut self, drive: &mut super::ObjectState) {
        self.opened.close_pipe_ends_for_exit(drive);
    }

    /// The positions a finished `_P_WAIT` child left behind, written back
    /// into the streams they were inherited from.
    pub(super) fn absorb_child_positions(&mut self, child: &StandardStreams) {
        self.opened.absorb_child_positions(&child.opened);
    }

    /// The process working directory, cloned: the kernel file surface
    /// resolves its own paths against it, exactly as Windows shares the
    /// one current directory between the CRT and the kernel.
    pub(super) fn working_directory(&self) -> String {
        self.cwd.clone()
    }

    /// `_chdir`'s replacement working directory, already validated against
    /// the drive's directories.
    pub(super) fn set_working_directory(&mut self, cwd: String) {
        self.cwd = cwd;
    }

    /// A guest file name as the drive stores it, resolved against the
    /// working directory first exactly as the CRT resolves relative paths
    /// on Windows: absolute input passes through unchanged, so a path the
    /// caller already resolved is safe to resolve again.
    pub(super) fn resolve_path(&self, name: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(name).ok()?;
        let resolved = super::crt::resolve_directory(&self.cwd, text);
        ObjectState::drive_path(resolved.as_bytes())
    }

    pub(super) fn inherit_for_spawn(&self) -> StandardStreams {
        StandardStreams {
            opened: self.opened.inherit_for_spawn(),
            input: Input {
                bytes: self.input.bytes[self.input.position..].to_vec(),
                position: 0,
                orientation: self.input.orientation,
                eof: self.input.eof,
            },
            cwd: self.cwd.clone(),
            ..StandardStreams::default()
        }
    }

    pub(super) fn output(&self) -> &[u8] {
        &self.output
    }

    pub(super) fn error(&self) -> &[u8] {
        &self.error
    }

    /// `__acrt_iob_func`: the `FILE` object of `stdin` (0), `stdout` (1) or
    /// `stderr` (2). The three are allocated together from the process heap
    /// on first use.
    pub(super) fn file(&mut self, memory: &mut GuestMemory, index: u32) -> Result<u64, ExitReason> {
        if index > 2 {
            return Err(RUNTIME_LIMIT);
        }
        let base = match self.files {
            Some(base) => base,
            None => {
                let base = memory
                    .map_heap_allocation(PROCESS_HEAP, (3 * FILE_BYTES) as usize)
                    .map_err(fault)?;
                // These standard streams use unbuffered output. Its two-byte
                // backing storage is the stream's own _charbuf field, while
                // the available count remains zero between operations.
                for stream in 0..3u64 {
                    let at = base + FILE_BYTES * stream;
                    memory.write_u64(at, at + 28).map_err(fault)?;
                    memory.write_u64(at + 8, at + 28).map_err(fault)?;
                    memory.write_u32(at + 32, 2).map_err(fault)?;
                    memory
                        .write_u32(at + 20, 0x2400 | if stream == 0 { 1 } else { 2 })
                        .map_err(fault)?;
                    memory.write_u32(at + 24, stream as u32).map_err(fault)?;
                }
                self.files = Some(base);
                base
            }
        };
        Ok(base + FILE_BYTES * u64::from(index))
    }

    /// Addresses of the live buffer fields for one of our standard streams.
    /// File streams returned by fopen are not represented by this layout:
    /// their zeroed legacy `_iobuf` keeps `_cnt` at zero, so the CRT macros
    /// reach `_filbuf`/`_flsbuf` for every byte instead of a buffer.
    pub(super) fn standard_buffer_fields(&self, file: u64) -> Result<[u64; 3], ExitReason> {
        let Some(base) = self.files else {
            return Err(RUNTIME_LIMIT);
        };
        let offset = file.wrapping_sub(base);
        if ![0, FILE_BYTES, FILE_BYTES * 2].contains(&offset) {
            return Err(RUNTIME_LIMIT);
        }
        Ok([file + 8, file, file + 16])
    }

    /// `__iob_func`: the legacy CRT's array of three 48-byte `_iobuf`
    /// objects, allocated once. The direction flag sits at offset 24 and the
    /// file descriptor at 28, as the mingw-w64 header fixes them; the buffer
    /// fields stay zero, so a legacy stream is unbuffered and every byte
    /// goes through `_filbuf`/`_flsbuf`, exactly as on Windows.
    pub(super) fn materialize_legacy_files(
        &mut self,
        memory: &mut GuestMemory,
    ) -> Result<u64, ExitReason> {
        if let Some(base) = self.legacy_files {
            return Ok(base);
        }
        let base = memory
            .map_heap_allocation(PROCESS_HEAP, 3 * LEGACY_FILE_BYTES as usize)
            .map_err(fault)?;
        for index in 0..3u64 {
            let entry = base + LEGACY_FILE_BYTES * index;
            let flags: u32 = if index == 0 { 1 } else { 2 }; // _IOREAD / _IOWRT
            memory.write_u32(entry + 24, flags).map_err(fault)?;
            memory.write_u32(entry + 28, index as u32).map_err(fault)?;
        }
        self.legacy_files = Some(base);
        Ok(base)
    }

    /// The standard stream a pointer into the legacy `__iob_func` array is,
    /// when it is exactly one of the three objects.
    fn legacy_stream(&self, file: u64) -> Option<Stream> {
        let base = self.legacy_files?;
        let offset = file.wrapping_sub(base);
        if offset % LEGACY_FILE_BYTES != 0 {
            return None;
        }
        match offset / LEGACY_FILE_BYTES {
            0 => Some(Stream::Input),
            1 => Some(Stream::Output),
            2 => Some(Stream::Error),
            _ => None,
        }
    }

    /// Which stream a non-null `FILE*` is: a standard stream, or one `fopen`
    /// returned. Any other pointer is no stream.
    fn stream(&self, file: u64) -> Result<Stream, ExitReason> {
        match self.files.map(|base| file.wrapping_sub(base)) {
            Some(0) => Ok(Stream::Input),
            Some(offset) if offset == FILE_BYTES => Ok(Stream::Output),
            Some(offset) if offset == 2 * FILE_BYTES => Ok(Stream::Error),
            _ if self.opened.contains(file) => Ok(Stream::File(file)),
            _ => self.legacy_stream(file).ok_or(RUNTIME_LIMIT),
        }
    }

    /// A stream that may be written. Writing `stdin` is not modelled.
    fn writable(&self, file: u64) -> Result<Stream, ExitReason> {
        match self.stream(file)? {
            Stream::Input => Err(RUNTIME_LIMIT),
            stream => Ok(stream),
        }
    }

    /// Write to a stream. A standard stream is captured in text mode: each
    /// line feed becomes a carriage return and a line feed. A file stream can
    /// fail, with the `errno` value in the inner result and nothing written.
    fn write(
        &mut self,
        drive: &mut ObjectState,
        stream: Stream,
        bytes: &[u8],
    ) -> Result<Result<(), u32>, ExitReason> {
        // A closed standard descriptor fails every later write, as on
        // Windows after `_close` of it succeeds.
        let mark = match stream {
            Stream::Output => Some(1),
            Stream::Error => Some(2),
            _ => None,
        };
        if mark.is_some_and(|fd| self.opened.closed[fd]) {
            return Ok(Err(EBADF));
        }
        // A standard stream writes through its descriptor, exactly as the
        // CRT's streams write through 1 and 2: when the table carries the
        // number - a redirection `_dup2` put it there - the ordinary
        // descriptor machinery answers rather than the captured output.
        if let Some(fd) = mark
            && self.opened.has_descriptor(fd as u32)
            && self.opened.standard_terminal(fd as u32).is_none()
        {
            return Ok(self.opened.descriptor_write(drive, fd as u32, bytes));
        }
        let orientation = match stream {
            Stream::Output => &mut self.output_orientation,
            Stream::Error => &mut self.error_orientation,
            Stream::Input => return Err(RUNTIME_LIMIT),
            Stream::File(file) => return Ok(self.opened.write(drive, file, bytes)),
        };
        if *orientation == 0 {
            *orientation = 1;
        }
        // A byte write on a wide-oriented output writes nothing, as the CRT
        // answers the conflict.
        if *orientation == 2 {
            return Ok(Err(EBADF));
        }
        let captured = match stream {
            Stream::Output => &mut self.output,
            Stream::Error => &mut self.error,
            Stream::Input | Stream::File(_) => unreachable!(),
        };
        let feeds = bytes.iter().filter(|byte| **byte == b'\n').count();
        if bytes.len() + feeds > MAX_CAPTURED_OUTPUT - captured.len() {
            return Err(RUNTIME_LIMIT);
        }
        for &byte in bytes {
            if byte == b'\n' {
                captured.push(b'\r');
            }
            captured.push(byte);
        }
        Ok(Ok(()))
    }

    /// `__stdio_common_vfprintf`. Returns the number of characters written,
    /// before the text-mode replacement.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn print(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        options: u64,
        file: u64,
        format: u64,
        locale: u64,
        arguments: u64,
    ) -> Outcome<i32> {
        // A null stream or format: the function returns -1 and sets errno.
        if file == 0 || format == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let stream = self.writable(file)?;
        let text = match formatted(memory, options, format, locale, arguments, false)? {
            // Xenora's choice for when execution continues after the invalid
            // parameter handler: nothing is written and the result is that of
            // a null format.
            Formatted::Invalid => return Ok(Err(Failed(-1, EINVAL))),
            Formatted::Text(text) => text,
        };
        // "A negative value if an output error occurs."
        Ok(match self.write(drive, stream, &text)? {
            Ok(()) => Ok(text.len() as i32),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// Write already formatted text to a stream the way `fprintf` does:
    /// the character count, or -1 with the errno of the failed write.
    pub(super) fn write_formatted(
        &mut self,
        drive: &mut ObjectState,
        file: u64,
        text: &[u8],
    ) -> Outcome<i32> {
        let stream = self.writable(file)?;
        Ok(match self.write(drive, stream, text)? {
            Ok(()) => Ok(text.len() as i32),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `putchar`: `fputc` to `stdout`. Returns the character, or `EOF` with
    /// `errno` set.
    pub(super) fn put_character_stdout(
        &mut self,
        drive: &mut ObjectState,
        character: i32,
    ) -> Outcome<i32> {
        let byte = [character as u8];
        Ok(match self.write(drive, Stream::Output, &byte)? {
            Ok(()) => Ok(i32::from(character as u8)),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `puts`: the string and a newline to `stdout`. Returns a nonnegative
    /// value (zero here), or `EOF` with `errno` set.
    pub(super) fn put_line_stdout(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        text: u64,
    ) -> Outcome<i32> {
        if text == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let mut bytes = c_string(memory, text, MAX_TRANSFER + 1).map_err(fault)?;
        if bytes.len() as u64 > MAX_TRANSFER {
            return Err(RUNTIME_LIMIT);
        }
        bytes.push(b'\n');
        Ok(match self.write(drive, Stream::Output, &bytes)? {
            Ok(()) => Ok(0),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `fwrite`. Returns the number of whole items written.
    pub(super) fn write_items(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        buffer: u64,
        size: u64,
        count: u64,
        file: u64,
    ) -> Outcome<u64> {
        if buffer == 0 || file == 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let stream = self.writable(file)?;
        let Some(length) = size
            .checked_mul(count)
            .filter(|bytes| *bytes <= MAX_TRANSFER)
        else {
            return Err(RUNTIME_LIMIT);
        };
        if length == 0 {
            return Ok(Ok(0));
        }
        let mut bytes = vec![0; length as usize];
        memory.read_bytes(buffer, &mut bytes).map_err(fault)?;
        // Fewer items than `count` means an error. A failed write here
        // writes none of them.
        Ok(match self.write(drive, stream, &bytes)? {
            Ok(()) => Ok(count),
            Err(errno) => Err(Failed(0, errno)),
        })
    }

    /// `fputs`. Writes the string without its terminator and returns a
    /// nonnegative value, here 0; `EOF` is -1.
    pub(super) fn put_string(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        text: u64,
        file: u64,
    ) -> Outcome<i32> {
        if text == 0 || file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let stream = self.writable(file)?;
        let bytes = c_string(memory, text, MAX_TRANSFER + 1).map_err(fault)?;
        if bytes.len() as u64 > MAX_TRANSFER {
            return Err(RUNTIME_LIMIT);
        }
        Ok(match self.write(drive, stream, &bytes)? {
            Ok(()) => Ok(0),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `fputc`. Writes the character converted to `unsigned char` to the
    /// stream and returns it, or `EOF` with `errno` set.
    pub(super) fn put_character(
        &mut self,
        drive: &mut ObjectState,
        character: i32,
        file: u64,
    ) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let stream = self.writable(file)?;
        let byte = [character as u8];
        Ok(match self.write(drive, stream, &byte)? {
            Ok(()) => Ok(i32::from(character as u8)),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `fread`. Reads up to `count` items of `size` bytes from the stream
    /// and returns how many whole items it read, which is fewer at the end
    /// of the file or when a read fails — not an error of its own, so the
    /// indicators separate the two, as the documentation asks. A null buffer
    /// or stream is `EINVAL` with a return of 0. More than this runtime
    /// transfers at once stops the guest, as for `fwrite`.
    /// Bytes of the standard input, honoring a redirection: when fd 0 was
    /// duplicated onto a pipe or file the stream reads what the descriptor
    /// names, as the CRT's stdin is backed by its descriptor. The captured
    /// input bytes answer only while fd 0 is the console's own.
    fn input_bytes(&mut self, drive: &ObjectState, count: usize) -> Result<Vec<u8>, u32> {
        if self.opened.has_descriptor(0) {
            return self.opened.descriptor_read(drive, 0, count);
        }
        Ok(self.input.take(count))
    }

    pub(super) fn read_items(
        &mut self,
        memory: &mut GuestMemory,
        drive: &ObjectState,
        buffer: u64,
        size: u64,
        count: u64,
        file: u64,
    ) -> Outcome<u64> {
        if buffer == 0 || file == 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let stream = self.stream(file)?;
        let Some(length) = size
            .checked_mul(count)
            .filter(|bytes| *bytes <= MAX_TRANSFER)
        else {
            return Err(RUNTIME_LIMIT);
        };
        if length == 0 {
            return Ok(Ok(0));
        }
        let bytes = match stream {
            Stream::Input => {
                if self.opened.closed[0] || !self.input.orient(false) {
                    return Ok(Err(Failed(0, EBADF)));
                }
                match self.input_bytes(drive, length as usize) {
                    Ok(bytes) => bytes,
                    Err(errno) => return Ok(Err(Failed(0, errno))),
                }
            }
            Stream::File(file) => match self.opened.read_bytes(drive, file, length as usize) {
                Ok(bytes) => {
                    // A short read means the end of the file, as nothing
                    // else shortens it here; the indicator separates it
                    // from an error, which is what `feof` is for.
                    if bytes.len() < length as usize {
                        self.opened.note_end_of_file(file);
                    }
                    bytes
                }
                Err(errno) => return Ok(Err(Failed(0, errno))),
            },
            _ => return Ok(Err(Failed(0, EBADF))),
        };
        if bytes.is_empty() {
            return Ok(Ok(0));
        }
        memory.write_bytes(buffer, &bytes).map_err(fault)?;
        // Only whole items count, and the bytes of a partial one stay in
        // the buffer, as the CRT leaves them.
        Ok(Ok((bytes.len() as u64) / size.max(1)))
    }

    /// `fgetc`. The next byte of the stream as `unsigned char`, or `EOF` at
    /// the end of the file. A null stream is `EINVAL` with a return of
    /// `EOF`; reading a stream open for writing is `EBADF`.
    pub(super) fn read_character_file(&mut self, drive: &ObjectState, file: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.stream(file)? {
            Stream::Input => {
                if self.opened.closed[0] {
                    return Ok(Err(Failed(-1, EBADF)));
                }
                if self.opened.has_descriptor(0) {
                    return match self.opened.descriptor_read(drive, 0, 1) {
                        Ok(bytes) if !bytes.is_empty() => Ok(Ok(i32::from(bytes[0]))),
                        Ok(_) => Ok(Ok(-1)),
                        Err(errno) => Ok(Err(Failed(-1, errno))),
                    };
                }
                Ok(Ok(match self.input.character() {
                    Some(byte) => i32::from(byte),
                    None => -1,
                }))
            }
            Stream::File(file) => match self.opened.read_bytes(drive, file, 1) {
                Ok(bytes) if !bytes.is_empty() => Ok(Ok(i32::from(bytes[0]))),
                Ok(_) => {
                    self.opened.note_end_of_file(file);
                    Ok(Ok(-1))
                }
                Err(errno) => Ok(Err(Failed(-1, errno))),
            },
            _ => Ok(Err(Failed(-1, EBADF))),
        }
    }

    /// `__stdio_common_vfscanf` and its secure variant read a byte-oriented
    /// stream. The cursor follows input actually consumed and a read that
    /// meets end-of-file sets the existing indicator.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn scan(
        &mut self,
        memory: &mut GuestMemory,
        drive: &ObjectState,
        options: u64,
        file: u64,
        format: u64,
        locale: u64,
        arguments: u64,
    ) -> Outcome<i32> {
        use super::crt_scan::{Bytes, EOF, Request};
        if file == 0 || format == 0 {
            return Ok(Err(Failed(EOF, EINVAL)));
        }
        let stream = self.stream(file)?;
        let request = Request::read(memory, options, format, locale)?;
        let scanned = match stream {
            Stream::Input => {
                if self.opened.closed[0] || !self.input.orient(false) {
                    return Ok(Err(Failed(EOF, EBADF)));
                }
                // The hosted input has already had its CRLFs translated.
                let mut source = Bytes {
                    bytes: &self.input.bytes,
                    at: self.input.position,
                    text: false,
                };
                let pending = request.scan(memory, &mut source, arguments);
                let scanned = pending.finish(memory)?;
                self.input.position = source.at;
                self.input.eof |= scanned.met_end;
                scanned
            }
            Stream::File(file) => {
                let (bytes, start, text) = match self.opened.reading(drive, file) {
                    Ok(reading) => reading,
                    Err(errno) => return Ok(Err(Failed(EOF, errno))),
                };
                let mut source = Bytes {
                    bytes,
                    at: start,
                    text,
                };
                let pending = request.scan(memory, &mut source, arguments);
                let scanned = pending.finish(memory)?;
                self.opened
                    .finish_scan(file, source.at - start, scanned.met_end);
                scanned
            }
            Stream::Output | Stream::Error => return Ok(Err(Failed(EOF, EBADF))),
        };
        Ok(Ok(scanned.result))
    }

    /// `rewind`: back to the start of the stream, clearing the end-of-file
    /// and error indicators as the documentation requires, which is what
    /// separates it from a bare `fseek` to zero. A standard stream, which
    /// seeking already refuses, is not modelled.
    pub(super) fn rewind_file(&mut self, drive: &ObjectState, file: u64) -> Outcome<()> {
        if file == 0 {
            return Ok(Err(Failed((), EINVAL)));
        }
        match self.stream(file)? {
            Stream::File(file) => match self.opened.seek(drive, file, 0, 0) {
                Ok(()) => {
                    self.opened.clear_errors(file);
                    Ok(Ok(()))
                }
                Err(errno) => Ok(Err(Failed((), errno))),
            },
            _ => Err(RUNTIME_LIMIT),
        }
    }

    /// `_lock_file` and `_unlock_file`. The lock itself does nothing, and
    /// that is a consequence of the execution model rather than a swallowed
    /// error: Xenora's guest scheduler runs one guest thread at a time, so
    /// two guest threads can never hold the same stream at once.
    pub(super) fn lock(&self, file: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        // A pointer that is no stream is not modelled.
        self.stream(file)?;
        Ok(Ok(0))
    }

    /// A guest block of at least `size` bytes that a service writes into.
    /// The same block is used again until a larger one is needed.
    pub(super) fn message_block(
        &mut self,
        memory: &mut GuestMemory,
        size: u64,
    ) -> Result<u64, ExitReason> {
        if let Some((address, capacity)) = self.scratch.message
            && capacity >= size
        {
            return Ok(address);
        }
        let address = memory
            .map_heap_allocation(PROCESS_HEAP, size.max(1) as usize)
            .map_err(fault)?;
        self.scratch.message = Some((address, size));
        Ok(address)
    }

    /// The guest block `localeconv` returns. It is filled once and stays.
    pub(super) fn locale_block(
        &mut self,
        memory: &mut GuestMemory,
        size: u64,
    ) -> Result<u64, ExitReason> {
        match self.scratch.locale {
            Some(address) => Ok(address),
            None => {
                let address = memory
                    .map_heap_allocation(PROCESS_HEAP, size.max(1) as usize)
                    .map_err(fault)?;
                self.scratch.locale = Some(address);
                Ok(address)
            }
        }
    }

    /// `getchar`: one character from the standard input, or `EOF` at the
    /// end. Text mode is applied when the input is supplied, so a character
    /// here is already after the replacement.
    pub(super) fn character_stdin(&mut self) -> i32 {
        if self.opened.closed[0] || !self.input.orient(false) {
            return -1;
        }
        match self.input.character() {
            Some(byte) => i32::from(byte),
            None => -1,
        }
    }

    /// `_open`. The descriptor, or -1 with `errno`. The wide text modes
    /// `_O_WTEXT`, `_O_U16TEXT` and `_O_U8TEXT` are not modelled and stop
    /// the guest; the hint bits (`_O_NOINHERIT`, `_O_SEQUENTIAL`,
    /// `_O_RANDOM`, `_O_SHORT_LIVED`) change nothing and are accepted.
    pub(super) fn open_descriptor(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        flags: u32,
        default_binary: bool,
    ) -> Outcome<i32> {
        if name == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        if flags & 0x7_0000 != 0 {
            return Err(RUNTIME_LIMIT);
        }
        let bytes = c_string(memory, name, MAX_NAME + 1).map_err(fault)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_NAME {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let Some(resolved) = self.resolve_path(&bytes) else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        Ok(self
            .opened
            .open_descriptor(drive, resolved.as_bytes(), flags, default_binary)
            .map(|fd| fd as i32)
            .map_err(|errno| Failed(-1, errno)))
    }

    /// `_close`. 0, or -1 with `EBADF` for a descriptor that is not open.
    /// Closing a standard descriptor is not modelled and stops the guest.
    /// `_locking`: byte-range locks over the descriptor stream's current
    /// position. See the table's `lock_range` for the contract.
    pub(super) fn lock_descriptor(&mut self, fd: i32, mode: i32, nbytes: i32) -> Outcome<i32> {
        if fd < 0 || nbytes < 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        Ok(
            match self
                .opened
                .lock_range(fd as u32, mode as u32, nbytes as u32)
            {
                Ok(()) => Ok(0),
                Err(errno) => Err(Failed(-1, errno)),
            },
        )
    }

    /// `_commit`: the hosted drive is the storage, so a valid file-backed
    /// descriptor has nothing to flush and answers success.
    pub(super) fn commit_descriptor(&mut self, fd: i32) -> Outcome<i32> {
        if fd < 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        Ok(match self.opened.commit_descriptor(fd as u32) {
            Ok(()) => Ok(0),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    pub(super) fn close_descriptor(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        fd: i32,
    ) -> Outcome<i32> {
        if fd < 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        // A standard descriptor the table carries closes through the
        // ordinary machinery: `_dup2` put it there, and closing it is
        // closing the duplication. One the table does not carry is the
        // standard stream itself, which closes as on Windows - the CRT does
        // not reserve them - and every later operation on it fails with
        // EBADF. A second close has nothing to close and fails.
        if fd < 3 && !self.opened.has_descriptor(fd as u32) {
            let mark = &mut self.opened.closed[fd as usize];
            if *mark {
                return Ok(Err(Failed(-1, EBADF)));
            }
            *mark = true;
            return Ok(Ok(0));
        }
        let closed = self.opened.descriptor_close(memory, drive, fd as u32);
        if closed && fd < 3 {
            self.opened.closed[fd as usize] = true;
        }
        Ok(if closed {
            Ok(0)
        } else {
            Err(Failed(-1, EBADF))
        })
    }

    /// `_read`. The byte count, or -1 with `errno`. Reading the standard
    /// input consumes what the host supplied; the output descriptors
    /// cannot be read. A buffer it cannot write stops the guest with a
    /// fault.
    pub(super) fn read_descriptor(
        &mut self,
        memory: &mut GuestMemory,
        drive: &ObjectState,
        fd: i32,
        buffer: u64,
        count: u32,
    ) -> Outcome<i32> {
        if buffer == 0 && count != 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        if fd < 0 || count as u64 > MAX_TRANSFER {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        // A duplication of a standard descriptor answers as the standard
        // stream itself, from whatever descriptor number it hangs on.
        if fd >= 0
            && let Some(n) = self.opened.standard_terminal(fd as u32)
        {
            if n != 0 {
                return Ok(Err(Failed(-1, EBADF)));
            }
            let bytes = self.input.take((count as usize).min(1 << 20));
            memory.write_bytes(buffer, &bytes).map_err(fault)?;
            return Ok(Ok(bytes.len() as i32));
        }
        let rewired = (0..3).contains(&fd) && self.opened.has_descriptor(fd as u32);
        let bytes = match fd {
            0 if !rewired && self.opened.closed[0] => return Ok(Err(Failed(-1, EBADF))),
            0 if !rewired => self.input.take((count as usize).min(1 << 20)),
            1 | 2 if !rewired => return Ok(Err(Failed(-1, EBADF))),
            // Pipe ends are wrapped kernel handles: the drain in
            // `descriptor_read` answers what the pipe holds, empty once the
            // write side is done - which in the synchronous process world is
            // the end-of-file a blocked read would reach, since no suspended
            // process can write while this one runs.
            _ => match self
                .opened
                .descriptor_read(drive, fd as u32, count as usize)
            {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(Err(Failed(-1, errno))),
            },
        };
        memory.write_bytes(buffer, &bytes).map_err(fault)?;
        Ok(Ok(bytes.len() as i32))
    }

    /// `_write`. The byte count, or -1 with `errno`. The standard output
    /// and error descriptors write to the captured streams; the input
    /// descriptor cannot be written.
    pub(super) fn write_descriptor(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        fd: i32,
        buffer: u64,
        count: u32,
    ) -> Outcome<i32> {
        if buffer == 0 && count != 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        if fd < 0 || count as u64 > MAX_TRANSFER {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let mut bytes = vec![0; count as usize];
        memory.read_bytes(buffer, &mut bytes).map_err(fault)?;
        // A duplication of a standard descriptor answers as the standard
        // stream itself, from whatever descriptor number it hangs on.
        if fd >= 0
            && let Some(n) = self.opened.standard_terminal(fd as u32)
        {
            let result = match n {
                0 => Err(EBADF),
                1 => self.write(drive, Stream::Output, &bytes)?,
                _ => self.write(drive, Stream::Error, &bytes)?,
            };
            return Ok(match result {
                Ok(()) => Ok(count as i32),
                Err(errno) => Err(Failed(-1, errno)),
            });
        }
        // A standard descriptor the table carries is no standard stream
        // anymore: `_dup2` rewired it, and the ordinary descriptor machinery
        // answers for it exactly as the CRT's table does.
        let rewired = (0..3).contains(&fd) && self.opened.has_descriptor(fd as u32);
        let result = match fd {
            0 if !rewired => Err(EBADF),
            1 if !rewired && self.opened.closed[1] => Err(EBADF),
            2 if !rewired && self.opened.closed[2] => Err(EBADF),
            1 if !rewired => self.write(drive, Stream::Output, &bytes)?,
            2 if !rewired => self.write(drive, Stream::Error, &bytes)?,
            _ => match self.opened.descriptor_write(drive, fd as u32, &bytes) {
                Ok(()) => Ok(()),
                Err(errno) => Err(errno),
            },
        };
        Ok(match result {
            Ok(()) => Ok(count as i32),
            Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `_lseek`. The new position, or -1 with `errno`. The standard
    /// descriptors cannot be sought.
    pub(super) fn seek_descriptor(
        &mut self,
        drive: &ObjectState,
        fd: i32,
        offset: i32,
        origin: i32,
    ) -> Outcome<i32> {
        if fd < 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        if fd < 3 && !self.opened.has_descriptor(fd as u32) {
            return Ok(Err(Failed(-1, EBADF)));
        }
        Ok(self
            .opened
            .descriptor_seek(drive, fd as u32, offset, origin as u32)
            .map(|position| position as i32)
            .map_err(|errno| Failed(-1, errno)))
    }
    /// `_lseeki64` (#459). The 64-bit form of the seek above: positions no
    /// 32-bit `long` need hold, the same rejection of the standard
    /// descriptors.
    pub(super) fn seek_descriptor64(
        &mut self,
        drive: &ObjectState,
        fd: i32,
        offset: i64,
        origin: i32,
    ) -> Outcome<i64> {
        if fd < 3 && !self.opened.has_descriptor(fd as u32) {
            return Ok(Err(Failed(-1, EBADF)));
        }
        if origin < 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        Ok(self
            .opened
            .descriptor_seek64(drive, fd as u32, offset, origin as u32)
            .map_err(|errno| Failed(-1, errno)))
    }

    /// `_telli64` (#459): the descriptor's position, a seek of zero from the
    /// current one, with the same rejection of the standard descriptors.
    pub(super) fn tell_descriptor64(&mut self, drive: &ObjectState, fd: i32) -> Outcome<i64> {
        self.seek_descriptor64(drive, fd, 0, 1)
    }

    /// `_creat` is `_open` with exactly `_O_WRONLY | _O_CREAT | _O_TRUNC`, as
    /// the CRT documents it; the permission argument does not act on a drive
    /// without permission bits.
    pub(super) fn create_descriptor(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        default_binary: bool,
    ) -> Outcome<i32> {
        self.open_descriptor(memory, drive, name, 1 | 0x100 | 0x200, default_binary)
    }

    /// `_mktemp` rewrites the trailing `X` characters of its template into a
    /// name no file of the drive carries, as the CRT rewrites them: a letter
    /// then digits of a counter. Null answers null with `EINVAL` when the
    /// template carries no `X`.
    pub(super) fn make_temporary_name(
        &mut self,
        memory: &mut GuestMemory,
        drive: &ObjectState,
        template: u64,
    ) -> Outcome<u64> {
        if template == 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let bytes = c_string(memory, template, MAX_NAME + 1).map_err(fault)?;
        let xs = bytes.iter().rev().take_while(|&&b| b == b'X').count();
        if xs == 0 || bytes.len() as u64 > MAX_NAME {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let mut name = bytes.clone();
        let stem = name.len() - xs;
        let per_letter = 10_u32.pow((xs - 1) as u32);
        for attempt in 0..26_u32 * per_letter {
            let letter = b'a' + (attempt / per_letter) as u8;
            let digits = format!("{:0width$}", attempt % per_letter, width = xs - 1);
            name.truncate(stem);
            name.push(letter);
            name.extend_from_slice(digits.as_bytes());
            if ObjectState::drive_path(&name)
                .is_some_and(|path| matches!(drive.drive_entry(&path), DriveEntry::Missing { .. }))
            {
                memory
                    .write_bytes(template, &name)
                    .and_then(|()| memory.write_u8(template + name.len() as u64, 0))
                    .map_err(fault)?;
                return Ok(Ok(template));
            }
        }
        Ok(Err(Failed(0, EEXIST)))
    }

    /// `_fstat64` fills the 56-byte legacy structure the mingw header fixes:
    /// device, inode and times are zero — the drive carries none — the mode
    /// is a regular file the CRT reports readable and writable, and the size
    /// is the file's length. The offsets are the ones the cross-compiler
    /// confirms: dev 0, ino 4, mode 6, nlink 8, uid 10, gid 12, rdev 16,
    /// size 24, the three times at 32, 40 and 48.
    pub(super) fn stat_descriptor64(
        &mut self,
        memory: &mut GuestMemory,
        drive: &ObjectState,
        fd: i32,
        buffer: u64,
    ) -> Outcome<i32> {
        if fd < 0 || buffer == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let (length, kind) = match self.opened.descriptor_stat(drive, fd as u32) {
            Ok(stat) => stat,
            Err(errno) => return Ok(Err(Failed(-1, errno))),
        };
        let mut stat = [0u8; 56];
        stat[6..8].copy_from_slice(&(kind | 0o666).to_le_bytes());
        stat[8..10].copy_from_slice(&1_i16.to_le_bytes()); // one link
        stat[24..32].copy_from_slice(&length.to_le_bytes());
        memory.write_bytes(buffer, &stat).map_err(fault)?;
        Ok(Ok(0))
    }

    /// `_pipe` answers the two descriptors through the caller's array.
    pub(super) fn pipe_create(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut super::ObjectState,
        fds: u64,
    ) -> Outcome<i32> {
        if fds == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.opened.pipe_create(drive) {
            Ok((read, write)) => {
                memory
                    .write_u32(fds, read)
                    .and_then(|()| memory.write_u32(fds + 4, write))
                    .map_err(fault)?;
                Ok(Ok(0))
            }
            Err(errno) => Ok(Err(Failed(-1, errno))),
        }
    }

    /// `_fdopen`: the descriptor becomes the stream's, and the mode string
    /// only has to parse — matching it against the descriptor's access is the
    /// caller's business, as the CRT leaves it undefined.
    pub(super) fn fdopen_stream(
        &mut self,
        memory: &mut GuestMemory,
        fd: i32,
        mode: u64,
    ) -> Outcome<u64> {
        if fd < 0 || mode == 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let bytes = c_string(memory, mode, 16).map_err(fault)?;
        if crt_files::parse_mode(&bytes, false).is_none() {
            return Ok(Err(Failed(0, EINVAL)));
        }
        Ok(self
            .opened
            .fdopen_stream(memory, fd as u32)
            .map_err(|errno| Failed(0, errno)))
    }

    /// `_dup` and `_dup2` (#459). The duplication shares the file position,
    /// as the CRT's does; the standard descriptors duplicate as any other.
    pub(super) fn duplicate_descriptor(&mut self, fd: i32) -> Outcome<i32> {
        if fd < 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        Ok(self
            .opened
            .descriptor_duplicate(fd as u32)
            .map(|fd| fd as i32)
            .map_err(|errno| Failed(-1, errno)))
    }

    pub(super) fn duplicate_descriptor2(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        fd: i32,
        target: i32,
    ) -> Outcome<i32> {
        if fd < 0 || target < 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        Ok(self
            .opened
            .descriptor_duplicate2(memory, drive, fd as u32, target as u32)
            .map(|fd| fd as i32)
            .map_err(|errno| Failed(-1, errno)))
    }

    /// `_setmode` (#459): the text or binary translation of the descriptor's
    /// stream, answering the previous one. The hosted streams are
    /// byte-oriented, so the wide forms are `EINVAL` here, and a descriptor
    /// that is not open is `EBADF`.
    pub(super) fn set_descriptor_mode(&mut self, fd: i32, mode: i32) -> Outcome<i32> {
        if fd < 0 {
            return Ok(Err(Failed(-1, EBADF)));
        }
        Ok(self
            .opened
            .descriptor_set_mode(fd as u32, mode as u32)
            .map(|previous| previous as i32)
            .map_err(|errno| Failed(-1, errno)))
    }

    /// `_fileno`. The descriptor of a stream: 0, 1 or 2 for the standard
    /// ones, a shared descriptor for one `fopen` returned. -1 with
    /// `EINVAL` for a null stream; a pointer that is no stream stops the
    /// guest.
    pub(super) fn descriptor_of(&mut self, file: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        Ok(match self.stream(file)? {
            Stream::Input => Ok(0),
            Stream::Output => Ok(1),
            Stream::Error => Ok(2),
            Stream::File(file) => self
                .opened
                .descriptor_of(file)
                .map(|fd| fd as i32)
                .map_err(|errno| Failed(-1, errno)),
        })
    }

    /// `_isatty`. Nothing here is a character device: the standard input is
    /// what the host supplied and the output is captured, so the answer is
    /// always 0. An invalid descriptor is 0 with `EBADF` in errno.
    pub(super) fn is_terminal(&mut self, fd: i32) -> Outcome<i32> {
        if fd < 0 {
            return Ok(Err(Failed(0, EBADF)));
        }
        if fd < 3 {
            if self.opened.closed[fd as usize] && !self.opened.has_descriptor(fd as u32) {
                return Ok(Err(Failed(0, EBADF)));
            }
            return Ok(Ok(0));
        }
        Ok(if self.opened.has_descriptor(fd as u32) {
            Ok(0)
        } else {
            Err(Failed(0, EBADF))
        })
    }

    /// `ungetc`. The byte pushed, or -1 with `EBADF` for a stream that is
    /// not open and readable in the byte orientation. EOF in is EOF out
    /// with nothing done, as ISO C 7.21.7.10 says.
    pub(super) fn ungetc(&mut self, c: i32, file: u64) -> Outcome<i32> {
        if c == -1 {
            return Ok(Ok(-1));
        }
        let byte = c as u8;
        Ok(match self.opened.ungetc_byte(file, byte) {
            std::result::Result::Ok(()) => Ok(i32::from(byte)),
            std::result::Result::Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `_open_osfhandle`: the descriptor number wrapping the kernel handle,
    /// which the CRT takes ownership of. -1 with `EBADF` for a handle that
    /// is no kernel pipe end — the only object this interop knows.
    pub(super) fn open_osfhandle(&mut self, drive: &ObjectState, handle: u64) -> Outcome<i32> {
        Ok(match self.opened.descriptor_open_handle(drive, handle) {
            std::result::Result::Ok(fd) => Ok(fd as i32),
            std::result::Result::Err(errno) => Err(Failed(-1, errno)),
        })
    }

    /// `_get_osfhandle`: the kernel handle a descriptor wraps, as an
    /// `intptr_t`. A CRT-opened file synthesizes the kernel object the real
    /// CRT always has behind its descriptors, lazily (#1312); -1 with
    /// `EBADF` for a descriptor that is no file at all.
    pub(super) fn get_osfhandle(
        &mut self,
        drive: &mut super::ObjectState,
        fd: i32,
    ) -> Outcome<u64> {
        if fd < 0 {
            return Ok(Err(Failed(u64::MAX, EBADF)));
        }
        Ok(match self.opened.descriptor_handle(drive, fd as u32) {
            std::result::Result::Ok(handle) => Ok(handle),
            std::result::Result::Err(errno) => Err(Failed(u64::MAX, errno)),
        })
    }

    /// `_filbuf`. The byte as an unsigned char, or EOF at the end or for a
    /// stream that is not open and readable. The standard streams are not
    /// opened files: `stdin` consumes the host-supplied input exactly as
    /// `fgetc` does, and the output streams cannot be read.
    pub(super) fn filbuf(&mut self, drive: &ObjectState, file: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        // A pointer that is no stream answers EOF with EBADF rather than
        // stopping the guest: the primitive has always failed softly, and
        // the byte-oriented CRT reaches it for every small read.
        let stream = match self.stream(file) {
            std::result::Result::Ok(stream) => stream,
            std::result::Result::Err(_) => return Ok(Err(Failed(-1, EBADF))),
        };
        match stream {
            Stream::Input => {
                if self.opened.closed[0] || !self.input.orient(false) {
                    return Ok(Err(Failed(-1, EBADF)));
                }
                if self.opened.has_descriptor(0) {
                    return match self.opened.descriptor_read(drive, 0, 1) {
                        std::result::Result::Ok(bytes) if !bytes.is_empty() => {
                            Ok(Ok(i32::from(bytes[0])))
                        }
                        std::result::Result::Ok(_) => Ok(Ok(-1)),
                        std::result::Result::Err(errno) => Ok(Err(Failed(-1, errno))),
                    };
                }
                Ok(Ok(match self.input.character() {
                    Some(byte) => i32::from(byte),
                    None => -1,
                }))
            }
            Stream::File(file) => Ok(match self.opened.read_one(drive, file) {
                std::result::Result::Ok(Some(byte)) => Ok(i32::from(byte)),
                std::result::Result::Ok(None) => Ok(-1),
                std::result::Result::Err(errno) => Err(Failed(-1, errno)),
            }),
            _ => Ok(Err(Failed(-1, EBADF))),
        }
    }

    /// `_flsbuf`. The byte written, or EOF for a stream that is not open
    /// and writable. The standard streams are not opened files: a byte for
    /// `stdout` or `stderr` goes through the same capture and text-mode
    /// translation as every other write, and `stdin` cannot be written.
    pub(super) fn flsbuf(&mut self, drive: &mut ObjectState, c: i32, file: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let stream = match self.stream(file) {
            std::result::Result::Ok(stream) => stream,
            std::result::Result::Err(_) => return Ok(Err(Failed(-1, EBADF))),
        };
        match stream {
            Stream::Input => Ok(Err(Failed(-1, EBADF))),
            stream @ (Stream::Output | Stream::Error) => {
                match self.write(drive, stream, &[c as u8])? {
                    std::result::Result::Ok(()) => Ok(Ok(i32::from(c as u8))),
                    std::result::Result::Err(errno) => Ok(Err(Failed(-1, errno))),
                }
            }
            Stream::File(file) => Ok(match self.opened.write_one(drive, file, c as u8) {
                std::result::Result::Ok(()) => Ok(i32::from(c as u8)),
                std::result::Result::Err(errno) => Err(Failed(-1, errno)),
            }),
        }
    }

    /// `feof`: the end-of-file indicator of the stream. Only the standard
    /// input can end here; the captured output streams cannot be read, and
    /// file streams do not expose theirs yet.
    /// `feof`: the end-of-file indicator of the stream. The captured output
    /// streams cannot be read and report 0.
    pub(super) fn end_of_file(&mut self, file: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.stream(file)? {
            Stream::Input => Ok(Ok(i32::from(self.input.eof))),
            Stream::File(file) => Ok(Ok(i32::from(self.opened.end_of_file(file)))),
            Stream::Output | Stream::Error => Ok(Ok(0)),
        }
    }

    /// `ferror`: the error indicator of the stream. The captured streams
    /// report 0, as their writes have no failure mode; a file stream's
    /// indicator is the one its failed writes set.
    pub(super) fn error_indicator(&mut self, file: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.stream(file)? {
            Stream::File(file) => Ok(Ok(i32::from(self.opened.error_flag(file)))),
            Stream::Input | Stream::Output | Stream::Error => Ok(Ok(0)),
        }
    }

    /// `clearerr`: the end-of-file and error indicators off. Nothing is
    /// returned; a null stream only sets `errno` to `EINVAL`, which the
    /// handler does. The captured output streams have no indicators.
    pub(super) fn clear_errors(&mut self, file: u64) -> Result<(), ExitReason> {
        if file == 0 {
            return Ok(());
        }
        match self.stream(file)? {
            Stream::Input => self.input.eof = false,
            Stream::File(file) => {
                self.opened.clear_errors(file);
            }
            Stream::Output | Stream::Error => {}
        }
        Ok(())
    }

    /// `fopen_s`: `fopen` through a pointer, as the secure form. The error
    /// number is the result and `errno` at once, and the pointer holds null
    /// whenever the call does not succeed. A null argument, an empty or
    /// overlong name or mode, or a string it cannot read is `EINVAL`; the
    /// invalid parameter handler is not modelled. An output pointer it
    /// cannot write stops the guest with a fault.
    pub(super) fn open_secure(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        file: u64,
        name: u64,
        mode: u64,
        default_binary: bool,
    ) -> Outcome<i32> {
        // Null the output, then answer EINVAL as both the result and errno.
        let invalid = |memory: &mut GuestMemory| -> Outcome<i32> {
            memory.write_u64(file, 0).map_err(fault)?;
            Ok(Err(Failed(EINVAL as i32, EINVAL)))
        };
        if file == 0 {
            return Ok(Err(Failed(EINVAL as i32, EINVAL)));
        }
        if name == 0 || mode == 0 {
            return invalid(memory);
        }
        let (Ok(name_bytes), Ok(mode_bytes)) = (
            c_string(memory, name, MAX_NAME + 1),
            c_string(memory, mode, MAX_NAME + 1),
        ) else {
            return invalid(memory);
        };
        if name_bytes.is_empty()
            || mode_bytes.is_empty()
            || name_bytes.len() as u64 > MAX_NAME
            || mode_bytes.len() as u64 > MAX_NAME
        {
            return invalid(memory);
        }
        let Some(name_resolved) = self.resolve_path(&name_bytes) else {
            return invalid(memory);
        };
        match self.opened.open(
            memory,
            drive,
            name_resolved.as_bytes(),
            &mode_bytes,
            default_binary,
        ) {
            Ok(stream) => {
                memory.write_u64(file, stream).map_err(fault)?;
                Ok(Ok(0))
            }
            Err(errno) => {
                memory.write_u64(file, 0).map_err(fault)?;
                Ok(Err(Failed(errno as i32, errno)))
            }
        }
    }

    /// The bytes the guest reads from `stdin`, before any text-mode
    /// replacement. A CR LF pair becomes one line feed; a CR alone stays.
    pub(super) fn set_input(&mut self, bytes: &[u8]) {
        let mut translated = Vec::with_capacity(bytes.len());
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at] == b'\r' && bytes.get(at + 1) == Some(&b'\n') {
                // The CR of a pair is dropped; the LF is pushed next round.
            } else {
                translated.push(bytes[at]);
            }
            at += 1;
        }
        // A refill keeps the orientation: it belongs to the stream, not to
        // the buffer.
        let orientation = self.input.orientation;
        self.input = Input {
            bytes: translated,
            position: 0,
            eof: false,
            orientation,
        };
    }

    /// Console output: bytes appended to the same capture `fwrite` uses, so
    /// `printf` and `WriteConsole` interleave in order. `error` selects the
    /// error capture instead of the output one.
    pub(super) fn console_write(&mut self, error: bool, bytes: &[u8]) {
        let capture = if error {
            &mut self.error
        } else {
            &mut self.output
        };
        capture.extend_from_slice(bytes);
    }

    /// One console input line: up to `limit` bytes ending after the first
    /// line feed, which the console hands back as CR LF. The input itself
    /// keeps its LF translation; only the console answer gains the CR.
    pub(super) fn console_line(&mut self, limit: usize) -> Vec<u8> {
        let mut line = Vec::new();
        while line.len() + 1 < limit {
            match self.input.character() {
                Some(b'\n') => {
                    line.push(b'\r');
                    line.push(b'\n');
                    break;
                }
                Some(byte) => line.push(byte),
                None => break,
            }
        }
        line
    }

    /// `fflush`. A null stream means every open stream. Nothing is ever held
    /// back, so there is nothing to do.
    pub(super) fn flush(&self, file: u64) -> Result<i32, ExitReason> {
        if file != 0 {
            self.stream(file)?;
        }
        Ok(0)
    }

    /// `setvbuf`. The mode and size are checked as documented and then have
    /// no effect.
    pub(super) fn set_buffer(&self, file: u64, mode: i32, size: u64) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        self.stream(file)?;
        let valid = match mode {
            // "No buffer is used, regardless of buffer or size."
            IONBF => true,
            // "Allowable range: 2 <= size <= INT_MAX".
            IOFBF | IOLBF => (2..=i32::MAX as u64).contains(&size),
            _ => false,
        };
        Ok(if valid {
            Ok(0)
        } else {
            Err(Failed(-1, EINVAL))
        })
    }

    /// `setbuf`, the legacy reduction of `setvbuf`: a null buffer selects
    /// no buffering, anything else full buffering with the documented 512
    /// of `BUFSIZ`. Output here is never held back either way, so past the
    /// stream validation there is nothing to do - immediate delivery is
    /// the unbuffered end of what every mode permits.
    pub(super) fn set_buffer_legacy(&self, file: u64) -> Outcome<()> {
        if file == 0 {
            return Ok(Err(Failed((), EINVAL)));
        }
        self.stream(file)?;
        Ok(Ok(()))
    }

    /// `fopen`. Returns the new `FILE*`, or null with the `errno` value.
    pub(super) fn open(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        mode: u64,
        default_binary: bool,
    ) -> Outcome<u64> {
        // A null name or mode is an invalid parameter, as an empty one is.
        if name == 0 || mode == 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let name = c_string(memory, name, MAX_NAME + 1).map_err(fault)?;
        let mode = c_string(memory, mode, MAX_NAME + 1).map_err(fault)?;
        if name.len() as u64 > MAX_NAME || mode.len() as u64 > MAX_NAME {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let Some(name) = self.resolve_path(&name) else {
            return Ok(Err(Failed(0, EINVAL)));
        };
        Ok(self
            .opened
            .open(memory, drive, name.as_bytes(), &mode, default_binary)
            .map_err(|errno| Failed(0, errno)))
    }

    /// `tmpfile`: a stream open for reading and writing in binary, deleted
    /// when it closes.
    pub(super) fn open_temporary(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
    ) -> Outcome<u64> {
        Ok(self
            .opened
            .open_temporary(memory, drive)
            .map_err(|errno| Failed(0, errno)))
    }

    /// `tmpnam`: a name no file on the drive holds, into the caller's
    /// buffer, or into a static buffer allocated once when `buffer` is
    /// null, as the CRT does. The buffer is `L_tmpnam` bytes; 260 are
    /// allocated, as the names never come close.
    pub(super) fn temporary_name(
        &mut self,
        memory: &mut GuestMemory,
        drive: &ObjectState,
        buffer: u64,
    ) -> Outcome<u64> {
        let buffer = if buffer == 0 {
            if self.temporary_static == 0 {
                let allocated = memory
                    .map_heap_allocation(PROCESS_HEAP, 260)
                    .map_err(fault)?;
                self.temporary_static = allocated;
            }
            self.temporary_static
        } else {
            buffer
        };
        let mut name = self.opened.temporary_name(drive).into_bytes();
        name.push(0);
        memory.write_bytes(buffer, &name).map_err(fault)?;
        Ok(Ok(buffer))
    }

    /// `fclose`. Returns 0, or `EOF` with `EINVAL` for a null stream. Closing
    /// a standard stream is not modelled.
    pub(super) fn close(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        file: u64,
    ) -> Outcome<i32> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.stream(file)? {
            Stream::File(file) => {
                self.opened.close(memory, drive, file);
                Ok(Ok(0))
            }
            // Closing a standard stream is legal on Windows - the CRT does
            // not reserve them - and every later operation on the descriptor
            // fails with EBADF, exactly as `_close` of the descriptor itself
            // behaves. awk and other filter applets close their input when
            // it reaches EOF, before exit (#1273).
            Stream::Input => self.close_descriptor(memory, drive, 0),
            Stream::Output => self.close_descriptor(memory, drive, 1),
            Stream::Error => self.close_descriptor(memory, drive, 2),
        }
    }

    /// `_ftelli64`: the position of a file stream, or -1 with `EINVAL` for a
    /// null stream. The standard streams have no position here: telling
    /// one is not modelled and stops the guest.
    pub(super) fn tell(&self, file: u64) -> Outcome<i64> {
        if file == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.stream(file)? {
            Stream::File(file) => Ok(self
                .opened
                .tell(file)
                .map(|position| position as i64)
                .map_err(|errno| Failed(-1, errno))),
            _ => Err(RUNTIME_LIMIT),
        }
    }

    /// `_fseeki64`: 0, or -1 with `EINVAL` for a null stream, an origin
    /// other than `SEEK_SET`, `SEEK_CUR` or `SEEK_END`, or a position before
    /// the start. Seeking a standard stream is not modelled.
    pub(super) fn seek(
        &mut self,
        drive: &ObjectState,
        file: u64,
        offset: i64,
        origin: u32,
    ) -> Outcome<i32> {
        if file == 0 || origin > 2 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.stream(file)? {
            Stream::File(file) => Ok(self
                .opened
                .seek(drive, file, offset, origin)
                .map(|()| 0)
                .map_err(|errno| Failed(-1, errno))),
            _ => Err(RUNTIME_LIMIT),
        }
    }

    /// `fgetpos`: the position into the guest's `fpos_t`, an `__int64` in
    /// the Universal CRT. 0, or -1 with `EINVAL` for a null argument. A
    /// `fpos_t` that cannot be written stops the guest with a fault.
    pub(super) fn get_position(
        &self,
        memory: &mut GuestMemory,
        file: u64,
        position: u64,
    ) -> Outcome<i32> {
        if file == 0 || position == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        match self.tell(file)? {
            Ok(at) => {
                memory.write_u64(position, at as u64).map_err(fault)?;
                Ok(Ok(0))
            }
            Err(Failed(_, errno)) => Ok(Err(Failed(-1, errno))),
        }
    }

    /// `fsetpos`: move to the position a `fpos_t` holds, as `_fseeki64`
    /// from the start does.
    pub(super) fn set_position(
        &mut self,
        memory: &GuestMemory,
        drive: &ObjectState,
        file: u64,
        position: u64,
    ) -> Outcome<i32> {
        if file == 0 || position == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let at = memory.read_u64(position).map_err(fault)? as i64;
        self.seek(drive, file, at, 0)
    }

    /// `remove`: delete a file. 0, or -1 with `ENOENT` for a name the drive
    /// does not hold or rejects, `EACCES` for a directory, `EINVAL` for a
    /// null name. An open stream does not stop it, as streams take no part
    /// in sharing here; its later operations fail with `EBADF`.
    pub(super) fn remove_file(
        &self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
    ) -> Outcome<i32> {
        let Some(path) = self.drive_name_resolved(memory, name)? else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        let Some(path) = path else {
            return Ok(Err(Failed(-1, ENOENT)));
        };
        Ok(match drive.drive_entry(&path) {
            DriveEntry::File => {
                drive.drive_remove(&path);
                Ok(0)
            }
            DriveEntry::Directory => Err(Failed(-1, EACCES)),
            DriveEntry::Missing { .. } => Err(Failed(-1, ENOENT)),
        })
    }

    /// `rename`: give a file a new name. 0, or -1 with `ENOENT` when the old
    /// name holds nothing, `EACCES` when the new name already exists or its
    /// directory does not, `EINVAL` for a null or rejected name. Renaming a
    /// directory is not modelled and stops the guest.
    pub(super) fn rename_file(
        &self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        from: u64,
        to: u64,
    ) -> Outcome<i32> {
        let (Some(from), Some(to)) = (
            self.drive_name_resolved(memory, from)?,
            self.drive_name_resolved(memory, to)?,
        ) else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        let (Some(from), Some(to)) = (from, to) else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        match drive.drive_entry(&from) {
            DriveEntry::File => {}
            DriveEntry::Directory => return Err(RUNTIME_LIMIT),
            DriveEntry::Missing { .. } => return Ok(Err(Failed(-1, ENOENT))),
        }
        Ok(match drive.drive_entry(&to) {
            DriveEntry::Missing { parent: true } => {
                drive.drive_rename(&from, &to);
                Ok(0)
            }
            _ => Err(Failed(-1, EACCES)),
        })
    }

    /// `fgets`. Returns `buffer`, or null at end of file or on an error.
    pub(super) fn get_line(
        &mut self,
        memory: &mut GuestMemory,
        drive: &ObjectState,
        buffer: u64,
        count: i32,
        file: u64,
    ) -> Outcome<u64> {
        if buffer == 0 || file == 0 || count <= 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        // Up to count - 1 characters, and then the terminator.
        let limit = ((count - 1) as u64).min(MAX_TRANSFER) as usize;
        let line = match self.stream(file)? {
            Stream::File(file) => match self.opened.read_line(drive, file, limit) {
                Ok(line) => line,
                Err(errno) => return Ok(Err(Failed(0, errno))),
            },
            Stream::Input => self.input.line(limit),
            // The output streams cannot be read.
            Stream::Output | Stream::Error => return Ok(Err(Failed(0, EBADF))),
        };
        // End of file with nothing read: null, and the buffer is left alone.
        let Some(mut line) = line else {
            return Ok(Ok(0));
        };
        line.push(0);
        memory.write_bytes(buffer, &line).map_err(fault)?;
        Ok(Ok(buffer))
    }

    /// `fputws`: every wide character of the string written as its byte in
    /// the C locale. `WEOF` (as u32, 0xFFFF) when one is above 255, when the
    /// stream is oriented byte, or when the write itself fails.
    pub(super) fn write_wide_string(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        string: u64,
        file: u64,
    ) -> Outcome<u32> {
        if file == 0 || string == 0 {
            return Ok(Err(Failed(0xFFFF, EINVAL)));
        }
        let mut bytes = Vec::new();
        for at in 0..MAX_TRANSFER / 2 {
            let unit = memory.read_u16(string + at * 2).map_err(fault)?;
            if unit == 0 {
                break;
            }
            let Ok(byte) = u8::try_from(unit) else {
                return Ok(Err(Failed(0xFFFF, crt_files::EILSEQ)));
            };
            bytes.push(byte);
        }
        let stream = self.writable(file)?;
        match stream {
            Stream::File(file) => {
                // The file layer owns conversion and orientation there; hand
                // it the wide units, not the bytes.
                let mut wide = Vec::with_capacity(bytes.len());
                for byte in &bytes {
                    wide.push(u16::from(*byte));
                }
                match self.opened.write_wide(drive, file, &wide) {
                    Ok(true) => Ok(Ok(0)),
                    Ok(false) | Err(_) => Ok(Err(Failed(0xFFFF, EBADF))),
                }
            }
            Stream::Input => Ok(Err(Failed(0xFFFF, EBADF))),
            Stream::Output | Stream::Error => {
                let orientation = if stream == Stream::Output {
                    &mut self.output_orientation
                } else {
                    &mut self.error_orientation
                };
                if *orientation == 0 {
                    *orientation = 2;
                }
                if *orientation == 1 {
                    return Ok(Err(Failed(0xFFFF, EBADF)));
                }
                match self.write_wide_captured(stream, &bytes) {
                    Ok(()) => Ok(Ok(0)),
                    Err(reason) => Err(reason),
                }
            }
        }
    }

    /// The wide write on a captured output: the bytes are already converted;
    /// the capture is text mode, as the byte write is.
    fn write_wide_captured(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ExitReason> {
        let captured = match stream {
            Stream::Output => &mut self.output,
            Stream::Error => &mut self.error,
            _ => unreachable!(),
        };
        let feeds = bytes.iter().filter(|byte| **byte == b'\n').count();
        if bytes.len() + feeds > MAX_CAPTURED_OUTPUT - captured.len() {
            return Err(RUNTIME_LIMIT);
        }
        for &byte in bytes {
            if byte == b'\n' {
                captured.push(b'\r');
            }
            captured.push(byte);
        }
        Ok(())
    }

    /// `fgetws`: up to `count - 1` wide characters, stopping after a line
    /// feed. Null at end of file, on an orientation conflict, or for the
    /// output streams — `fgetws` answers null to all three, as `fgets` does.
    pub(super) fn read_wide_line(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        buffer: u64,
        count: u64,
        file: u64,
    ) -> Outcome<u64> {
        if buffer == 0 || file == 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        if count == 0 {
            return Ok(Ok(0));
        }
        let limit = ((count - 1).min(MAX_TRANSFER / 2)) as usize;
        let wide: Option<Vec<u16>> = match self.stream(file)? {
            Stream::File(file) => match self.opened.read_wide_line(drive, file, limit) {
                Ok(line) => line,
                Err(errno) => return Ok(Err(Failed(0, errno))),
            },
            Stream::Input => {
                if !self.input.orient(true) {
                    None
                } else {
                    let mut line = Vec::new();
                    while line.len() < limit {
                        match self.input.character() {
                            Some(byte) => {
                                line.push(u16::from(byte));
                                if byte == b'\n' {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    if line.is_empty() { None } else { Some(line) }
                }
            }
            Stream::Output | Stream::Error => return Ok(Err(Failed(0, EBADF))),
        };
        let Some(mut wide) = wide else {
            return Ok(Ok(0));
        };
        wide.push(0);
        let mut stored = Vec::with_capacity(wide.len() * 2);
        for unit in &wide {
            stored.extend(unit.to_le_bytes());
        }
        memory.write_bytes(buffer, &stored).map_err(fault)?;
        Ok(Ok(buffer))
    }

    /// `putwchar`: one wide character to the standard output, or `WEOF`.
    pub(super) fn wide_character_stdout(&mut self, unit: u32) -> Outcome<u32> {
        let Some(unit16) = u16::try_from(unit).ok() else {
            return Ok(Err(Failed(0xFFFF, EINVAL)));
        };
        let Ok(byte) = u8::try_from(unit16) else {
            return Ok(Err(Failed(0xFFFF, crt_files::EILSEQ)));
        };
        if self.output_orientation == 0 {
            self.output_orientation = 2;
        }
        if self.output_orientation == 1 {
            return Ok(Err(Failed(0xFFFF, EBADF)));
        }
        self.write_wide_captured(Stream::Output, &[byte])?;
        Ok(Ok(u32::from(unit16)))
    }

    /// `fputwc`: one wide character to a stream, or `WEOF`. The conversion
    /// is the C locale's: the byte of the character, nothing above 255.
    pub(super) fn write_wide_unit(
        &mut self,
        drive: &mut ObjectState,
        unit: u32,
        file: u64,
    ) -> Outcome<u32> {
        if file == 0 {
            return Ok(Err(Failed(0xFFFF, EINVAL)));
        }
        let Some(unit16) = u16::try_from(unit).ok() else {
            return Ok(Err(Failed(0xFFFF, EINVAL)));
        };
        let Ok(byte) = u8::try_from(unit16) else {
            return Ok(Err(Failed(0xFFFF, crt_files::EILSEQ)));
        };
        let stream = self.writable(file)?;
        match stream {
            Stream::Input => Ok(Err(Failed(0xFFFF, EBADF))),
            Stream::File(file) => match self.opened.write_wide(drive, file, &[unit16]) {
                Ok(true) => Ok(Ok(u32::from(unit16))),
                Ok(false) | Err(_) => Ok(Err(Failed(0xFFFF, EBADF))),
            },
            Stream::Output | Stream::Error => {
                let orientation = if stream == Stream::Output {
                    &mut self.output_orientation
                } else {
                    &mut self.error_orientation
                };
                if *orientation == 0 {
                    *orientation = 2;
                }
                if *orientation == 1 {
                    return Ok(Err(Failed(0xFFFF, EBADF)));
                }
                self.write_wide_captured(stream, &[byte])?;
                Ok(Ok(u32::from(unit16)))
            }
        }
    }

    /// `getwchar`: one wide character from the standard input, or `WEOF` at
    /// the end or on an orientation conflict — both answer `WEOF`.
    pub(super) fn wide_character_stdin(&mut self) -> u32 {
        if !self.input.orient(true) {
            return 0xFFFF;
        }
        match self.input.character() {
            Some(byte) => u32::from(byte),
            None => 0xFFFF,
        }
    }

    /// `_wfopen`: the wide form of `open`; the name and the mode are
    /// UTF-16. Anything beyond ASCII in either is a name or mode the drive
    /// rejects, as a rejected narrow one is.
    pub(super) fn open_wide(
        &mut self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        mode: u64,
        default_binary: bool,
    ) -> Outcome<u64> {
        if name == 0 || mode == 0 {
            return Ok(Err(Failed(0, EINVAL)));
        }
        let Some(Some(path)) = self.drive_name_wide_resolved(memory, name)? else {
            return Ok(Err(Failed(0, EINVAL)));
        };
        let mode = wide_ascii(memory, mode, 16).map_err(|_| RUNTIME_LIMIT)?;
        Ok(self
            .opened
            .open(memory, drive, path.as_bytes(), &mode, default_binary)
            .map_err(|errno| Failed(0, errno)))
    }

    /// `_unlink` and `_wunlink`: delete a file. 0, or -1 with `ENOENT` for
    /// a name the drive does not hold, `EACCES` for a directory or a
    /// read-only file, `EINVAL` for a null or rejected name.
    pub(super) fn unlink_file(
        &self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        wide: bool,
    ) -> Outcome<i32> {
        let resolved = if wide {
            self.drive_name_wide_resolved(memory, name)?
        } else {
            self.drive_name_resolved(memory, name)?
        };
        let Some(Some(path)) = resolved else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        Ok(match drive.drive_entry(&path) {
            DriveEntry::File => {
                if drive.drive_remove(&path) {
                    Ok(0)
                } else {
                    Err(Failed(-1, EACCES))
                }
            }
            DriveEntry::Directory => Err(Failed(-1, EACCES)),
            DriveEntry::Missing { .. } => Err(Failed(-1, ENOENT)),
        })
    }

    /// `_access` and `_waccess`: whether the name exists, and whether it
    /// answers the mode bits. 0, or -1 with `ENOENT` for a missing name,
    /// `EACCES` when a write bit meets a read-only file, `EINVAL` for a
    /// null or rejected name or a mode with other bits.
    pub(super) fn access_file(
        &self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        wide: bool,
        mode: u32,
    ) -> Outcome<i32> {
        if mode & !6 != 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        }
        let resolved = if wide {
            self.drive_name_wide_resolved(memory, name)?
        } else {
            self.drive_name_resolved(memory, name)?
        };
        let Some(Some(path)) = resolved else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        Ok(match drive.drive_entry(&path) {
            DriveEntry::File | DriveEntry::Directory => {
                if mode & 2 != 0 && drive.drive_is_readonly(&path) {
                    Err(Failed(-1, EACCES))
                } else {
                    Ok(0)
                }
            }
            DriveEntry::Missing { .. } => Err(Failed(-1, ENOENT)),
        })
    }

    /// `_wmkdir`: create a directory. 0, or -1 with `EACCES` when the name
    /// is taken, `ENOENT` when its parent is missing, `EINVAL` for a null
    /// or rejected name.
    pub(super) fn make_dir_wide(
        &self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
    ) -> Outcome<i32> {
        let Some(Some(path)) = self.drive_name_wide_resolved(memory, name)? else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        match drive.drive_entry(&path) {
            DriveEntry::Missing { parent: true } => {
                if drive.drive_create_dir(&path) {
                    Ok(Ok(0))
                } else {
                    Ok(Err(Failed(-1, ENOSPC)))
                }
            }
            DriveEntry::Missing { parent: false } => Ok(Err(Failed(-1, ENOENT))),
            _ => Ok(Err(Failed(-1, EACCES))),
        }
    }

    /// `_chmod`: the narrow form. Only the read-only bit of the mode means
    /// anything here, exactly as the wide form: the drive's files are
    /// otherwise readable and writable.
    pub(super) fn chmod(
        &self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        mode: u32,
    ) -> Outcome<i32> {
        let Some(Some(path)) = self.drive_name_resolved(memory, name)? else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        if drive.drive_chmod(&path, mode & 0x80 == 0) {
            Ok(Ok(0))
        } else {
            Ok(Err(Failed(-1, ENOENT)))
        }
    }

    /// `_wchmod`: the read-only bit of a file. 0, or -1 with `ENOENT` for a
    /// missing file, `EINVAL` for a null or rejected name. The other
    /// permission bits do not exist here: the drive's files are otherwise
    /// readable and writable.
    pub(super) fn chmod_wide(
        &self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        mode: u32,
    ) -> Outcome<i32> {
        let Some(Some(path)) = self.drive_name_wide_resolved(memory, name)? else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        if drive.drive_chmod(&path, mode & 0x80 == 0) {
            Ok(Ok(0))
        } else {
            Ok(Err(Failed(-1, ENOENT)))
        }
    }

    /// `_wstat64i32`: the 48-byte stat block of mingw-w64. The drive knows
    /// sizes and the read-only mark; the times answer -1 because it has no
    /// time stamps, the ids answer 0, the link count 1. The mode is the
    /// regular-file or directory bit, read always, write unless read-only.
    pub(super) fn stat_wide(
        &self,
        memory: &mut GuestMemory,
        drive: &mut ObjectState,
        name: u64,
        output: u64,
    ) -> Outcome<i32> {
        let Some(Some(path)) = self.drive_name_wide_resolved(memory, name)? else {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        if output == 0 {
            return Ok(Err(Failed(-1, EINVAL)));
        };
        let entry = drive.drive_entry(&path);
        let (present, directory, size) = match entry {
            DriveEntry::File => (
                true,
                false,
                drive.drive_file(&path).map_or(0, |f| f.len() as u64),
            ),
            DriveEntry::Directory => (true, true, 0),
            DriveEntry::Missing { .. } => (false, false, 0),
        };
        if !present {
            return Ok(Err(Failed(-1, ENOENT)));
        }
        let mut block = [0u8; 48];
        let readonly = drive.drive_is_readonly(&path);
        let mut mode: u16 = if directory { 0x4000 } else { 0x8000 } | 0x100;
        if !readonly {
            mode |= 0x80;
        }
        block[6..8].copy_from_slice(&mode.to_le_bytes());
        block[8..10].copy_from_slice(&1i16.to_le_bytes()); // st_nlink
        block[20..24].copy_from_slice(&(size as u32).to_le_bytes());
        for slot in [24, 32, 40] {
            block[slot..slot + 8].copy_from_slice(&(-1i64).to_le_bytes());
        }
        memory.write_bytes(output, &block).map_err(fault)?;
        Ok(Ok(0))
    }

    /// `perror`: the message, a colon and a space when there is a message,
    /// then the text for `errno` and a newline, to `stderr`.
    pub(super) fn report(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        message: u64,
        errno: u32,
    ) -> Result<(), ExitReason> {
        let mut text = Vec::new();
        if message != 0 {
            text = c_string(memory, message, MAX_TRANSFER + 1).map_err(fault)?;
            if text.len() as u64 > MAX_TRANSFER {
                return Err(RUNTIME_LIMIT);
            }
        }
        if !text.is_empty() {
            text.extend_from_slice(b": ");
        }
        text.extend_from_slice(crt_files::error_text(errno).as_bytes());
        text.push(b'\n');
        self.write(drive, Stream::Error, &text).map(|_| ())
    }

    /// `_assert`: "Assertion failed: <expression>, file <file>, line <line>"
    /// and a newline on `stderr`, then the process ends with status 3. The
    /// CRT's abort would raise SIGABRT first; no signal handler can exist
    /// here, so the end is immediate. The debug dialog does not exist either:
    /// there is no one to answer it.
    pub(super) fn assert_failure(
        &mut self,
        memory: &GuestMemory,
        drive: &mut ObjectState,
        expression: u64,
        file: u64,
        line: u32,
    ) -> Result<(), ExitReason> {
        let read = |address| {
            if address == 0 {
                return Ok(Vec::new());
            }
            c_string(memory, address, MAX_TRANSFER + 1).map_err(fault)
        };
        let expression = read(expression)?;
        let file = read(file)?;
        let mut text = b"Assertion failed: ".to_vec();
        text.extend_from_slice(&expression);
        text.extend_from_slice(b", file ");
        text.extend_from_slice(&file);
        text.extend_from_slice(format!(", line {line}\n").as_bytes());
        // The write is best-effort: even a stderr that cannot take the
        // message does not stop the assertion from ending the process.
        let _ = self.write(drive, Stream::Error, &text)?;
        Err(ExitReason::ProcessExit(3))
    }
}

/// The option bits the legacy CRT's printf family behaves with: the legacy
/// wide meaning of `%S` and `%C`, three-digit exponents, and the legacy
/// termination rules. The legacy rounding of floating-point conversions is
/// not modelled, so they are refused, as they are for the modern forms
/// without the rounding bit.
const LEGACY_PRINTF_OPTIONS: u64 =
    LEGACY_WIDE_SPECIFIERS | LEGACY_THREE_DIGIT_EXPONENTS | LEGACY_VSPRINTF_NULL_TERMINATION;

/// The legacy stream forms carry no buffer behaviour bits: their options
/// are the wide-specifier and exponent ones only.
const LEGACY_STREAM_PRINTF_OPTIONS: u64 = LEGACY_WIDE_SPECIFIERS | LEGACY_THREE_DIGIT_EXPONENTS;

/// Arguments of a legacy variadic form, read from the calling convention:
/// the positions after the fixed ones, registers first and then the stack,
/// as `Win64Args` extracts them. A floating-point variadic argument reaches
/// its integer slot as well, which is where this reads it.
struct VariadicArguments<'a> {
    args: &'a Win64Args,
    memory: &'a GuestMemory,
    next: usize,
}

impl Source for VariadicArguments<'_> {
    fn argument(&mut self) -> Result<u64, MemoryError> {
        let value = self.args.get(self.next, self.memory)?;
        self.next += 1;
        Ok(value)
    }

    fn string(&mut self, address: u64, limit: usize) -> Result<Vec<u8>, MemoryError> {
        c_string(self.memory, address, limit as u64)
    }
}

/// The registry answer of a legacy printf form: the value, with `errno` set
/// when the form failed.
fn printf_answer(
    memory: &mut GuestMemory,
    teb: u64,
    outcome: Outcome<i32>,
) -> Result<u64, ExitReason> {
    match outcome? {
        Ok(value) => Ok(value as u32 as u64),
        Err(Failed(value, errno)) => {
            super::crt::set_errno(memory, teb, errno)?;
            Ok(value as u32 as u64)
        }
    }
}

/// The legacy CRT's printf buffer forms (`msvcrt.dll`). `_vsnprintf`
/// terminates only when the text fits with room, as the legacy contract
/// says, and `_vscprintf` is the size query. `sprintf` is uncounted: the
/// terminator always follows the text, and a short buffer is the guest's
/// own overrun, exactly as on Windows.
/// The legacy CRT's `_iobuf` is 48 bytes on x64, as the mingw-w64 header
/// fixes it: `_ptr` 0, `_cnt` 8, `_base` 16, `_flag` 24, `_file` 28.
pub(super) const LEGACY_FILE_BYTES: u64 = 48;

pub(super) fn register_legacy(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    registry.register(MSVCRT, "_vsnprintf", |args, cpu, memory| {
        let outcome = print_to_buffer(
            memory,
            LEGACY_PRINTF_OPTIONS,
            args.rcx,
            args.rdx,
            args.r8,
            0,
            args.r9,
        );
        printf_answer(memory, cpu.gs_base, outcome)
    });
    registry.register(MSVCRT, "_vscprintf", |args, cpu, memory| {
        let outcome = print_to_buffer(memory, LEGACY_PRINTF_OPTIONS, 0, 0, args.rcx, 0, args.rdx);
        printf_answer(memory, cpu.gs_base, outcome)
    });
    registry.register(MSVCRT, "sprintf", |args, cpu, memory| {
        if args.rcx == 0 || args.rdx == 0 {
            super::crt::set_errno(memory, cpu.gs_base, EINVAL)?;
            return Ok(u64::from(u32::MAX));
        }
        let formatted = {
            let mut source = VariadicArguments {
                args,
                memory,
                next: 2,
            };
            format_with(
                memory,
                LEGACY_PRINTF_OPTIONS,
                args.rdx,
                0,
                &mut source,
                true,
            )?
        };
        let mut text = match formatted {
            Formatted::Invalid => {
                super::crt::set_errno(memory, cpu.gs_base, EINVAL)?;
                return Ok(u64::from(u32::MAX));
            }
            Formatted::Text(text) => text,
        };
        let len = text.len() as u32;
        text.push(0);
        memory.write_bytes(args.rcx, &text).map_err(fault)?;
        Ok(u64::from(len))
    });

    // `vfprintf` formats through the argument pointer the caller passes, in
    // the same shape the modern common entry point receives — the Win64
    // `va_list` is that pointer in both CRTs.
    let vfprintf_state = Arc::clone(state);
    registry.register(MSVCRT, "vfprintf", move |args, cpu, memory| {
        let outcome = {
            let mut streams = vfprintf_state.crt_streams();
            let mut drive = vfprintf_state.objects.lock().expect("guest object state");
            streams.print(
                memory,
                &mut drive,
                LEGACY_STREAM_PRINTF_OPTIONS,
                args.rcx,
                args.rdx,
                0,
                args.r8,
            )
        };
        printf_answer(memory, cpu.gs_base, outcome)
    });

    // `fprintf` reads its variadic arguments from the calling convention:
    // the stream and the format take the first two slots, so the arguments
    // start at the third. The formatted text is then written as the modern
    // entry point writes it.
    let fprintf_state = Arc::clone(state);
    registry.register(MSVCRT, "fprintf", move |args, cpu, memory| {
        if args.rcx == 0 || args.rdx == 0 {
            super::crt::set_errno(memory, cpu.gs_base, EINVAL)?;
            return Ok(u64::from(u32::MAX));
        }
        let formatted = {
            let mut source = VariadicArguments {
                args,
                memory,
                next: 2,
            };
            format_with(
                memory,
                LEGACY_STREAM_PRINTF_OPTIONS,
                args.rdx,
                0,
                &mut source,
                false,
            )?
        };
        let text = match formatted {
            Formatted::Invalid => {
                super::crt::set_errno(memory, cpu.gs_base, EINVAL)?;
                return Ok(u64::from(u32::MAX));
            }
            Formatted::Text(text) => text,
        };
        let outcome = {
            let mut streams = fprintf_state.crt_streams();
            let mut drive = fprintf_state.objects.lock().expect("guest object state");
            streams.write_formatted(&mut drive, args.rcx, &text)
        };
        printf_answer(memory, cpu.gs_base, outcome)
    });

    // `sscanf` scans the string its first argument names through the
    // variadic pointers the calling convention passes after the format.
    registry.register(MSVCRT, "sscanf", |args, _, memory| {
        if args.rcx == 0 || args.rdx == 0 {
            return Ok(u64::from(u32::MAX));
        }
        let input = crt_scan::scan_input_string(memory, args.rcx)?;
        let format = crt_scan::scan_input_string(memory, args.rdx)?;
        // The scan writes through the same memory the variadic reader
        // reads, so the slots are read first — as many as the format
        // consumes, no more.
        let needed = crt_scan::count_assignments(&format);
        let mut slots = Vec::with_capacity(needed);
        {
            let mut source = VariadicArguments {
                args,
                memory,
                next: 2,
            };
            for _ in 0..needed {
                slots.push(source.argument().map_err(fault)?);
            }
        }
        let mut next_slot = slots.iter();
        let scan = crt_scan::scan(memory, input, &format, || {
            Ok(*next_slot.next().unwrap_or(&0))
        });
        match scan {
            Ok(count) => Ok(count as u32 as u64),
            Err(crt_scan::ScanError::Unsupported) => Err(RUNTIME_LIMIT),
            Err(crt_scan::ScanError::Memory(error)) => Err(fault(error)),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::GuestMemory;
    use crate::services::ObjectState;

    fn fixture() -> (StandardStreams, GuestMemory, ObjectState) {
        let memory = GuestMemory::new();
        (StandardStreams::default(), memory, ObjectState::default())
    }

    /// A relative file name resolves against the working directory exactly
    /// as the CRT resolves it on Windows: `_chdir` into `x` makes `d` the
    /// drive's `x\\d`, while absolute input passes through unchanged, so
    /// tar's extraction after its chdir creates the archive's members under
    /// the target directory (#1336).
    #[test]
    fn relative_paths_resolve_against_the_working_directory() {
        let (mut streams, _memory, _drive) = fixture();
        assert_eq!(streams.resolve_path(b"d"), Some("d".to_owned()));
        streams.set_working_directory("x".to_owned());
        assert_eq!(streams.resolve_path(b"d"), Some("x\\d".to_owned()));
        assert_eq!(streams.resolve_path(b"./d"), Some("x\\d".to_owned()));
        assert_eq!(streams.resolve_path(b"..\\d"), Some("d".to_owned()));
        // An absolute name is already resolved: applying the resolution
        // again is idempotent, as the open paths resolving before the
        // drive's own canonicalisation rely on.
        assert_eq!(streams.resolve_path(b"c:\\y\\d"), Some("y\\d".to_owned()));
        // The copy a spawned child inherits keeps the directory at spawn
        // time, and the parent's later moves do not reach it, as on Windows.
        let child = streams.inherit_for_spawn();
        streams.set_working_directory("moved".to_owned());
        assert_eq!(child.resolve_path(b"d"), Some("x\\d".to_owned()));
        assert_eq!(streams.resolve_path(b"d"), Some("moved\\d".to_owned()));
    }

    /// A redirection `_dup2` onto a standard number routes the standard
    /// stream's writes through the descriptor machinery into the file, as
    /// the CRT writes its streams through descriptors 1 and 2; restoring
    /// the standard wiring returns the writes to the capture.
    #[test]
    fn standard_stream_writes_follow_a_rewired_descriptor_and_return_on_restore() {
        let (mut streams, mut memory, mut drive) = fixture();
        let _file = streams
            .opened
            .open(&mut memory, &mut drive, b"target", b"w", false)
            .expect("open");
        let file_fd = streams
            .opened
            .open_descriptor(&mut drive, b"target", 1, false)
            .expect("write descriptor");
        // The same write through the descriptor itself succeeds, so the
        // assertions below isolate the routing rather than the file.
        streams
            .opened
            .descriptor_write(&mut drive, file_fd, b"direct")
            .expect("direct write");
        // The shell's redirection frame saves stdout before rewiring it:
        // the duplication happens while 1 is still the standard stream.
        let saved = streams.opened.descriptor_duplicate(1).expect("save stdout");
        // Dup2 the file onto 1: writes through the stdout stream must reach
        // the file rather than the capture.
        streams
            .opened
            .descriptor_duplicate2(&mut memory, &mut drive, file_fd, 1)
            .expect("dup2 onto stdout");
        streams
            .write(&mut drive, Stream::Output, b"redirected")
            .expect("write")
            .expect("no errno");
        assert!(streams.output().is_empty());
        assert_eq!(drive.drive_file("target"), Some(&b"directredirected"[..]));
        // Restoring the standard wiring - `_dup2` of a saved copy of the
        // standard stream back onto 1 - returns the writes to the capture.
        streams
            .opened
            .descriptor_duplicate2(&mut memory, &mut drive, saved, 1)
            .expect("restore stdout");
        streams
            .write(&mut drive, Stream::Output, b"captured")
            .expect("write")
            .expect("no errno");
        assert_eq!(streams.output(), b"captured");
    }

    /// Closing a standard stream is legal: awk and other filter applets
    /// close their input when it reaches EOF, before exit, and the CRT does
    /// not reserve the standard streams (#1273). The close marks the
    /// descriptor closed exactly as `_close` of it does, every later
    /// operation fails, and a second close has nothing to close.
    #[test]
    fn fclose_of_a_standard_stream_closes_the_descriptor_once() {
        let (mut streams, mut memory, mut drive) = fixture();
        let stdin = streams.file(&mut memory, 0).expect("stdin object");
        // The close succeeds rather than stopping the guest.
        let closed = streams
            .close(&mut memory, &mut drive, stdin)
            .expect("no stop");
        assert!(matches!(closed, Ok(0)));
        // The descriptor is marked closed exactly as `_close(0)` marks it.
        assert!(streams.opened.closed[0]);
        // A second close fails rather than closing again.
        let twice = streams
            .close(&mut memory, &mut drive, stdin)
            .expect("no stop");
        assert!(matches!(twice, Err(_)));
    }

    /// A spawned child inherits a position snapshot of each file-backed
    /// descriptor, and the positions it leaves behind write back into the
    /// parent's streams: one advancing position across the two processes.
    #[test]
    fn spawn_inheritance_snapshots_positions_and_writes_the_childs_back() {
        let (mut parent, memory, mut drive) = fixture();
        drive.drive_create("shared");
        drive.drive_write("shared", 0, b"0123456789");
        let fd = parent
            .opened
            .open_descriptor(&mut drive, b"shared", 0, false)
            .expect("parent descriptor");
        let _ = memory;
        let _ = fd;
        // The parent reads two bytes before spawning: position 2 carries.
        let read = parent
            .opened
            .descriptor_read(&drive, fd, 2)
            .expect("parent read");
        assert_eq!(read, b"01");
        let mut child = parent.opened.inherit_for_spawn();
        // The child reads at the inherited position, not at the start.
        let child_fd = fd;
        let read = child
            .descriptor_read(&drive, child_fd, 2)
            .expect("child read");
        assert_eq!(read, b"23");
        // The positions the child leaves write back: the parent continues
        // where the child stopped, as one shared open file description.
        parent.opened.absorb_child_positions(&child);
        let read = parent
            .opened
            .descriptor_read(&drive, fd, 2)
            .expect("parent continues");
        assert_eq!(read, b"45");
    }
}
