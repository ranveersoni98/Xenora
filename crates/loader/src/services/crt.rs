// SPDX-License-Identifier: GPL-3.0-or-later

//! C runtime services that operate on checked guest memory.

use crate::cpu::ExitReason;
use crate::imports::{ImportRegistry, ServiceStatus, Win64Args};
use crate::memory::{GuestMemory, MemoryError, PROCESS_HEAP};
use crate::runtime::ServiceContext;

use std::sync::Arc;

use super::ServicesState;

use super::crt_files;
use super::crt_streams::{Failed, Outcome};

const SCAN_BUDGET: u64 = 1_048_576;

/// The honest refusal for a runtime service the machine cannot perform:
/// the guest stops explicitly rather than running on invented behaviour.
const RUNTIME_LIMIT: ExitReason = ExitReason::IllegalInstruction(0xFE);
pub(super) const UCRT: &str = "ucrtbase.dll";
const CRT_STRING_API: &str = "api-ms-win-crt-string-l1-1-0.dll";
/// The legacy CRT module that pre-UCRT mingw binaries import directly.
const MSVCRT: &str = "msvcrt.dll";

#[derive(Clone, Copy)]
enum StringUnit {
    Byte,
    Wide,
}

impl StringUnit {
    fn width(self) -> u64 {
        match self {
            Self::Byte => 1,
            Self::Wide => 2,
        }
    }

    fn read(self, memory: &GuestMemory, base: u64, offset: u64) -> Result<u16, ExitReason> {
        if base == 0 {
            return Err(ExitReason::MemoryFault(MemoryError::UnmappedAddress(0)));
        }
        let address = base
            .checked_add(offset * self.width())
            .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
        match self {
            Self::Byte => memory.read_u8(address).map(u16::from),
            Self::Wide => memory.read_u16(address),
        }
        .map_err(ExitReason::MemoryFault)
    }
}

fn string_length(
    memory: &GuestMemory,
    address: u64,
    limit: u64,
    unit: StringUnit,
) -> Result<u64, ExitReason> {
    const BLOCK: u64 = 256;
    let budget = SCAN_BUDGET / unit.width();
    let scan = limit.min(budget);
    let mut buffer = [0u8; 2 * BLOCK as usize];
    let mut offset = 0;
    while offset < scan {
        let count = BLOCK.min(scan - offset);
        let bytes = &mut buffer[..(count * unit.width()) as usize];
        // A block that crosses into unmapped or unreadable memory is scanned
        // one unit at a time, so a terminator before the boundary still ends
        // the scan and the fault reports the first inaccessible unit.
        let block = address
            .checked_add(offset * unit.width())
            .filter(|_| address != 0)
            .is_some_and(|start| memory.read_bytes(start, bytes).is_ok());
        for index in 0..count {
            let value = if block {
                match unit {
                    StringUnit::Byte => u16::from(bytes[index as usize]),
                    StringUnit::Wide => {
                        let at = 2 * index as usize;
                        u16::from_le_bytes([bytes[at], bytes[at + 1]])
                    }
                }
            } else {
                unit.read(memory, address, offset + index)?
            };
            if value == 0 {
                return Ok(offset + index);
            }
        }
        offset += count;
    }
    if limit <= budget {
        return Ok(limit);
    }
    Err(ExitReason::IllegalInstruction(0xFE))
}

fn compare_strings(
    memory: &GuestMemory,
    left: u64,
    right: u64,
    limit: u64,
    unit: StringUnit,
) -> Result<u64, ExitReason> {
    let budget = SCAN_BUDGET / unit.width();
    for offset in 0..limit.min(budget) {
        let a = unit.read(memory, left, offset)?;
        let b = unit.read(memory, right, offset)?;
        if a != b || a == 0 {
            return Ok(u64::from((i32::from(a) - i32::from(b)) as u32));
        }
    }
    if limit <= budget {
        return Ok(0);
    }
    Err(ExitReason::IllegalInstruction(0xFE))
}

fn transfer_buffer(count: u64, fill: u8) -> Result<Vec<u8>, ExitReason> {
    if count > SCAN_BUDGET {
        return Err(ExitReason::IllegalInstruction(0xFE));
    }
    let count = count as usize;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(count)
        .map_err(|_| ExitReason::MemoryFault(MemoryError::AllocationFailed))?;
    buffer.resize(count, fill);
    Ok(buffer)
}

pub(super) fn register(registry: &mut ImportRegistry) {
    for (length, bounded_length, compare, bounded_compare, unit) in [
        ("strlen", "strnlen", "strcmp", "strncmp", StringUnit::Byte),
        ("wcslen", "wcsnlen", "wcscmp", "wcsncmp", StringUnit::Wide),
    ] {
        registry.register(UCRT, length, move |args, _, memory| {
            string_length(memory, args.rcx, u64::MAX, unit)
        });
        registry.register(UCRT, bounded_length, move |args, _, memory| {
            string_length(memory, args.rcx, args.rdx, unit)
        });
        registry.register(UCRT, compare, move |args, _, memory| {
            compare_strings(memory, args.rcx, args.rdx, u64::MAX, unit)
        });
        registry.register(UCRT, bounded_compare, move |args, _, memory| {
            compare_strings(memory, args.rcx, args.rdx, args.r8, unit)
        });
        for symbol in [length, bounded_length, compare, bounded_compare] {
            registry.alias(CRT_STRING_API, UCRT, symbol);
            // The legacy CRT exports the same narrow and wide string forms.
            registry.alias(MSVCRT, UCRT, symbol);
            registry.set_status(UCRT, symbol, ServiceStatus::Partial);
        }
    }

    registry.register(UCRT, "memset", |args, _, memory| {
        if args.r8 != 0 {
            let buffer = transfer_buffer(args.r8, args.rdx as u8)?;
            memory
                .write_bytes(args.rcx, &buffer)
                .map_err(ExitReason::MemoryFault)?;
        }
        Ok(args.rcx)
    });

    for symbol in ["memcpy", "memmove"] {
        registry.register(UCRT, symbol, |args, _, memory| {
            if args.r8 != 0 {
                let mut buffer = transfer_buffer(args.r8, 0)?;
                memory
                    .read_bytes(args.rdx, &mut buffer)
                    .map_err(ExitReason::MemoryFault)?;
                memory
                    .write_bytes(args.rcx, &buffer)
                    .map_err(ExitReason::MemoryFault)?;
            }
            Ok(args.rcx)
        });
    }

    registry.register(UCRT, "memcmp", |args, _, memory| {
        if args.r8 == 0 {
            return Ok(0);
        }
        let mut left = transfer_buffer(args.r8, 0)?;
        let mut right = transfer_buffer(args.r8, 0)?;
        memory
            .read_bytes(args.rcx, &mut left)
            .map_err(ExitReason::MemoryFault)?;
        memory
            .read_bytes(args.rdx, &mut right)
            .map_err(ExitReason::MemoryFault)?;
        let result = left
            .iter()
            .zip(right)
            .find_map(|(&a, b)| (a != b).then_some(i32::from(a) - i32::from(b)))
            .unwrap_or(0);
        Ok(u64::from(result as u32))
    });

    for symbol in ["memset", "memcpy", "memmove", "memcmp"] {
        registry.alias(CRT_STRING_API, UCRT, symbol);
        // The legacy CRT exports the memory forms under the same names.
        registry.alias(MSVCRT, UCRT, symbol);
        registry.set_status(UCRT, symbol, ServiceStatus::Partial);
    }
    // The mingw-w64 C runtime imports `memcpy`, `memmove` and `memcmp`
    // through this API set.
    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "memcpy");
    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "memmove");
    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "memcmp");
}

const ENOMEM: u32 = 12;
pub(super) const EINVAL: u32 = 22;

pub(super) fn set_errno(memory: &mut GuestMemory, teb: u64, error: u32) -> Result<(), ExitReason> {
    let address = memory
        .crt_errno_address(teb)
        .map_err(ExitReason::MemoryFault)?;
    memory
        .write_u32(address, error)
        .map_err(ExitReason::MemoryFault)
}

fn allocation_result(
    memory: &mut GuestMemory,
    teb: u64,
    result: Result<u64, MemoryError>,
) -> Result<u64, ExitReason> {
    match result {
        Ok(address) => Ok(address),
        Err(_) => {
            set_errno(memory, teb, ENOMEM)?;
            Ok(0)
        }
    }
}

const ERANGE: u32 = 34;

fn parse_integer(
    memory: &mut GuestMemory,
    args: &Win64Args,
    teb: u64,
    signed: bool,
    wide_result: bool,
    unit: StringUnit,
) -> Result<u64, ExitReason> {
    let (address, end, mut radix) = (args.rcx, args.rdx, args.r8 as u32);
    if address == 0 || (radix != 0 && !(2..=36).contains(&radix)) {
        if end != 0 {
            memory
                .write_u64(end, address)
                .map_err(ExitReason::MemoryFault)?;
        }
        set_errno(memory, teb, EINVAL)?;
        return Ok(0);
    }

    let read = |index| {
        if index >= SCAN_BUDGET / unit.width() {
            return Err(ExitReason::IllegalInstruction(0xFE));
        }
        unit.read(memory, address, index)
            .map(|value| char::from_u32(u32::from(value)).unwrap_or(char::REPLACEMENT_CHARACTER))
    };
    let mut index = 0;
    let mut next = read(index)?;
    while matches!(next, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c') {
        index += 1;
        next = read(index)?;
    }
    let negative = next == '-';
    if matches!(next, '+' | '-') {
        index += 1;
        next = read(index)?;
    }
    if next == '0'
        && matches!(radix, 0 | 16)
        && matches!(read(index + 1)?, 'x' | 'X')
        && read(index + 2)?.is_ascii_hexdigit()
    {
        radix = 16;
        index += 2;
        next = read(index)?;
    }
    if radix == 0 {
        radix = if next == '0' { 8 } else { 10 };
    }

    let limit = match (wide_result, signed) {
        (false, false) => u64::from(u32::MAX),
        (false, true) => i32::MAX as u64 + u64::from(negative),
        (true, false) => u64::MAX,
        (true, true) => i64::MAX as u64 + u64::from(negative),
    };
    let start = index;
    let mut value = 0u64;
    let mut overflow = false;
    while let Some(digit) = next.to_digit(radix) {
        match value
            .checked_mul(u64::from(radix))
            .and_then(|v| v.checked_add(u64::from(digit)))
        {
            Some(v) if v <= limit => value = v,
            _ => overflow = true,
        }
        index += 1;
        next = read(index)?;
    }
    let consumed = if start == index { 0 } else { index };
    if end != 0 {
        let pointer = address
            .checked_add(consumed * unit.width())
            .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
        memory
            .write_u64(end, pointer)
            .map_err(ExitReason::MemoryFault)?;
    }
    if overflow {
        set_errno(memory, teb, ERANGE)?;
        value = limit;
    }
    if negative && (!overflow || signed) {
        value = value.wrapping_neg();
    }
    Ok(if wide_result {
        value
    } else {
        u64::from(value as u32)
    })
}

pub(super) fn register_conversions(registry: &mut ImportRegistry) {
    for (symbol, signed, wide_result, unit) in [
        ("strtol", true, false, StringUnit::Byte),
        ("strtoul", false, false, StringUnit::Byte),
        ("wcstol", true, false, StringUnit::Wide),
        ("wcstoul", false, false, StringUnit::Wide),
        ("strtoll", true, true, StringUnit::Byte),
        ("strtoull", false, true, StringUnit::Byte),
        ("wcstoll", true, true, StringUnit::Wide),
        ("wcstoull", false, true, StringUnit::Wide),
        ("_strtoi64", true, true, StringUnit::Byte),
        ("_strtoui64", false, true, StringUnit::Byte),
        ("_wcstoi64", true, true, StringUnit::Wide),
        ("_wcstoui64", false, true, StringUnit::Wide),
    ] {
        registry.register(UCRT, symbol, move |args, cpu, memory| {
            parse_integer(memory, args, cpu.gs_base, signed, wide_result, unit)
        });
        registry.alias("api-ms-win-crt-convert-l1-1-0.dll", UCRT, symbol);
        // The legacy CRT exports the narrow integer parses under the same
        // names; the wide forms are the legacy CRT's own spellings too.
        registry.alias(MSVCRT, UCRT, symbol);
        registry.set_status(UCRT, symbol, ServiceStatus::Partial);
    }
}

/// The console key input of the legacy CRT. `_getch` reads one key
/// without echo and `_getche` with it, directly from the console rather
/// than stdin. The machine's console input buffer is empty - no keyboard
/// exists - so a read would block the one executor forever. Blocking is
/// not modelled: the honest answer for a program that actually asks for a
/// key is to stop, while a program that merely imports the forms - the
/// common case, since the legacy CRT binds them transitively - runs
/// undisturbed.
/// The spawn family. A spawn creates another process, and the machine is
/// one process: there is no loader for a child and no kernel to schedule it.
/// The honest answer is the error the CRT documents for a failure, ENOSYS,
/// not a pretend success nothing ever runs behind. busybox imports
/// `_spawnve` for its applet spawning; programs that never spawn bind the
/// import undisturbed.
pub(super) fn register_spawn(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    for (module, symbol, wide) in [
        (UCRT, "_spawnve", false),
        (UCRT, "_wspawnve", true),
        (MSVCRT, "_spawnve", false),
        ("api-ms-win-crt-process-l1-1-0.dll", "_spawnve", false),
        ("api-ms-win-crt-process-l1-1-0.dll", "_wspawnve", true),
    ] {
        let s = Arc::clone(state);
        registry.register(module, symbol, move |args, cpu, memory| {
            spawnve(&s, args, cpu, memory, wide)
        });
        registry.set_status(module, symbol, ServiceStatus::Partial);
    }
}

/// `_P_WAIT`: the parent suspends until the child exits, and the spawn
/// returns the child's exit status. The other modes - nowait, overlay,
/// detach - are process topologies the machine does not have, so they keep
/// the honest ENOSYS refusal.
const P_WAIT: u64 = 0;

/// `_P_NOWAIT`: the spawn answers a process handle instead of the exit
/// status, and `_cwait`/`waitpid` collect the child later. The machine runs
/// the child to completion inside the spawn either way - process
/// concurrency does not exist - which is exact for the spawn-then-wait
/// pattern shells use, and documented in the PR as the limit for programs
/// that truly overlap parent and child.
const P_NOWAIT: u64 = 1;

/// The child runs with a generous but finite step budget: enough for real
/// applet work, bounded so a runaway child cannot hang the suspended parent
/// forever. Measured busybox applets take millions of steps, not billions.
const CHILD_STEP_BUDGET: usize = 1 << 28;

/// Read one NUL-terminated string, narrow or wide, with the scan budget the
/// other CRT string services use.
fn spawn_string(memory: &GuestMemory, address: u64, wide: bool) -> Result<Vec<u8>, ExitReason> {
    if address == 0 {
        return Err(RUNTIME_LIMIT);
    }
    let unit = if wide {
        StringUnit::Wide
    } else {
        StringUnit::Byte
    };
    let len = string_length(memory, address, 4096, unit)?;
    if len >= 4096 {
        return Err(RUNTIME_LIMIT);
    }
    let mut bytes = vec![0u8; (len * unit.width()) as usize];
    memory
        .read_bytes(address, &mut bytes)
        .map_err(ExitReason::MemoryFault)?;
    if wide {
        let mut narrow = Vec::with_capacity(len as usize);
        for index in 0..len as usize {
            let at = 2 * index;
            let unit = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
            if unit > 0xFF {
                // The synthetic narrow world is UTF-8 bytes; a wide argument
                // outside Latin-1 has no faithful narrow form.
                return Err(RUNTIME_LIMIT);
            }
            narrow.push(unit as u8);
        }
        return Ok(narrow);
    }
    Ok(bytes)
}

/// Read a `char *const *` vector: a NUL-terminated array of pointers to
/// NUL-terminated strings. Capped the way the CRT caps argument vectors.
fn spawn_string_vector(
    memory: &GuestMemory,
    address: u64,
    wide: bool,
) -> Result<Vec<Vec<u8>>, ExitReason> {
    let mut entries = Vec::new();
    for index in 0..256u64 {
        let pointer = memory
            .read_u64(address + index * 8)
            .map_err(ExitReason::MemoryFault)?;
        if pointer == 0 {
            return Ok(entries);
        }
        entries.push(spawn_string(memory, pointer, wide)?);
    }
    Err(RUNTIME_LIMIT)
}

fn spawnve(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    cpu: &mut crate::cpu::CpuState,
    memory: &mut GuestMemory,
    wide: bool,
) -> Result<u64, ExitReason> {
    const ENOENT: u32 = 2;
    const EINVAL: u32 = 22;
    let mode = args.rcx & 0xFFFF_FFFF;
    if mode != P_WAIT && mode != P_NOWAIT {
        set_errno(memory, cpu.gs_base, 40)?;
        return Ok(u64::MAX);
    }
    let image = match state.spawn_image() {
        Some(image) => image,
        None => {
            // No image was kept: there is nothing a child could run.
            set_errno(memory, cpu.gs_base, ENOENT)?;
            return Ok(u64::MAX);
        }
    };
    let command = spawn_string(memory, args.rdx, wide)?;
    let expected = state.spawn_image_name();
    let trailing = command
        .rsplit(|byte| *byte == b'\\' || *byte == b'/')
        .next()
        .unwrap_or(&command);
    if !trailing.eq_ignore_ascii_case(expected.as_bytes()) {
        // Only the program's own image can run today: the machine keeps no
        // other executable, so any other path is honestly not found.
        set_errno(memory, cpu.gs_base, ENOENT)?;
        return Ok(u64::MAX);
    }
    let argv_bytes = spawn_string_vector(memory, args.r8, wide)?;
    let mut argv = Vec::with_capacity(argv_bytes.len());
    for entry in &argv_bytes {
        match std::str::from_utf8(entry) {
            Ok(text) => argv.push(text.to_owned()),
            Err(_) => {
                set_errno(memory, cpu.gs_base, EINVAL)?;
                return Ok(u64::MAX);
            }
        }
    }

    let child = state.child_for_spawn();
    {
        // The descriptors the child inherited are references of its own,
        // as Windows handle inheritance adds to the kernel object's count.
        let child_streams = child.crt_streams();
        let mut drive = child.objects.lock().expect("guest object state");
        child_streams.count_inherited_pipe_references(&mut drive);
    }
    {
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        if child.set_program_arguments(&refs).is_err() {
            set_errno(memory, cpu.gs_base, EINVAL)?;
            return Ok(u64::MAX);
        }
    }
    let mut imports = ImportRegistry::new();
    crate::services::register_standard_services(&mut imports, Arc::clone(&child));
    // Shared-memory hand-off: the suspended parent's writes live in its own
    // views, so they copy out to the backing stores before the child maps
    // them, and the views the child leaves behind drop with its memory.
    super::file_mapping::sync_views_to_backings(state, memory);
    let parent_views = super::file_mapping::live_view_addresses(state);
    let run = crate::startup::run_synthetic_startup_scheduled_with_budget(
        &image,
        crate::startup::StartupLayout {
            image_base: 0x150000000,
            stack_top: 0x200010000,
            tls_base: 0x300000000,
        },
        imports,
        Arc::clone(&child),
        CHILD_STEP_BUDGET,
        crate::scheduler::DEFAULT_QUANTUM,
        crate::pe::DEFAULT_MAPPED_IMAGE_BUDGET,
        |_| {},
    );
    super::file_mapping::drop_views_except(state, &parent_views);
    // Process exit closes the child's descriptors: its pipe ends stop
    // counting for the readers, as they would once the writer died.
    {
        let mut child_streams = child.crt_streams();
        let mut drive = child.objects.lock().expect("guest object state");
        child_streams.close_pipe_ends_for_exit(&mut drive);
    }
    // The positions the child left on inherited file descriptors write back
    // into the parent's streams: one advancing position across the two
    // processes, as the shared open file description behaves on Windows.
    state
        .crt_streams()
        .absorb_child_positions(&child.crt_streams());
    let startup = match run {
        Ok(startup) => startup,
        Err(_) => {
            set_errno(memory, cpu.gs_base, EINVAL)?;
            return Ok(u64::MAX);
        }
    };
    state.forward_child_output(&child.standard_output(), &child.standard_error());
    match startup.execution.exit_reason {
        ExitReason::ProcessExit(status) => {
            if mode == P_NOWAIT {
                Ok(state.finish_spawn_child(status))
            } else {
                Ok(u64::from(status))
            }
        }
        // A child that stops any other way - a refusal, a fault, the budget -
        // died abnormally, which the CRT reports as a spawn failure rather
        // than an exit status.
        _ => {
            let cpu = &startup.execution.final_state;
            set_errno(memory, cpu.gs_base, EINVAL)?;
            Ok(u64::MAX)
        }
    }
}

/// `waitpid`/`_cwait`: collect a `_P_NOWAIT` child. The child finished
/// inside its spawn, so the wait never blocks: the status is either already
/// there or the handle is not a child, the documented EINVAL.
fn cwait(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    cpu: &mut crate::cpu::CpuState,
    memory: &mut GuestMemory,
    style: WaitStyle,
) -> Result<u64, ExitReason> {
    const EINVAL: u32 = 22;
    // _cwait(status_ptr, handle, action) or waitpid(handle, status_ptr, options):
    // the handle is the middle argument of one and the first of the other.
    let (status_ptr, handle) = match style {
        WaitStyle::Cwait => (args.rcx, args.rdx),
        WaitStyle::Waitpid => (args.rdx, args.rcx),
    };
    match state.collect_spawn_child(handle) {
        Some(status) => {
            if status_ptr != 0 {
                memory
                    .write_u32(status_ptr, status)
                    .map_err(ExitReason::MemoryFault)?;
            }
            Ok(handle)
        }
        None => {
            set_errno(memory, cpu.gs_base, EINVAL)?;
            Ok(u64::MAX)
        }
    }
}

#[derive(Clone, Copy)]
enum WaitStyle {
    Cwait,
    Waitpid,
}

pub(super) fn register_spawn_wait(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    for (module, symbol, style) in [
        (UCRT, "_cwait", WaitStyle::Cwait),
        (
            "api-ms-win-crt-process-l1-1-0.dll",
            "_cwait",
            WaitStyle::Cwait,
        ),
        (MSVCRT, "_cwait", WaitStyle::Cwait),
        (MSVCRT, "waitpid", WaitStyle::Waitpid),
    ] {
        let s = Arc::clone(state);
        registry.register(module, symbol, move |args, cpu, memory| {
            cwait(&s, args, cpu, memory, style)
        });
        registry.set_status(module, symbol, ServiceStatus::Partial);
    }
}

pub(super) fn register_conio(registry: &mut ImportRegistry) {
    for symbol in ["_getch", "_getche"] {
        registry.register(MSVCRT, symbol, |_, _, _| {
            Err(ExitReason::IllegalInstruction(0xFE))
        });
        registry.set_status(MSVCRT, symbol, ServiceStatus::Partial);
    }
}

pub(super) fn register_errno(registry: &mut ImportRegistry) {
    registry.register(UCRT, "_errno", |_, cpu, memory| {
        memory
            .crt_errno_address(cpu.gs_base)
            .map_err(ExitReason::MemoryFault)
    });
    registry.register(UCRT, "_set_errno", |args, cpu, memory| {
        set_errno(memory, cpu.gs_base, args.rcx as u32)?;
        Ok(0)
    });
    registry.register(UCRT, "_get_errno", |args, cpu, memory| {
        if args.rcx == 0 {
            set_errno(memory, cpu.gs_base, EINVAL)?;
            return Ok(u64::from(EINVAL));
        }
        let address = memory
            .crt_errno_address(cpu.gs_base)
            .map_err(ExitReason::MemoryFault)?;
        let value = memory.read_u32(address).map_err(ExitReason::MemoryFault)?;
        memory
            .write_u32(args.rcx, value)
            .map_err(ExitReason::MemoryFault)?;
        Ok(0)
    });
    for symbol in ["_errno", "_set_errno", "_get_errno"] {
        registry.alias("api-ms-win-crt-runtime-l1-1-0.dll", UCRT, symbol);
        // The legacy CRT carries the same errno accessors.
        registry.alias(MSVCRT, UCRT, symbol);
        registry.set_status(UCRT, symbol, ServiceStatus::Partial);
    }
}

pub(super) fn register_heap(registry: &mut ImportRegistry) {
    registry.register(UCRT, "malloc", |args, cpu, memory| {
        let result = memory.map_heap_allocation(PROCESS_HEAP, args.rcx.max(1) as usize);
        allocation_result(memory, cpu.gs_base, result)
    });
    registry.register(UCRT, "calloc", |args, cpu, memory| {
        let result = args
            .rcx
            .checked_mul(args.rdx)
            .ok_or(MemoryError::AllocationFailed)
            .and_then(|size| memory.map_heap_allocation(PROCESS_HEAP, size.max(1) as usize));
        allocation_result(memory, cpu.gs_base, result)
    });
    registry.register(UCRT, "realloc", |args, cpu, memory| {
        let address = args.rcx;
        let size = args.rdx;
        if address == 0 {
            let result = memory.map_heap_allocation(PROCESS_HEAP, size.max(1) as usize);
            return allocation_result(memory, cpu.gs_base, result);
        }
        if size == 0 {
            free(memory, address)?;
            return Ok(0);
        }
        let result = memory.resize_heap_allocation(PROCESS_HEAP, address, size as usize, false);
        allocation_result(memory, cpu.gs_base, result)
    });
    registry.register(UCRT, "free", |args, _, memory| {
        free(memory, args.rcx)?;
        Ok(0)
    });

    for symbol in ["malloc", "calloc", "realloc", "free"] {
        registry.alias("api-ms-win-crt-heap-l1-1-0.dll", UCRT, symbol);
        // The legacy CRT exports the heap forms under the same names.
        registry.alias(MSVCRT, UCRT, symbol);
        registry.set_status(UCRT, symbol, ServiceStatus::Partial);
    }
}

fn free(memory: &mut GuestMemory, address: u64) -> Result<(), ExitReason> {
    if address == 0 || memory.release_heap_allocation(PROCESS_HEAP, address) {
        Ok(())
    } else {
        Err(ExitReason::MemoryFault(MemoryError::UnmappedAddress(
            address,
        )))
    }
}

/// The Universal C runtime services that a C++ guest's runtime imports and
/// that this runtime models. They are called through the generated adapters
/// in `runtime_table.rs`, so each takes the service context and the
/// arguments the registry declares.
///
/// The result of a service that returns a value and may set `errno`: the
/// handler sets `errno` to the second field and returns the first.
fn or_errno<T>(context: &mut ServiceContext<'_>, outcome: Outcome<T>) -> Result<T, ExitReason> {
    match outcome? {
        Ok(value) => Ok(value),
        Err(Failed(value, errno)) => {
            set_errno(context.memory, context.teb, errno)?;
            Ok(value)
        }
    }
}

/// `fputc`. Writes the character converted to `unsigned char` to the stream
/// and returns it, or `EOF` with `errno` set (stdio.h).
pub fn fputc(
    context: &mut ServiceContext<'_>,
    character: i32,
    stream: u64,
) -> Result<i32, ExitReason> {
    let outcome = {
        let mut streams = context.state.crt_streams();
        let mut drive = context.state.objects.lock().expect("guest object state");
        streams.put_character(&mut drive, character, stream)
    };
    or_errno(context, outcome)
}

/// `_lock_file`. The lock itself does nothing: Xenora's guest scheduler runs
/// one guest thread at a time, so two guest threads can never hold the same
/// stream at once. That is a consequence of the execution model, not a
/// swallowed error.
pub fn _lock_file(
    context: &mut ServiceContext<'_>,
    stream: u64,
    _mode: i32,
) -> Result<i32, ExitReason> {
    let outcome = context.state.crt_streams().lock(stream);
    or_errno(context, outcome)
}

/// `_unlock_file`. The counterpart of `_lock_file`, and as empty.
pub fn _unlock_file(context: &mut ServiceContext<'_>, stream: u64) -> Result<i32, ExitReason> {
    let outcome = context.state.crt_streams().lock(stream);
    or_errno(context, outcome)
}

/// The message `strerror` gives for an error number. The runtime's own error
/// texts are used, so that `perror` and `strerror` name an error the same
/// way. Any other number gets the generic text.
fn error_message(code: i32) -> &'static str {
    match code {
        5 => "Input/output error",
        code if code < 0 => "Unknown error",
        code => crt_files::error_text(code as u32),
    }
}

/// `strerror`. Returns a pointer to a NUL-terminated message for the error
/// number. The message stays valid until the next call.
pub fn strerror(context: &mut ServiceContext<'_>, code: i32) -> Result<u64, ExitReason> {
    let text = error_message(code);
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    let address = {
        let mut streams = context.state.crt_streams();
        streams.message_block(context.memory, bytes.len() as u64)?
    };
    context
        .memory
        .write_bytes(address, &bytes)
        .map_err(ExitReason::MemoryFault)?;
    Ok(address)
}

/// The C locale's `struct lconv` (corecrt_locale.h): twelve pointers and
/// eight characters, in the order Microsoft documents.
const LCONV_BYTES: usize = 104;
/// The offset of the first character member of `struct lconv`.
const LCONV_CHARACTERS: usize = 80;
/// `CHAR_MAX`, the value of a member the current locale does not provide.
const CHAR_MAX: u8 = 127;

/// One pointer of `struct lconv`.
fn store_pointer(image: &mut [u8; LCONV_BYTES], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// `localeconv`. Returns a pointer to the C locale's `struct lconv`. Only
/// the C locale is modelled: no other locale can be set.
pub fn localeconv(context: &mut ServiceContext<'_>) -> Result<u64, ExitReason> {
    // The decimal point of the C locale, and the empty string that every
    // other string member points at.
    let decimal = b".\0";
    let empty = b"\0";
    let size = (LCONV_BYTES + decimal.len() + empty.len()) as u64;
    let address = {
        let mut streams = context.state.crt_streams();
        streams.locale_block(context.memory, size)?
    };
    let decimal_at = address + LCONV_BYTES as u64;
    let empty_at = decimal_at + decimal.len() as u64;
    let mut image = [0u8; LCONV_BYTES];
    store_pointer(&mut image, 0, decimal_at);
    for offset in [8usize, 16, 24, 32, 40, 48, 56, 64, 72] {
        store_pointer(&mut image, offset, empty_at);
    }
    // The C locale has no monetary formatting, so none of its numeric
    // members is available and every one of them is `CHAR_MAX`.
    image[LCONV_CHARACTERS..LCONV_CHARACTERS + 8].fill(CHAR_MAX);
    context
        .memory
        .write_bytes(address, &image)
        .map_err(ExitReason::MemoryFault)?;
    context
        .memory
        .write_bytes(decimal_at, decimal)
        .map_err(ExitReason::MemoryFault)?;
    context
        .memory
        .write_bytes(empty_at, empty)
        .map_err(ExitReason::MemoryFault)?;
    Ok(address)
}

/// The characters of the C locale are the basic character set, so a byte
/// above 0x7F is not a valid single-byte character in it.
const C_LOCALE_LAST: u8 = 0x7F;
/// `(size_t)-1`, the result of a conversion that fails.
const CONVERSION_FAILED: u64 = u64::MAX;

/// `mbrtowc`. The C locale is single-byte, so one byte is one character.
/// The registry declares the multibyte character by value rather than
/// through a pointer, so the byte to convert is the `character` argument.
///
/// The conversion happens whether or not `output` points anywhere; nothing is
/// written then. The `mbstate_t` is not used in the C locale, so a null
/// `state` is accepted and a `state` that is not null is left alone.
pub fn mbrtowc(
    context: &mut ServiceContext<'_>,
    output: u64,
    count: u64,
    character: i32,
    _state: u64,
) -> Result<u64, ExitReason> {
    if count == 0 {
        return Ok(0);
    }
    let byte = character as u8;
    if byte > C_LOCALE_LAST {
        // Not a valid single-byte character in the C locale.
        return Ok(CONVERSION_FAILED);
    }
    if output != 0 {
        // The null character is the one wide character the C locale writes
        // as zero.
        context
            .memory
            .write_u32(output, u32::from(byte))
            .map_err(ExitReason::MemoryFault)?;
    }
    // The null character is a character of zero bytes.
    Ok(u64::from(byte != 0))
}

/// `wcrtomb`. The C locale is single-byte, so a wide character of the basic
/// character set is one byte. The conversion happens whether or not `output`
/// points anywhere; nothing is written then. The `mbstate_t` is not used in
/// the C locale, so a null `state` is accepted and a `state` that is not
/// null is left alone.
pub fn wcrtomb(
    context: &mut ServiceContext<'_>,
    output: u64,
    character: u32,
    _state: u64,
) -> Result<u64, ExitReason> {
    let byte = character;
    if byte > u32::from(C_LOCALE_LAST) {
        // The wide character cannot be represented in the C locale.
        return Ok(CONVERSION_FAILED);
    }
    if output != 0 {
        context
            .memory
            .write_u8(output, byte as u8)
            .map_err(ExitReason::MemoryFault)?;
    }
    Ok(1)
}

#[cfg(test)]
#[test]
fn errno_isolated_by_guest_teb_on_one_host_thread() {
    use crate::cpu::{CpuState, Register};
    use crate::import_table::ImportName;

    let mut registry = ImportRegistry::new();
    register_errno(&mut registry);
    register_heap(&mut registry);
    let mut memory = GuestMemory::new();
    let mut first = CpuState {
        gs_base: 0x10000,
        ..CpuState::default()
    };
    let mut second = CpuState {
        gs_base: 0x20000,
        ..CpuState::default()
    };
    let call = |symbol: &str, cpu: &mut CpuState, memory: &mut GuestMemory| {
        let service = registry
            .resolve(UCRT, &ImportName::Name(symbol.to_owned()))
            .unwrap();
        (service.handler)(&Win64Args::new(cpu), cpu, memory).unwrap()
    };

    let first_slot = call("_errno", &mut first, &mut memory);
    first.set(Register::Rcx, 23);
    assert_eq!(call("_set_errno", &mut first, &mut memory), 0);
    let second_slot = call("_errno", &mut second, &mut memory);
    assert_ne!(first_slot, second_slot);
    assert_eq!(memory.read_u32(second_slot).unwrap(), 0);
    second.set(Register::Rcx, u64::MAX);
    assert_eq!(call("malloc", &mut second, &mut memory), 0);
    assert_eq!(memory.read_u32(second_slot).unwrap(), ENOMEM);
    assert_eq!(call("_errno", &mut first, &mut memory), first_slot);
    assert_eq!(memory.read_u32(first_slot).unwrap(), 23);
}

/// Copies a narrow string with its terminator; bounded, the copy is zero
/// padded like strncpy when the source is shorter than the count.
fn copy_string(
    memory: &mut GuestMemory,
    dest: u64,
    source: u64,
    count: u64,
) -> Result<(), ExitReason> {
    let length = string_length(memory, source, count, StringUnit::Byte)?;
    let copied = if count == u64::MAX {
        length + 1
    } else {
        length.min(count)
    };
    if copied != 0 {
        let mut bytes = transfer_buffer(copied, 0)?;
        memory
            .read_bytes(source, &mut bytes)
            .map_err(ExitReason::MemoryFault)?;
        memory
            .write_bytes(dest, &bytes)
            .map_err(ExitReason::MemoryFault)?;
    }
    if count != u64::MAX && copied < count {
        let zeroes = transfer_buffer(count - copied, 0)?;
        memory
            .write_bytes(
                dest.checked_add(copied)
                    .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?,
                &zeroes,
            )
            .map_err(ExitReason::MemoryFault)?;
    } else if count == u64::MAX || length >= count {
        // The unbounded form always terminates; the bounded one does not
        // when the source fills the count exactly.
        if count == u64::MAX {
            memory
                .write_u8(
                    dest.checked_add(length)
                        .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?,
                    0,
                )
                .map_err(ExitReason::MemoryFault)?;
        }
    }
    Ok(())
}

/// The remaining small CRT utilities of the survey: string reversal and
/// case conversion in place, duplication, the C-locale collation forms,
/// the Annex K copy forms, the missing character classes, the integer
/// formatting family and `getenv_s` over the empty environment.
pub(super) fn register_utilities(registry: &mut ImportRegistry) {
    // strrchr: the last occurrence, the terminator included in the scan.
    registry.register(UCRT, "strrchr", |args, _, memory| {
        let wanted = args.rdx as u8;
        let mut address = args.rcx;
        let mut last = 0u64;
        loop {
            let byte = memory.read_u8(address).map_err(ExitReason::MemoryFault)?;
            if byte == wanted {
                last = address;
            }
            if byte == 0 {
                return Ok(last);
            }
            address = address
                .checked_add(1)
                .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
        }
    });

    // `_strdup` is served by the typed registry since #655.

    // `_strdup` is served by the typed registry since #655.
    // Case conversion and reversal in place, ASCII like the C locale.
    for (symbol, upper) in [("_strlwr", false), ("_strupr", true)] {
        registry.register(UCRT, symbol, move |args, _, memory| {
            let mut address = args.rcx;
            loop {
                let byte = memory.read_u8(address).map_err(ExitReason::MemoryFault)?;
                if byte == 0 {
                    return Ok(args.rcx);
                }
                let converted = if upper {
                    byte.to_ascii_uppercase()
                } else {
                    byte.to_ascii_lowercase()
                };
                if converted != byte {
                    memory
                        .write_u8(address, converted)
                        .map_err(ExitReason::MemoryFault)?;
                }
                address = address
                    .checked_add(1)
                    .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
            }
        });
    }

    registry.register(UCRT, "_strrev", |args, _, memory| {
        let length = string_length(memory, args.rcx, u64::MAX, StringUnit::Byte)?;
        if length > 1 {
            let mut bytes = transfer_buffer(length, 0)?;
            memory
                .read_bytes(args.rcx, &mut bytes)
                .map_err(ExitReason::MemoryFault)?;
            bytes.reverse();
            memory
                .write_bytes(args.rcx, &bytes)
                .map_err(ExitReason::MemoryFault)?;
        }
        Ok(args.rcx)
    });

    // The C locale collates byte-wise: strcoll is strcmp and strxfrm the
    // identity copy with the documented length semantics.
    registry.register(UCRT, "strcoll", |args, _, memory| {
        compare_strings(memory, args.rcx, args.rdx, u64::MAX, StringUnit::Byte)
    });

    registry.register(UCRT, "strxfrm", |args, _, memory| {
        let length = string_length(memory, args.rdx, u64::MAX, StringUnit::Byte)?;
        if args.r8 > length {
            // Only when the whole string fits is the output defined.
            let mut bytes = transfer_buffer(length + 1, 0)?;
            memory
                .read_bytes(args.rdx, &mut bytes)
                .map_err(ExitReason::MemoryFault)?;
            memory
                .write_bytes(args.rcx, &bytes)
                .map_err(ExitReason::MemoryFault)?;
        } else if args.r8 != 0 {
            // A small buffer copies what fits and the output is undefined
            // content-wise, but the copy itself is what programs observe.
            let mut bytes = transfer_buffer(args.r8, 0)?;
            memory
                .read_bytes(args.rdx, &mut bytes)
                .map_err(ExitReason::MemoryFault)?;
            memory
                .write_bytes(args.rcx, &bytes)
                .map_err(ExitReason::MemoryFault)?;
        }
        Ok(length)
    });

    // The Annex K copy forms: null pointers are invalid, a count over the
    // destination size zeroes the destination and answers ERANGE.
    for (symbol, overlapping) in [("memcpy_s", false), ("memmove_s", true)] {
        registry.register(UCRT, symbol, move |args, cpu, memory| {
            let (dest, dest_size, source, count) = (args.rcx, args.rdx, args.r8, args.r9);
            if dest == 0 || source == 0 {
                set_errno(memory, cpu.gs_base, EINVAL)?;
                return Ok(u64::from(EINVAL));
            }
            if count > dest_size {
                // The constraint violation zeroes the destination, as
                // documented, before answering the range error.
                if dest_size != 0 {
                    let zeroes = transfer_buffer(dest_size, 0)?;
                    memory
                        .write_bytes(dest, &zeroes)
                        .map_err(ExitReason::MemoryFault)?;
                }
                set_errno(memory, cpu.gs_base, ERANGE)?;
                return Ok(u64::from(ERANGE));
            }
            if count != 0 {
                if !overlapping {
                    // memcpy_s also rejects actual overlap; the ranges are
                    // half-open, the documented test.
                    let dest_end = dest.wrapping_add(count);
                    let source_end = source.wrapping_add(count);
                    if dest < source_end && source < dest_end {
                        let zeroes = transfer_buffer(dest_size.max(1), 0)?;
                        memory
                            .write_bytes(dest, &zeroes[..dest_size as usize])
                            .map_err(ExitReason::MemoryFault)?;
                        set_errno(memory, cpu.gs_base, EINVAL)?;
                        return Ok(u64::from(EINVAL));
                    }
                }
                let mut bytes = transfer_buffer(count, 0)?;
                memory
                    .read_bytes(source, &mut bytes)
                    .map_err(ExitReason::MemoryFault)?;
                memory
                    .write_bytes(dest, &bytes)
                    .map_err(ExitReason::MemoryFault)?;
            }
            Ok(0)
        });
    }

    // The integer formatting family: radix 2 through 36, lowercase digits,
    // a minus sign for signed negative input in radix ten only, as
    // documented. The _s forms check the buffer size.
    for (symbol, bits, signed) in [
        ("_itoa", 32u32, true),
        ("_ltoa", 32, true),
        ("_i64toa", 64, true),
        ("_ultoa", 32, false),
        ("_ui64toa", 64, false),
    ] {
        registry.register(UCRT, symbol, move |args, cpu, memory| {
            format_integer(
                memory,
                cpu.gs_base,
                args.rcx,
                args.rdx,
                args.r8 as u32,
                0,
                bits,
                signed,
            )
        });
    }
    registry.register(UCRT, "_itoa_s", |args, cpu, memory| {
        format_integer(
            memory,
            cpu.gs_base,
            args.rcx,
            args.rdx,
            args.r9 as u32,
            args.r8,
            32,
            true,
        )
    });

    // The copying and concatenation forms mingw inlines least often.
    registry.register(UCRT, "strcpy", |args, _, memory| {
        copy_string(memory, args.rcx, args.rdx, u64::MAX)?;
        Ok(args.rcx)
    });
    registry.register(UCRT, "strncpy", |args, _, memory| {
        copy_string(memory, args.rcx, args.rdx, args.r8)?;
        Ok(args.rcx)
    });
    registry.register(UCRT, "strcat", |args, _, memory| {
        let length = string_length(memory, args.rcx, u64::MAX, StringUnit::Byte)?;
        let end = args
            .rcx
            .checked_add(length)
            .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
        copy_string(memory, end, args.rdx, u64::MAX)?;
        Ok(args.rcx)
    });
    registry.register(UCRT, "strncat", |args, _, memory| {
        let length = string_length(memory, args.rcx, u64::MAX, StringUnit::Byte)?;
        let end = args
            .rcx
            .checked_add(length)
            .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
        copy_string(memory, end, args.rdx, args.r8)?;
        memory
            .write_u8(
                end.checked_add(string_length(memory, args.rdx, args.r8, StringUnit::Byte)?)
                    .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?,
                0,
            )
            .map_err(ExitReason::MemoryFault)?;
        Ok(args.rcx)
    });

    // The string search family. All of it scans byte strings within the
    // scan budget, one unit at a time across block boundaries.
    registry.register(UCRT, "strstr", |args, _, memory| {
        let needle = string_length(memory, args.rdx, u64::MAX, StringUnit::Byte)?;
        if needle == 0 {
            return Ok(args.rcx);
        }
        let haystack = string_length(memory, args.rcx, u64::MAX, StringUnit::Byte)?;
        let first = memory.read_u8(args.rdx).map_err(ExitReason::MemoryFault)?;
        let mut offset = 0u64;
        while offset + needle <= haystack {
            let candidate = memory
                .read_u8(args.rcx + offset)
                .map_err(ExitReason::MemoryFault)?;
            if candidate == first {
                let mut matched = true;
                for index in 1..needle {
                    let a = memory
                        .read_u8(args.rcx + offset + index)
                        .map_err(ExitReason::MemoryFault)?;
                    let b = memory
                        .read_u8(args.rdx + index)
                        .map_err(ExitReason::MemoryFault)?;
                    if a != b {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return Ok(args.rcx + offset);
                }
            }
            offset += 1;
        }
        Ok(0)
    });

    registry.register(UCRT, "strcspn", |args, _, memory| {
        let length = string_length(memory, args.rcx, u64::MAX, StringUnit::Byte)?;
        let reject = string_length(memory, args.rdx, u64::MAX, StringUnit::Byte)?;
        let mut rejects = [false; 256];
        for index in 0..reject {
            let byte = memory
                .read_u8(args.rdx + index)
                .map_err(ExitReason::MemoryFault)?;
            rejects[usize::from(byte)] = true;
        }
        for index in 0..length {
            let byte = memory
                .read_u8(args.rcx + index)
                .map_err(ExitReason::MemoryFault)?;
            if rejects[usize::from(byte)] {
                return Ok(index);
            }
        }
        Ok(length)
    });

    registry.register(UCRT, "strspn", |args, _, memory| {
        let length = string_length(memory, args.rcx, u64::MAX, StringUnit::Byte)?;
        let accept = string_length(memory, args.rdx, u64::MAX, StringUnit::Byte)?;
        let mut accepts = [false; 256];
        for index in 0..accept {
            let byte = memory
                .read_u8(args.rdx + index)
                .map_err(ExitReason::MemoryFault)?;
            accepts[usize::from(byte)] = true;
        }
        for index in 0..length {
            let byte = memory
                .read_u8(args.rcx + index)
                .map_err(ExitReason::MemoryFault)?;
            if !accepts[usize::from(byte)] {
                return Ok(index);
            }
        }
        Ok(length)
    });

    registry.register(UCRT, "strpbrk", |args, _, memory| {
        let length = string_length(memory, args.rcx, u64::MAX, StringUnit::Byte)?;
        let accept = string_length(memory, args.rdx, u64::MAX, StringUnit::Byte)?;
        let mut accepts = [false; 256];
        for index in 0..accept {
            let byte = memory
                .read_u8(args.rdx + index)
                .map_err(ExitReason::MemoryFault)?;
            accepts[usize::from(byte)] = true;
        }
        for index in 0..length {
            let byte = memory
                .read_u8(args.rcx + index)
                .map_err(ExitReason::MemoryFault)?;
            if accepts[usize::from(byte)] {
                return Ok(args.rcx + index);
            }
        }
        Ok(0)
    });

    // strtok keeps its scan position in CRT state shared by every thread of
    // the CRT instance - which is exactly why the CRT later grew strtok_s.
    let position = std::sync::Arc::new(std::sync::Mutex::new(0u64));
    registry.register(UCRT, "strtok", move |args, _, memory| {
        let start = if args.rcx != 0 {
            args.rcx
        } else {
            *position.lock().expect("strtok scan position")
        };
        if start == 0 {
            return Ok(0);
        }
        let length = string_length(memory, start, u64::MAX, StringUnit::Byte)?;
        let delimiters = string_length(memory, args.rdx, u64::MAX, StringUnit::Byte)?;
        let mut delims = [false; 256];
        for index in 0..delimiters {
            let byte = memory
                .read_u8(args.rdx + index)
                .map_err(ExitReason::MemoryFault)?;
            delims[usize::from(byte)] = true;
        }
        let mut index = 0u64;
        while index < length {
            let byte = memory
                .read_u8(start + index)
                .map_err(ExitReason::MemoryFault)?;
            if !delims[usize::from(byte)] {
                break;
            }
            index += 1;
        }
        if index >= length {
            *position.lock().expect("strtok scan position") = 0;
            return Ok(0);
        }
        let token = start + index;
        while index < length {
            let byte = memory
                .read_u8(start + index)
                .map_err(ExitReason::MemoryFault)?;
            if delims[usize::from(byte)] {
                memory
                    .write_u8(start + index, 0)
                    .map_err(ExitReason::MemoryFault)?;
                *position.lock().expect("strtok scan position") = start + index + 1;
                return Ok(token);
            }
            index += 1;
        }
        *position.lock().expect("strtok scan position") = 0;
        Ok(token)
    });

    // The case-insensitive comparisons fold the ASCII letters; bytes outside
    // ASCII compare as themselves, which is the invariant the CRT documents
    // for the POSIX-compatible behavior of these forms.
    for (symbol, limit) in [("_stricmp", u64::MAX), ("_strnicmp", u64::MAX)] {
        registry.register(UCRT, symbol, move |args, _, memory| {
            let bounded = if symbol == "_strnicmp" {
                args.r8
            } else {
                limit
            };
            let fold = |byte: u8| -> u8 {
                if byte.is_ascii_uppercase() {
                    byte + 32
                } else {
                    byte
                }
            };
            let budget = SCAN_BUDGET.min(bounded);
            for offset in 0..budget {
                let a = fold(
                    memory
                        .read_u8(args.rcx + offset)
                        .map_err(ExitReason::MemoryFault)?,
                );
                let b = fold(
                    memory
                        .read_u8(args.rdx + offset)
                        .map_err(ExitReason::MemoryFault)?,
                );
                if a != b || a == 0 {
                    return Ok(u64::from((i32::from(a) - i32::from(b)) as u32));
                }
            }
            Ok(0)
        });
    }

    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "strrchr");
    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "strcpy");
    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "strncpy");
    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "strcat");
    registry.alias("api-ms-win-crt-private-l1-1-0.dll", UCRT, "strncat");

    // Legacy binaries link the string surface straight out of msvcrt.dll
    // rather than the api-ms-win-crt forwarding surface.
    for symbol in [
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strrchr",
        "strlen",
        "strcmp",
        "strncmp",
        "strnlen",
        "strstr",
        "strtok",
        "strcspn",
        "strspn",
        "strpbrk",
        "_stricmp",
        "_strnicmp",
        "_strdup",
        "_strlwr",
        "_strupr",
        "_strrev",
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
        "memchr",
        "strchr",
    ] {
        registry.alias(MSVCRT, UCRT, symbol);
    }

    for (symbol, api) in [
        ("strcpy", CRT_STRING_API),
        ("strncpy", CRT_STRING_API),
        ("strcat", CRT_STRING_API),
        ("strncat", CRT_STRING_API),
        ("strrchr", CRT_STRING_API),
        ("_strdup", CRT_STRING_API),
        ("_strlwr", CRT_STRING_API),
        ("_strupr", CRT_STRING_API),
        ("_strrev", CRT_STRING_API),
        ("strcoll", CRT_STRING_API),
        ("strxfrm", CRT_STRING_API),
        ("memcpy_s", CRT_STRING_API),
        ("memmove_s", CRT_STRING_API),
        ("_itoa", "api-ms-win-crt-convert-l1-1-0.dll"),
        ("_ltoa", "api-ms-win-crt-convert-l1-1-0.dll"),
        ("_i64toa", "api-ms-win-crt-convert-l1-1-0.dll"),
        ("_ultoa", "api-ms-win-crt-convert-l1-1-0.dll"),
        ("_ui64toa", "api-ms-win-crt-convert-l1-1-0.dll"),
        ("_itoa_s", "api-ms-win-crt-convert-l1-1-0.dll"),
    ] {
        registry.alias(api, UCRT, symbol);
        registry.set_status(UCRT, symbol, ServiceStatus::Partial);
    }
}

/// The shared integer formatting core: radix 2 through 36, lowercase
/// digits, the sign only for negative signed input in radix ten.
#[allow(clippy::too_many_arguments)]
fn format_integer(
    memory: &mut GuestMemory,
    teb: u64,
    value: u64,
    buffer: u64,
    radix: u32,
    size: u64,
    bits: u32,
    signed: bool,
) -> Result<u64, ExitReason> {
    if buffer == 0 || !(2..=36).contains(&radix) {
        if signed || bits == 32 {
            set_errno(memory, teb, EINVAL)?;
        }
        return Ok(if size == 0 { 0 } else { u64::from(EINVAL) });
    }
    // Normalize to the width the function formats.
    let normalized = if bits == 32 {
        u64::from(value as u32)
    } else {
        value
    };
    let negative = signed && radix == 10 && {
        let sign_bit = 1u64 << (bits - 1);
        normalized & sign_bit != 0
    };
    let magnitude = if negative {
        // The two's complement magnitude, correct for the minimum value.
        if bits == 32 {
            u64::from((normalized as u32).wrapping_neg())
        } else {
            normalized.wrapping_neg()
        }
    } else {
        normalized
    };
    let mut digits = Vec::new();
    let mut remaining = magnitude;
    loop {
        let digit = (remaining % u64::from(radix)) as u8;
        digits.push(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
        remaining /= u64::from(radix);
        if remaining == 0 {
            break;
        }
    }
    if negative {
        digits.push(b'-');
    }
    digits.reverse();
    digits.push(0);
    let needed = digits.len() as u64;
    if size != 0 {
        // The _s form: too small is an invalid parameter with zeroed start.
        if needed > size {
            memory
                .write_u8(buffer, 0)
                .map_err(ExitReason::MemoryFault)?;
            set_errno(memory, teb, EINVAL)?;
            return Ok(u64::from(EINVAL));
        }
        memory
            .write_bytes(buffer, &digits)
            .map_err(ExitReason::MemoryFault)?;
        return Ok(0);
    }
    memory
        .write_bytes(buffer, &digits)
        .map_err(ExitReason::MemoryFault)?;
    Ok(buffer)
}

#[cfg(test)]
#[test]
fn the_legacy_crt_aliases_the_integer_parses_and_the_console_keys_stop() {
    use crate::cpu::CpuState;
    use crate::import_table::ImportName;

    let mut registry = ImportRegistry::new();
    register_conversions(&mut registry);
    register_conio(&mut registry);
    // The legacy CRT resolves the integer parses through the alias: the
    // strtol family busybox imports from msvcrt.dll is the ucrtbase engine.
    for symbol in [
        "strtol",
        "strtoul",
        "strtoll",
        "strtoull",
        "_strtoi64",
        "_strtoui64",
    ] {
        assert!(
            registry
                .resolve(MSVCRT, &ImportName::Name(symbol.to_owned()))
                .is_some(),
            "{symbol} resolves through the legacy CRT"
        );
    }
    // The console keys are registered - a program importing them binds -
    // and calling one stops the guest because the empty console input
    // would block the one executor forever.
    let mut memory = GuestMemory::new();
    let cpu = CpuState::default();
    let service = registry
        .resolve(MSVCRT, &ImportName::Name("_getch".to_owned()))
        .expect("_getch resolves");
    let result = (service.handler)(&Win64Args::new(&cpu), &mut CpuState::default(), &mut memory);
    assert!(matches!(result, Err(ExitReason::IllegalInstruction(0xFE))));
}

#[cfg(test)]
#[test]
fn spawnve_modes_other_than_pwait_refuse_honestly_with_enosys() {
    use super::ServicesState;
    use crate::cpu::{CpuState, Register};
    use crate::import_table::ImportName;
    use crate::imports::Win64Args;
    use crate::memory::{GuestMemory, MemoryPermissions};
    use crate::services::MockClock;
    use std::sync::Arc;

    let mut registry = ImportRegistry::new();
    let _state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
    register_spawn(&mut registry, &_state);
    let mut memory = GuestMemory::new();
    memory
        .map_region(0x1000, 8192, MemoryPermissions::READ_WRITE)
        .unwrap();
    let call = |memory: &mut GuestMemory, module: &str, symbol: &str, args: &[u64]| {
        let mut cpu = CpuState::default();
        for (reg, &value) in [Register::Rcx, Register::Rdx, Register::R8, Register::R9]
            .into_iter()
            .zip(args)
        {
            cpu.set(reg, value);
        }
        cpu.set(Register::Rsp, 0x2000);
        for (index, &value) in args.iter().enumerate().skip(4) {
            memory
                .write_u64(0x2000 + 0x28 + (index as u64 - 4) * 8, value)
                .unwrap();
        }
        let descriptor = registry
            .resolve(module, &ImportName::Name(symbol.to_owned()))
            .unwrap();
        (descriptor.handler)(&Win64Args::new(&cpu), &mut cpu, memory).unwrap()
    };

    // Modes other than _P_WAIT refuse in the documented failure shape:
    // minus one, ENOSYS in errno. No pretend success ever stands in for a
    // child process topology the machine does not have. (mode = 1 here is
    // _P_NOWAIT.)
    for (module, symbol) in [
        (UCRT, "_spawnve"),
        (UCRT, "_wspawnve"),
        (MSVCRT, "_spawnve"),
    ] {
        assert_eq!(
            call(&mut memory, module, symbol, &[1, 0x1100, 0x1200, 0]),
            u64::MAX
        );
    }
}
#[test]
fn the_spawn_image_is_provisioned_in_the_drive_all_or_nothing() {
    use super::ServicesState;
    use crate::services::MockClock;
    use std::sync::Arc;

    let state = ServicesState::new(Arc::new(MockClock::new(0)));
    let image: Vec<u8> = (0..512u32).map(|index| (index % 251) as u8).collect();
    state.set_spawn_image("PrOg.EXE", &image);
    {
        let objects = state.objects.lock().expect("guest object state");
        // The drive key folds case exactly as every drive path does.
        assert_eq!(
            objects.drive_file("prog.exe"),
            Some(image.as_slice()),
            "the drive must hold the exact image bytes"
        );
    }

    // An image beyond the drive's byte bound stays absent rather than
    // truncated, because a partial image would answer reads wrongly.
    let big = ServicesState::new(Arc::new(MockClock::new(0)));
    let huge = vec![0x5A; 17 * 1024 * 1024];
    big.set_spawn_image("huge.exe", &huge);
    let objects = big.objects.lock().expect("guest object state");
    assert_eq!(objects.drive_file("huge.exe"), None);
}

// The CRT directory surface. The process working directory is a path in
// the virtual filesystem: it starts at the volume root, `_chdir` validates
// against the directory set, `_fullpath` resolves lexically without an
// existence check - exactly the split the CRT documents. All paths resolve
// case-insensitively on the single machine drive, matching how the file
// surface stores them.
pub(crate) fn resolve_directory(cwd: &str, input: &str) -> String {
    let mut path = input.trim().to_lowercase().replace('/', "\\");
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        path = path.split_off(2);
    }
    let absolute = path.starts_with('\\');
    let mut segments: Vec<String> = if absolute {
        Vec::new()
    } else {
        cwd.split('\\')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect()
    };
    for part in path.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other.to_owned()),
        }
    }
    segments.join("\\")
}

fn windows_form(vfs_path: &str) -> String {
    // The drive is case-folded and the merged `_fullpath` evidence answers
    // the lowercase form, so the working directory displays the same way.
    if vfs_path.is_empty() {
        "c:\\".to_owned()
    } else {
        format!("c:\\{vfs_path}")
    }
}

const ENOENT: u32 = 2;

fn read_crt_string(memory: &GuestMemory, address: u64, limit: u64) -> Result<String, MemoryError> {
    let mut bytes = Vec::new();
    for index in 0..limit {
        let slot = address.checked_add(index).ok_or(MemoryError::Overflow)?;
        let byte = memory.read_u8(slot)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(super) fn register_directories(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let getcwd = Arc::clone(state);
    registry.register(UCRT, "_getcwd", move |args, cpu, memory| {
        if args.rcx == 0 {
            set_errno(memory, cpu.gs_base, EINVAL)?;
            return Ok(0);
        }
        let form = windows_form(&getcwd.crt_streams().working_directory());
        if args.rdx < form.len() as u64 + 1 {
            set_errno(memory, cpu.gs_base, ERANGE)?;
            return Ok(0);
        }
        memory
            .write_bytes(args.rcx, form.as_bytes())
            .map_err(ExitReason::MemoryFault)?;
        memory
            .write_u8(args.rcx + form.len() as u64, 0)
            .map_err(ExitReason::MemoryFault)?;
        Ok(args.rcx)
    });

    let chdir = Arc::clone(state);
    registry.register(UCRT, "_chdir", move |args, cpu, memory| {
        let input = read_crt_string(memory, args.rcx, 260).map_err(ExitReason::MemoryFault)?;
        let resolved = {
            let streams = chdir.crt_streams();
            resolve_directory(&streams.working_directory(), &input)
        };
        let exists = resolved.is_empty() || {
            let objects = chdir.objects.lock().expect("guest object state");
            objects.directories.contains(&resolved)
        };
        if !exists {
            set_errno(memory, cpu.gs_base, ENOENT)?;
            return Ok(u64::from(u32::MAX));
        }
        chdir.crt_streams().set_working_directory(resolved);
        Ok(0)
    });

    // msvcrt.dll aliases for the legacy binaries that link them there.
    for symbol in ["_getcwd", "_chdir", "_fullpath"] {
        registry.alias(MSVCRT, UCRT, symbol);
    }
}
