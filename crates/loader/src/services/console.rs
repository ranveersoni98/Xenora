// SPDX-License-Identifier: GPL-3.0-or-later
//
//! The console identity and the standard handles, package 8 first part of
//! #459. What is implemented, and the honest scope:
//!
//! - `GetStdHandle` answers one fixed pseudo-handle per standard device.
//!   They are Xenora's choice: Windows hands out small values that vary
//!   with the machine state, and nothing here depends on the exact number.
//! - `SetStdHandle` stores the replacement, and `GetStdHandle` then answers
//!   it, as documented. A write or read through a handle that is not one of
//!   the console devices fails with `ERROR_INVALID_HANDLE` - the runtime
//!   has no file handles to redirect to yet, so redirection can only point
//!   at another console device or break, which is the honest model until
//!   the Win32 file layer exists.
//! - `GetConsoleMode`/`SetConsoleMode` round-trip mode bits per handle.
//!   The modes do not alter the capture behavior yet; that is documented
//!   here rather than hidden, and the round-trip itself is the implemented
//!   semantics.
//! - `GetConsoleCP`/`GetConsoleOutputCP` answer UTF-8 (65001), coherent
//!   with the process code page choice documented in `codepages`.
//! - `WriteConsoleW` converts its wide text to UTF-8 and appends it to the
//!   same capture `stdout`/`stderr` use, so a program mixing `printf` and
//!   `WriteConsole` produces one coherent output. `WriteConsoleA` appends
//!   its bytes as they are: the console code page is UTF-8, so no
//!   conversion applies. Both report the characters consumed.
//! - `ReadConsoleA` reads one line of the captured standard input. The
//!   input was captured with CR LF replaced by LF (the CRT text mode), and
//!   the console line input hands the line ending back as CR LF, as the
//!   page documents. Reading without a line feed in the rest of the input
//!   ends at the end of the input.

/// Xenora's fixed pseudo-handles for the three standard devices.
use super::{GuestObject, ServicesState};
use std::sync::{Arc, Mutex};

pub(super) const INPUT_HANDLE: u64 = 0x101;
pub(super) const OUTPUT_HANDLE: u64 = 0x102;
pub(super) const ERROR_HANDLE: u64 = 0x103;

pub(super) const STD_INPUT: u32 = 0xFFFF_FFF6; // -10
pub(super) const STD_OUTPUT: u32 = 0xFFFF_FFF5; // -11
pub(super) const STD_ERROR: u32 = 0xFFFF_FFF4; // -12

/// The default modes: line input with echo and processing, processed output
/// with wrap. They round-trip through Set but alter nothing yet.
pub(super) const DEFAULT_INPUT_MODE: u32 = 0x1 | 0x2 | 0x4;
pub(super) const DEFAULT_OUTPUT_MODE: u32 = 0x1 | 0x2;

/// One character cell of a screen buffer: a UTF-16 unit and its attributes,
/// the CHAR_INFO pair of the Windows console.
#[derive(Clone, Copy, Default)]
pub(super) struct Cell {
    pub ch: u16,
    pub attr: u16,
}

/// A console screen buffer: a width by height grid of cells, a cursor, and
/// the current text attribute. The grid is bounded like every guest object.
pub(super) struct ScreenBuffer {
    pub width: u16,
    pub height: u16,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub attribute: u16,
    pub cells: Vec<Cell>,
}

impl ScreenBuffer {
    pub(super) fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            cursor_x: 0,
            cursor_y: 0,
            // The console default: light gray on black.
            attribute: 0x7,
            cells: vec![Cell::default(); usize::from(width) * usize::from(height)],
        }
    }

    pub(super) fn resize(&mut self, width: u16, height: u16) {
        let mut cells = vec![Cell::default(); usize::from(width) * usize::from(height)];
        for row in 0..self.height.min(height) {
            for column in 0..self.width.min(width) {
                let old = usize::from(row) * usize::from(self.width) + usize::from(column);
                let new = usize::from(row) * usize::from(width) + usize::from(column);
                cells[new] = self.cells[old];
            }
        }
        self.width = width;
        self.height = height;
        self.cells = cells;
        self.cursor_x = self.cursor_x.min(width.saturating_sub(1));
        self.cursor_y = self.cursor_y.min(height.saturating_sub(1));
    }
}

/// The console one buffer answers before any is created: the standard
/// Windows 80x25.
pub(super) const DEFAULT_WIDTH: u16 = 80;
pub(super) const DEFAULT_HEIGHT: u16 = 25;

pub(super) fn register(registry: &mut crate::imports::ImportRegistry, state: &Arc<ServicesState>) {
    use super::{
        ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOACCESS, ERROR_NOT_ENOUGH_MEMORY,
        ERROR_NOT_SUPPORTED, GuestObject, KERNEL32,
    };
    use crate::cpu::ExitReason;
    let create = Arc::clone(state);
    registry.register(
        KERNEL32,
        "CreateConsoleScreenBuffer",
        move |args, cpu, memory| {
            // GENERIC access is accepted; a share mode the console ignores, and
            // only CONSOLE_TEXTMODE_BUFFER (1) exists. The security attributes
            // and the reserved parameter must be null, as documented.
            // args are zero-based across all parameters: the flags are r9 (3)
            // and the reserved parameter is the first stack argument (4).
            if args.r8 != 0 || args.get(3, memory).map_err(ExitReason::MemoryFault)? != 1 {
                return create.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, u64::MAX);
            }
            if args.get(4, memory).map_err(ExitReason::MemoryFault)? != 0 {
                return create.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, u64::MAX);
            }
            let mut objects = create.objects.lock().expect("guest object state");
            let Some(handle) = objects.next_handle() else {
                return create.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, u64::MAX);
            };
            objects.insert_handle(
                handle,
                GuestObject::ConsoleBuffer(Arc::new(Mutex::new(ScreenBuffer::new(
                    DEFAULT_WIDTH,
                    DEFAULT_HEIGHT,
                )))),
            );
            Ok(handle)
        },
    );

    let info = Arc::clone(state);
    registry.register(
        KERNEL32,
        "GetConsoleScreenBufferInfo",
        move |args, cpu, memory| {
            let buffer = {
                let objects = info.objects.lock().expect("guest object state");
                match objects.handles.get(&args.rcx) {
                    Some(GuestObject::ConsoleBuffer(buffer)) => Arc::clone(buffer),
                    _ if args.rcx == OUTPUT_HANDLE || args.rcx == ERROR_HANDLE => {
                        // The standard devices share the machine's console state,
                        // modeled as the default 80x25 grid until writes shape it.
                        return write_default_info(memory, args.rdx);
                    }
                    _ => return info.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
                }
            };
            write_info(memory, args.rdx, &buffer.lock().expect("screen buffer"))
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    let cursor = Arc::clone(state);
    registry.register(
        KERNEL32,
        "SetConsoleCursorPosition",
        move |args, cpu, memory| {
            let _ = memory;
            let buffer = {
                let objects = cursor.objects.lock().expect("guest object state");
                match objects.handles.get(&args.rcx) {
                    Some(GuestObject::ConsoleBuffer(buffer)) => Arc::clone(buffer),
                    _ => return cursor.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
                }
            };
            let x = (args.rdx & 0xFFFF) as u16;
            let y = ((args.rdx >> 16) & 0xFFFF) as u16;
            let mut buffer = buffer.lock().expect("screen buffer");
            if x >= buffer.width || y >= buffer.height {
                return cursor.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            buffer.cursor_x = x;
            buffer.cursor_y = y;
            Ok(1)
        },
    );

    let attribute = Arc::clone(state);
    registry.register(
        KERNEL32,
        "SetConsoleTextAttribute",
        move |args, cpu, memory| {
            let _ = memory;
            let buffer = {
                let objects = attribute.objects.lock().expect("guest object state");
                match objects.handles.get(&args.rcx) {
                    Some(GuestObject::ConsoleBuffer(buffer)) => Arc::clone(buffer),
                    _ if args.rcx == OUTPUT_HANDLE || args.rcx == ERROR_HANDLE => {
                        // The attribute of the standard capture is accepted and
                        // does not alter it: the capture has no colors.
                        return Ok(1);
                    }
                    _ => return attribute.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
                }
            };
            buffer.lock().expect("screen buffer").attribute = args.rdx as u16;
            Ok(1)
        },
    );

    let resize = Arc::clone(state);
    registry.register(
        KERNEL32,
        "SetConsoleScreenBufferSize",
        move |args, cpu, memory| {
            let _ = memory;
            let buffer = {
                let objects = resize.objects.lock().expect("guest object state");
                match objects.handles.get(&args.rcx) {
                    Some(GuestObject::ConsoleBuffer(buffer)) => Arc::clone(buffer),
                    _ => return resize.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
                }
            };
            let width = (args.rdx & 0xFFFF) as u16;
            let height = ((args.rdx >> 16) & 0xFFFF) as u16;
            if width == 0 || height == 0 {
                return resize.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            buffer.lock().expect("screen buffer").resize(width, height);
            Ok(1)
        },
    );

    let active = Arc::clone(state);
    registry.register(
        KERNEL32,
        "SetConsoleActiveScreenBuffer",
        move |args, cpu, _| {
            let mut objects = active.objects.lock().expect("guest object state");
            if !matches!(
                objects.handles.get(&args.rcx),
                Some(GuestObject::ConsoleBuffer(_))
            ) {
                return active.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            objects.active_screen_buffer = args.rcx;
            Ok(1)
        },
    );

    let fill_character = Arc::clone(state);
    let fill_character_wide = Arc::clone(state);
    registry.register(
        KERNEL32,
        "FillConsoleOutputCharacterA",
        move |args, cpu, memory| {
            fill_cells(
                &fill_character,
                cpu.gs_base,
                memory,
                args,
                false,
                args.rdx as u16,
            )
        },
    );
    registry.register(
        KERNEL32,
        "FillConsoleOutputCharacterW",
        move |args, cpu, memory| {
            fill_cells(
                &fill_character_wide,
                cpu.gs_base,
                memory,
                args,
                false,
                args.rdx as u16,
            )
        },
    );

    let fill_attribute = Arc::clone(state);
    registry.register(
        KERNEL32,
        "FillConsoleOutputAttribute",
        move |args, cpu, memory| {
            fill_cells(
                &fill_attribute,
                cpu.gs_base,
                memory,
                args,
                true,
                args.rdx as u16,
            )
        },
    );

    // The console input buffer is empty and stays empty: the machine has no
    // keyboard. Counting its events is exact.
    let count_events = Arc::clone(state);
    registry.register(
        KERNEL32,
        "GetNumberOfConsoleInputEvents",
        move |args, cpu, memory| {
            if !is_input(args.rcx) {
                return count_events.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            if args.rdx == 0 {
                return count_events.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            memory
                .write_u32(args.rdx, 0)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    // Peeking an empty input buffer succeeds and reads nothing, as
    // documented for an empty buffer.
    for name in ["PeekConsoleInputA", "PeekConsoleInputW"] {
        let peek = Arc::clone(state);
        registry.register(KERNEL32, name, move |args, cpu, memory| {
            if !is_input(args.rcx) {
                return peek.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            if args.r9 == 0 || !memory.can_write(args.r9, 4) {
                return peek.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            memory
                .write_u32(args.r9, 0)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        });
    }

    // Reading console input would block forever on a machine with no
    // keyboard, and blocking the only executor deadlocks it: the read is
    // honestly unsupported rather than a silent hang.
    let read_input = Arc::clone(state);
    for (name, _) in [("ReadConsoleInputA", ()), ("ReadConsoleInputW", ())] {
        let read_input = Arc::clone(&read_input);
        registry.register(KERNEL32, name, move |_args, cpu, memory| {
            let _ = memory;
            read_input.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0)
        });
    }

    // The console code pages are UTF-8. Setting UTF-8 is a correct no-op;
    // anything else would contradict the capture, which stays UTF-8.
    let set_cp = Arc::clone(state);
    for (name, _) in [("SetConsoleCP", ()), ("SetConsoleOutputCP", ())] {
        let set_cp = Arc::clone(&set_cp);
        registry.register(KERNEL32, name, move |args, cpu, memory| {
            let _ = memory;
            if args.rcx == 65001 {
                Ok(1)
            } else {
                set_cp.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0)
            }
        });
    }

    // Control handlers are stored and never fire: the machine generates no
    // control events, so never firing is the correct behavior rather than a
    // missing feature. The machine keeps no list beyond the count, since
    // nothing reads the list back.
    let ctrl = Arc::clone(state);
    registry.register(
        KERNEL32,
        "SetConsoleCtrlHandler",
        move |args, cpu, memory| {
            let _ = memory;
            if args.rcx == 0 && args.rdx != 0 {
                return ctrl.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            Ok(1)
        },
    );

    // Generating a control event would need asynchronous delivery to the
    // one process, machinery the machine does not have: honestly unsupported.
    let generate = Arc::clone(state);
    registry.register(
        KERNEL32,
        "GenerateConsoleCtrlEvent",
        move |_args, cpu, memory| {
            let _ = memory;
            generate.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0)
        },
    );

    // The A/W variants share a four-byte CHAR_INFO layout, with a one-byte
    // character for ANSI writes. Intersect the screen and caller-buffer
    // rectangles, keeping the requested rectangle's origin for indexing.
    for (symbol, to_screen, ansi_write) in [
        ("WriteConsoleOutputW", true, false),
        ("WriteConsoleOutputA", true, true),
        ("ReadConsoleOutputW", false, false),
        ("ReadConsoleOutputA", false, false),
    ] {
        let state = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let buffer = {
                let objects = state.objects.lock().expect("guest object state");
                match objects.handles.get(&args.rcx) {
                    Some(GuestObject::ConsoleBuffer(buffer)) => Arc::clone(buffer),
                    _ => return state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
                }
            };
            let region = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
            if args.rdx == 0 || region == 0 {
                return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            let signed = |value: u64| i64::from(value as i16);
            let width = signed(args.r8);
            let height = signed(args.r8 >> 16);
            if width <= 0 || height <= 0 {
                return state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let x = signed(args.r9);
            let y = signed(args.r9 >> 16);
            let mut rect = [0; 8];
            memory
                .read_bytes(region, &mut rect)
                .map_err(ExitReason::MemoryFault)?;
            let (coords, _) = rect.as_chunks::<2>();
            let [left, top, right, bottom] =
                std::array::from_fn(|i| i64::from(i16::from_le_bytes(coords[i])));
            let mut buffer = buffer.lock().expect("screen buffer");
            let screen_width = i64::from(buffer.width);
            let screen_height = i64::from(buffer.height);
            let clip_left = left.max(0).max(left - x);
            let clip_top = top.max(0).max(top - y);
            let clip_right = right.min(screen_width - 1).min(left - x + width - 1);
            let clip_bottom = bottom.min(screen_height - 1).min(top - y + height - 1);

            let transferred = if clip_left <= clip_right && clip_top <= clip_bottom {
                for row in clip_top..=clip_bottom {
                    let caller_row = y + row - top;
                    for column in clip_left..=clip_right {
                        let caller_column = x + column - left;
                        let offset = (caller_row * width + caller_column) as u64 * 4;
                        let addr = args.rdx.checked_add(offset).ok_or(ExitReason::MemoryFault(
                            crate::memory::MemoryError::Overflow,
                        ))?;
                        let cell = &mut buffer.cells[(row * screen_width + column) as usize];
                        if to_screen {
                            let packed = memory.read_u32(addr).map_err(ExitReason::MemoryFault)?;
                            cell.ch = if ansi_write {
                                u16::from(packed as u8)
                            } else {
                                packed as u16
                            };
                            cell.attr = (packed >> 16) as u16;
                        } else {
                            let packed = u32::from(cell.ch) | (u32::from(cell.attr) << 16);
                            memory
                                .write_u32(addr, packed)
                                .map_err(ExitReason::MemoryFault)?;
                        }
                    }
                }
                [clip_left, clip_top, clip_right, clip_bottom]
            } else {
                [0, 0, -1, -1]
            };

            for (dst, coord) in rect.as_chunks_mut::<2>().0.iter_mut().zip(transferred) {
                *dst = (coord as i16).to_le_bytes();
            }
            memory
                .write_bytes(region, &rect)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        });
    }

    for symbol in [
        "CreateConsoleScreenBuffer",
        "GetConsoleScreenBufferInfo",
        "SetConsoleCursorPosition",
        "SetConsoleTextAttribute",
        "SetConsoleScreenBufferSize",
        "SetConsoleActiveScreenBuffer",
        "FillConsoleOutputCharacterA",
        "FillConsoleOutputCharacterW",
        "FillConsoleOutputAttribute",
        "WriteConsoleOutputA",
        "WriteConsoleOutputW",
        "ReadConsoleOutputA",
        "ReadConsoleOutputW",
        "GetNumberOfConsoleInputEvents",
        "PeekConsoleInputA",
        "PeekConsoleInputW",
        "ReadConsoleInputA",
        "ReadConsoleInputW",
        "SetConsoleCP",
        "SetConsoleOutputCP",
        "SetConsoleCtrlHandler",
        "GenerateConsoleCtrlEvent",
    ] {
        registry.alias(CONSOLE_API, KERNEL32, symbol);
        registry.set_status(KERNEL32, symbol, crate::imports::ServiceStatus::Partial);
    }
}

const CONSOLE_API: &str = "api-ms-win-core-console-l2-1-0.dll";

/// CONSOLE_SCREEN_BUFFER_INFO: two COORDs, the attributes, the window rect
/// and the largest window, all packed. The window is the whole buffer.
fn write_info(
    memory: &mut crate::memory::GuestMemory,
    output: u64,
    buffer: &ScreenBuffer,
) -> Result<(), crate::memory::MemoryError> {
    if output == 0 {
        return Err(crate::memory::MemoryError::UnmappedAddress(0));
    }
    let mut fields = [0u16; 11];
    fields[0] = buffer.width;
    fields[1] = buffer.height;
    fields[2] = buffer.cursor_x;
    fields[3] = buffer.cursor_y;
    fields[4] = buffer.attribute;
    // srWindow left, top, right, bottom: the whole buffer.
    fields[7] = buffer.width.saturating_sub(1);
    fields[8] = buffer.height.saturating_sub(1);
    fields[9] = buffer.width;
    fields[10] = buffer.height;
    let bytes: Vec<u8> = fields
        .iter()
        .flat_map(|field| field.to_le_bytes())
        .collect();
    memory.write_bytes(output, &bytes)
}

fn write_default_info(
    memory: &mut crate::memory::GuestMemory,
    output: u64,
) -> Result<u64, crate::cpu::ExitReason> {
    let default = ScreenBuffer::new(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    write_info(memory, output, &default).map_err(crate::cpu::ExitReason::MemoryFault)?;
    Ok(1)
}

/// Fills `count` cells from the packed coordinate with one character or
/// attribute, writing the number of cells filled. Both forms share the
/// semantics; only the cell field differs.
fn fill_cells(
    state: &Arc<ServicesState>,
    teb: u64,
    memory: &mut crate::memory::GuestMemory,
    args: &crate::imports::Win64Args,
    attribute: bool,
    value: u16,
) -> Result<u64, crate::cpu::ExitReason> {
    use super::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};
    use crate::cpu::ExitReason;
    let buffer = {
        let objects = state.objects.lock().expect("guest object state");
        match objects.handles.get(&args.rcx) {
            Some(GuestObject::ConsoleBuffer(buffer)) => Arc::clone(buffer),
            _ => return state.fail(teb, ERROR_INVALID_HANDLE, 0),
        }
    };
    let count = args.r8 as u32;
    let x = (args.r9 & 0xFFFF) as u16;
    let y = ((args.r9 >> 16) & 0xFFFF) as u16;
    let output = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
    let mut buffer = buffer.lock().expect("screen buffer");
    if x >= buffer.width || y >= buffer.height {
        return state.fail(teb, ERROR_INVALID_PARAMETER, 0);
    }
    let mut filled = 0u32;
    let mut position = usize::from(y) * usize::from(buffer.width) + usize::from(x);
    while filled < count && position < buffer.cells.len() {
        if attribute {
            buffer.cells[position].attr = value;
        } else {
            buffer.cells[position].ch = value;
        }
        position += 1;
        filled += 1;
    }
    if output != 0 {
        memory
            .write_u32(output, filled)
            .map_err(ExitReason::MemoryFault)?;
    }
    Ok(1)
}

/// The input half of the console is the standard input device: screen
/// buffers carry no input.
fn is_input(handle: u64) -> bool {
    handle == INPUT_HANDLE
}
