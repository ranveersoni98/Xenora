// SPDX-License-Identifier: GPL-3.0-or-later

//! Typed runtime services, called by translated guest code through a bound
//! import table, and the import parser and registry behind them.
//!
//! Expected values come from the public Win32, ISO C and Microsoft x64 calling
//! convention documentation, not from the registry or the handlers.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use xenora_loader::cpu::{CpuState, ExitReason, Register};
use xenora_loader::dbt::DbtEngine;
use xenora_loader::import_table::{ImportName, ImportTableError, MAX_IMPORTS, parse_imports};
use xenora_loader::imports::{
    IMPORT_TRAMPOLINE_BASE_VA, ImportError, ImportRegistry, RegistryError, ServiceStatus, Win64Args,
};
use xenora_loader::memory::{GuestMemory, MemoryPermissions};
use xenora_loader::pe::ParsedPe;
use xenora_loader::probe::{ProbeConfig, ProbeReport, probe_pe_bytes};
use xenora_loader::runtime::{Call, Float32, Float64};
use xenora_loader::runtime_table::SERVICES;
use xenora_loader::services::{
    MAX_CAPTURED_OUTPUT, MAX_PROGRAM_ARGUMENT_BYTES, MockClock, ProgramArgumentsError,
    ServicesState, register_standard_services,
};

const BASE: u64 = 0x1_4000_0000;
const CODE_RVA: u32 = 0x1000;
const IDATA_RVA: u32 = 0x10000;
const IDATA_RAW: usize = 0x2200;
const IDATA_LEN: usize = 0x10000;
const SCRATCH: u64 = 0x5_0000;
const CPBUF: u64 = 0x6_0000;
const STACK: u64 = 0x8_0000;
const STACK_TOP: u64 = STACK + 0x800;

#[derive(Clone)]
enum Symbol {
    Name(&'static str),
    Ordinal(u16),
}

/// Original PE32+ image importing `imports`, one descriptor each. The code for
/// import `n`, at RVA 0x1000 + 16n, is `call [its slot]; hlt`.
struct Image {
    bytes: Vec<u8>,
    slots: Vec<u32>,
}

fn build(imports: &[(&str, Symbol)]) -> Image {
    let mut pe = vec![0u8; IDATA_RAW + IDATA_LEN];
    fn put(pe: &mut [u8], at: usize, bytes: &[u8]) {
        pe[at..at + bytes.len()].copy_from_slice(bytes);
    }
    put(&mut pe, 0, b"MZ");
    put(&mut pe, 0x3C, &0x80u32.to_le_bytes());
    put(&mut pe, 0x80, b"PE\0\0");
    put(&mut pe, 0x84, &0x8664u16.to_le_bytes());
    put(&mut pe, 0x86, &2u16.to_le_bytes());
    put(&mut pe, 0x94, &240u16.to_le_bytes());
    let optional = 0x98;
    put(&mut pe, optional, &0x20Bu16.to_le_bytes());
    put(&mut pe, optional + 16, &CODE_RVA.to_le_bytes());
    put(&mut pe, optional + 24, &BASE.to_le_bytes());
    put(&mut pe, optional + 32, &0x1000u32.to_le_bytes());
    put(&mut pe, optional + 36, &0x200u32.to_le_bytes());
    put(&mut pe, optional + 56, &0x20000u32.to_le_bytes());
    put(&mut pe, optional + 60, &0x200u32.to_le_bytes());
    put(&mut pe, optional + 108, &16u32.to_le_bytes());
    put(&mut pe, optional + 120, &IDATA_RVA.to_le_bytes());
    let descriptor_size = 20 * (imports.len() as u32 + 1);
    put(&mut pe, optional + 124, &descriptor_size.to_le_bytes());
    for (index, (name, rva, raw, len, flags)) in [
        (b".text", CODE_RVA, 0x200, 0x2000, 0x6000_0020u32),
        (b".idat", IDATA_RVA, IDATA_RAW, IDATA_LEN, 0xC000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let section = optional + 240 + 40 * index;
        put(&mut pe, section, name);
        put(&mut pe, section + 8, &(len as u32).to_le_bytes());
        put(&mut pe, section + 12, &rva.to_le_bytes());
        put(&mut pe, section + 16, &(len as u32).to_le_bytes());
        put(&mut pe, section + 20, &(raw as u32).to_le_bytes());
        put(&mut pe, section + 36, &flags.to_le_bytes());
    }

    let file = |rva: u32| IDATA_RAW + (rva - IDATA_RVA) as usize;
    let mut next = IDATA_RVA + descriptor_size;
    let mut take = |len: usize| {
        let rva = next;
        next = (next + len as u32 + 7) & !7;
        rva
    };
    let mut slots = Vec::new();
    for (index, (module, symbol)) in imports.iter().enumerate() {
        let module_rva = take(module.len() + 1);
        put(&mut pe, file(module_rva), module.as_bytes());
        let entry = match symbol {
            Symbol::Ordinal(ordinal) => 1 << 63 | u64::from(*ordinal),
            Symbol::Name(name) => {
                let hint = take(name.len() + 3);
                put(&mut pe, file(hint) + 2, name.as_bytes());
                u64::from(hint)
            }
        };
        let (lookup, slot) = (take(16), take(16));
        put(&mut pe, file(lookup), &entry.to_le_bytes());
        put(&mut pe, file(slot), &entry.to_le_bytes());
        let descriptor = file(IDATA_RVA) + 20 * index;
        put(&mut pe, descriptor, &lookup.to_le_bytes());
        put(&mut pe, descriptor + 12, &module_rva.to_le_bytes());
        put(&mut pe, descriptor + 16, &slot.to_le_bytes());
        slots.push(slot);

        let code_rva = CODE_RVA + 16 * index as u32;
        let displacement = slot.wrapping_sub(code_rva + 6);
        let at = 0x200 + 16 * index;
        put(&mut pe, at, &[0xFF, 0x15]); // call qword ptr [rip + displacement]
        put(&mut pe, at + 2, &displacement.to_le_bytes());
        put(&mut pe, at + 6, &[0xF4]); // hlt
    }
    Image { bytes: pe, slots }
}

fn standard(clock: u64) -> (ImportRegistry, Arc<MockClock>) {
    let (registry, clock, _) = standard_with_state(clock);
    (registry, clock)
}

fn standard_with_state(clock: u64) -> (ImportRegistry, Arc<MockClock>, Arc<ServicesState>) {
    let clock = Arc::new(MockClock::new(clock));
    let state = Arc::new(ServicesState::new(clock.clone()));
    let mut registry = ImportRegistry::new();
    register_standard_services(&mut registry, state.clone());
    (registry, clock, state)
}

/// A guest whose image imports every generated service from its own library,
/// and `_errno` after them, which is registered by hand.
struct Guest {
    engine: DbtEngine,
    memory: GuestMemory,
    clock: Arc<MockClock>,
    state: Arc<ServicesState>,
    /// IAT slot RVAs in import order: the table services, `_errno`, then
    /// the legacy data symbols.
    slots: Vec<u32>,
    teb: u64,
    /// Upper halves and XMM lanes of unrelated arguments hold this pattern.
    xmm: [u128; 4],
}

impl Guest {
    fn new() -> Self {
        let mut imports: Vec<(&str, Symbol)> = SERVICES
            .iter()
            .map(|service| (service.library, Symbol::Name(service.symbol)))
            .collect();
        imports.push(("ucrtbase.dll", Symbol::Name("_errno")));
        for symbol in LEGACY_DATA_SYMBOLS {
            imports.push(("msvcrt.dll", Symbol::Name(symbol)));
        }
        for symbol in LEGACY_FUNCTION_SYMBOLS {
            imports.push(("msvcrt.dll", Symbol::Name(symbol)));
        }
        let image = build(&imports);
        let pe = ParsedPe::parse(&image.bytes).unwrap();
        let mut memory = pe.load_into_memory(&image.bytes).unwrap().memory;
        memory
            .map_region(SCRATCH, 0x100, MemoryPermissions::READ_WRITE)
            .unwrap();
        memory
            .map_region(STACK, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        let (mut registry, clock, state) = standard_with_state(0x01DA_0000_1234_5678);
        let bound = registry
            .bind_imports(&pe, &image.bytes, BASE, &mut memory)
            .unwrap();
        assert_eq!(
            bound,
            SERVICES.len() + 1 + LEGACY_DATA_SYMBOLS.len() + LEGACY_FUNCTION_SYMBOLS.len()
        );
        let mut engine = DbtEngine::new(256 * 1024).unwrap();
        engine.set_import_registry(registry);
        Self {
            engine,
            memory,
            clock,
            state,
            slots: image.slots,
            teb: 0,
            xmm: [0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_0123_4567; 4],
        }
    }

    fn run(&mut self, symbol: &str, args: &[u64]) -> (CpuState, ExitReason) {
        let index = SERVICES
            .iter()
            .position(|service| service.symbol == symbol)
            .or((symbol == "_errno").then_some(SERVICES.len()))
            .or(LEGACY_FUNCTION_SYMBOLS
                .iter()
                .position(|&entry| entry == symbol)
                .map(|index| SERVICES.len() + 1 + LEGACY_DATA_SYMBOLS.len() + index))
            .unwrap();
        let mut cpu = CpuState::new(BASE + u64::from(CODE_RVA) + 16 * index as u64, STACK_TOP);
        cpu.gs_base = self.teb;
        for (index, register) in cpu.gpr.iter_mut().enumerate() {
            if index != Register::Rsp as usize {
                *register = 0x0101_0101_0101_0101 * (index as u64 + 1);
            }
        }
        for (register, value) in [Register::Rcx, Register::Rdx, Register::R8, Register::R9]
            .into_iter()
            .zip(args)
        {
            cpu.set(register, *value);
        }
        for (index, register) in cpu.xmm.iter_mut().enumerate() {
            *register = 0x1111_2222_3333_4444_5555_6666_7777_0000 + index as u128;
        }
        cpu.xmm[..4].copy_from_slice(&self.xmm);
        let before = cpu.clone();
        let result = self.engine.run(&mut cpu, &mut self.memory, 8);
        if result.exit_reason == ExitReason::Halt {
            use Register::{R12, R13, R14, R15, Rbp, Rbx, Rdi, Rsi, Rsp};
            for register in [Rbx, Rbp, Rdi, Rsi, Rsp, R12, R13, R14, R15] {
                assert_eq!(
                    cpu.get(register),
                    before.get(register),
                    "{symbol} {register:?}"
                );
            }
            assert_eq!(cpu.xmm[6..], before.xmm[6..], "{symbol}");
            assert_eq!(cpu.mxcsr, before.mxcsr, "{symbol}");
        }
        (cpu, result.exit_reason)
    }

    fn call(&mut self, symbol: &str, args: &[u64]) -> u64 {
        let (cpu, exit) = self.run(symbol, args);
        assert_eq!(exit, ExitReason::Halt, "{symbol}");
        cpu.get(Register::Rax)
    }

    fn last_error(&mut self) -> u64 {
        self.call("GetLastError", &[])
    }

    /// The calling thread's `errno`, read through the pointer `_errno` returns.
    fn errno(&mut self) -> u32 {
        let address = self.call("_errno", &[]);
        self.memory.read_u32(address).unwrap()
    }

    fn set_errno(&mut self, value: u32) {
        let address = self.call("_errno", &[]);
        self.memory.write_u32(address, value).unwrap();
    }
}

/// Bits above an `int` argument are not part of it.
const JUNK_HIGH: u64 = 0xFFFF_FFFF_0000_0000;

const PROCESS: u64 = u64::MAX;
const THREAD: u64 = u64::MAX - 1;

#[test]
fn identity_services_return_documented_pseudo_handles_and_ids() {
    let mut guest = Guest::new();
    assert_eq!(guest.call("GetCurrentProcess", &[]), PROCESS);
    assert_eq!(guest.call("GetCurrentThread", &[]), THREAD);
    let id = guest.call("GetCurrentProcessId", &[]);
    assert!(id != 0 && id <= u64::from(u32::MAX));
    assert_ne!(guest.call("GetCurrentThreadId", &[]), id);
    assert_eq!(guest.call("GetProcessId", &[PROCESS]), id);
    assert_eq!(guest.call("GetProcessId", &[THREAD]), 0);
    assert_eq!(guest.last_error(), 6); // ERROR_INVALID_HANDLE
}

#[test]
fn priority_boost_round_trips_and_checks_its_handle() {
    let mut guest = Guest::new();
    let read = |guest: &mut Guest| {
        guest.memory.write_u64(SCRATCH, u64::MAX).unwrap();
        assert_eq!(
            guest.call("GetProcessPriorityBoost", &[PROCESS, SCRATCH]),
            1
        );
        // A BOOL is four bytes; the next four stay untouched.
        assert_eq!(guest.memory.read_u32(SCRATCH + 4).unwrap(), u32::MAX);
        guest.memory.read_u32(SCRATCH).unwrap()
    };
    assert_eq!(read(&mut guest), 0);
    // Any nonzero BOOL disables; bits above 32 are not part of the argument.
    assert_eq!(
        guest.call("SetProcessPriorityBoost", &[PROCESS, 0xFFFF_FFFF_0000_0002]),
        1
    );
    assert_eq!(read(&mut guest), 1);
    assert_eq!(
        guest.call("SetProcessPriorityBoost", &[PROCESS, 0xFFFF_FFFF_0000_0000]),
        1
    );
    assert_eq!(read(&mut guest), 0);
    assert_eq!(guest.call("SetProcessPriorityBoost", &[THREAD, 1]), 0);
    assert_eq!(guest.last_error(), 6);
    assert_eq!(
        guest.call("GetProcessPriorityBoost", &[PROCESS, 0x9000_0000]),
        0
    );
    assert_eq!(guest.last_error(), 998); // ERROR_NOACCESS
}

#[test]
fn thread_handles_check_access_and_are_rejected_once_closed() {
    let mut guest = Guest::new();
    let id = guest.call("GetCurrentThreadId", &[]);
    // THREAD_QUERY_INFORMATION only.
    let query = guest.call("OpenThread", &[0x40, 0, id]);
    assert_ne!(query, 0);
    assert_eq!(guest.call("GetThreadPriority", &[query]), 0);
    assert_eq!(guest.call("SetThreadPriority", &[query, 1]), 0);
    assert_eq!(guest.last_error(), 5); // ERROR_ACCESS_DENIED
    assert_eq!(guest.call("GetThreadPriority", &[query]), 0);
    // THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION.
    let full = guest.call("OpenThread", &[0x60, 0, id]);
    assert_ne!(full, query);
    // A negative int is returned in EAX with the upper half clear.
    assert_eq!(
        guest.call("SetThreadPriority", &[full, 0xABCD_0000_FFFF_FFFE]),
        1
    );
    assert_eq!(guest.call("GetThreadPriority", &[full]), 0xFFFF_FFFE);
    assert_eq!(guest.call("SetThreadPriority", &[full, 3]), 0);
    assert_eq!(guest.last_error(), 87); // ERROR_INVALID_PARAMETER
    assert_eq!(guest.call("CloseHandle", &[full]), 1);
    assert_eq!(guest.call("GetThreadPriority", &[full]), 0x7FFF_FFFF);
    assert_eq!(guest.last_error(), 6);
    assert_eq!(guest.call("CloseHandle", &[full]), 0);
    assert_eq!(guest.call("OpenThread", &[0x40, 0, id + 1]), 0);
    assert_eq!(guest.last_error(), 87);
    assert_eq!(guest.call("OpenThread", &[0x40, 1, id]), 0);
    assert_eq!(guest.last_error(), 50); // ERROR_NOT_SUPPORTED
    assert_ne!(
        guest.call("OpenThread", &[0x40, 0, id]),
        full,
        "handles are not reused"
    );
}

#[test]
fn system_time_comes_from_the_injected_clock() {
    let mut guest = Guest::new();
    guest.call("GetSystemTimeAsFileTime", &[SCRATCH + 3]);
    assert_eq!(
        guest.memory.read_u64(SCRATCH + 3).unwrap(),
        0x01DA_0000_1234_5678
    );
    guest.clock.advance(10);
    guest.call("GetSystemTimeAsFileTime", &[SCRATCH]);
    assert_eq!(
        guest.memory.read_u64(SCRATCH).unwrap(),
        0x01DA_0000_1234_5682
    );
    for pointer in [0, SCRATCH + 0xFC] {
        let before = guest.memory.read_u32(SCRATCH + 0xFC).unwrap();
        let (_, exit) = guest.run("GetSystemTimeAsFileTime", &[pointer]);
        assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
        assert_eq!(guest.memory.read_u32(SCRATCH + 0xFC).unwrap(), before);
    }
}

#[test]
fn guest_udp_loopback_delivers_datagrams_through_bound_imports() {
    let symbols = [
        "WSAStartup",
        "socket",
        "bind",
        "connect",
        "send",
        "recv",
        "WSAGetLastError",
        "WSACleanup",
        "WSAPoll",
        "getsockname",
        "getpeername",
        "getsockopt",
        "inet_pton",
        "inet_ntop",
        "htons",
    ];
    let imports = symbols.map(|symbol| ("ws2_32.dll", Symbol::Name(symbol)));
    let image = build(&imports);
    let pe = ParsedPe::parse(&image.bytes).unwrap();
    let mut memory = pe.load_into_memory(&image.bytes).unwrap().memory;
    memory
        .map_region(SCRATCH, 4096, MemoryPermissions::READ_WRITE)
        .unwrap();
    memory
        .map_region(STACK, 4096, MemoryPermissions::READ_WRITE)
        .unwrap();
    let (mut registry, _) = standard(0);
    assert_eq!(
        registry
            .bind_imports(&pe, &image.bytes, BASE, &mut memory)
            .unwrap(),
        symbols.len()
    );
    let mut engine = DbtEngine::new(256 * 1024).unwrap();
    engine.set_import_registry(registry);
    let mut call = |memory: &mut GuestMemory, symbol, args: &[u64]| {
        let index = symbols.iter().position(|&name| symbol == name).unwrap() as u64;
        let mut cpu = CpuState::new(BASE + u64::from(CODE_RVA) + 16 * index, STACK_TOP);
        for (register, &value) in [Register::Rcx, Register::Rdx, Register::R8, Register::R9]
            .into_iter()
            .zip(args)
        {
            cpu.set(register, value);
        }
        if let Some(&fifth) = args.get(4) {
            memory.write_u64(STACK_TOP + 32, fifth).unwrap();
        }
        let result = engine.run(&mut cpu, memory, 8);
        assert_eq!(result.exit_reason, ExitReason::Halt, "{symbol}");
        cpu.get(Register::Rax)
    };
    let address = SCRATCH + 0x200;
    let outgoing = SCRATCH + 0x220;
    let incoming = SCRATCH + 0x240;
    let text = SCRATCH + 0x260;
    let poll = SCRATCH + 0x280;
    let formatted = SCRATCH + 0x2a0;
    let address_length = SCRATCH + 0x2b0;
    let peer_address = SCRATCH + 0x2c0;
    memory.write_u16(address, 2).unwrap();
    let port = call(&mut memory, "htons", &[5000]);
    assert_eq!(port, 0x8813);
    memory.write_bytes(text, b"127.0.0.1\0").unwrap();
    assert_eq!(call(&mut memory, "inet_pton", &[2, text, address + 4]), 1);
    assert_eq!(
        memory.read_u32(address + 4).unwrap().to_le_bytes(),
        [127, 0, 0, 1]
    );
    memory.write_bytes(text, b"127.0.0.999\0").unwrap();
    assert_eq!(call(&mut memory, "inet_pton", &[2, text, address + 4]), 0);
    assert_eq!(
        memory.read_u32(address + 4).unwrap().to_le_bytes(),
        [127, 0, 0, 1]
    );
    assert_eq!(
        call(&mut memory, "inet_pton", &[23, text, address + 4]),
        u64::from(u32::MAX)
    );
    assert_eq!(call(&mut memory, "WSAGetLastError", &[]), 10047);
    memory.write_u8(formatted, 0xaa).unwrap();
    assert_eq!(
        call(&mut memory, "inet_ntop", &[2, address + 4, formatted, 9]),
        0
    );
    assert_eq!(call(&mut memory, "WSAGetLastError", &[]), 87);
    assert_eq!(memory.read_u8(formatted).unwrap(), 0xaa);
    assert_eq!(
        call(&mut memory, "inet_ntop", &[2, address + 4, formatted, 10]),
        formatted
    );
    let mut formatted_address = [0; 10];
    memory
        .read_bytes(formatted, &mut formatted_address)
        .unwrap();
    assert_eq!(&formatted_address, b"127.0.0.1\0");
    assert_eq!(call(&mut memory, "WSAStartup", &[0x0202, SCRATCH]), 0);
    let receiver = call(&mut memory, "socket", &[2, 2, 17]);
    let sender = call(&mut memory, "socket", &[2, 2, 17]);
    assert_ne!(receiver, u64::MAX);
    assert_ne!(sender, u64::MAX);
    assert_ne!(sender, receiver);
    for (option, expected) in [(0x1008, 2), (0x2003, 65_507)] {
        memory.write_u32(address_length, 8).unwrap();
        assert_eq!(
            call(
                &mut memory,
                "getsockopt",
                &[sender, 0xffff, option, incoming, address_length]
            ),
            0
        );
        assert_eq!(memory.read_u32(incoming).unwrap(), expected);
        assert_eq!(memory.read_u32(address_length).unwrap(), 4);
    }
    memory.write_u32(address_length, 3).unwrap();
    assert_eq!(
        call(
            &mut memory,
            "getsockopt",
            &[sender, 0xffff, 0x1008, incoming, address_length]
        ),
        u64::from(u32::MAX)
    );
    assert_eq!(call(&mut memory, "WSAGetLastError", &[]), 10014);
    assert_eq!(memory.read_u32(incoming).unwrap(), 65_507);
    assert_eq!(call(&mut memory, "bind", &[receiver, address, 16]), 0);
    memory.write_u32(address_length, 15).unwrap();
    assert_eq!(
        call(
            &mut memory,
            "getsockname",
            &[receiver, address, address_length]
        ),
        u64::from(u32::MAX)
    );
    assert_eq!(call(&mut memory, "WSAGetLastError", &[]), 10014);
    assert_eq!(memory.read_u16(address + 2).unwrap(), 0);
    memory.write_u32(address_length, 32).unwrap();
    assert_eq!(
        call(
            &mut memory,
            "getsockname",
            &[receiver, address, address_length]
        ),
        0
    );
    assert_eq!(memory.read_u32(address_length).unwrap(), 16);
    assert_eq!(memory.read_u16(address + 2).unwrap().swap_bytes(), 49152);
    assert_eq!(call(&mut memory, "connect", &[sender, address, 16]), 0);
    assert_eq!(
        call(
            &mut memory,
            "getpeername",
            &[sender, peer_address, address_length]
        ),
        0
    );
    assert_eq!(
        memory.read_u64(peer_address).unwrap(),
        memory.read_u64(address).unwrap()
    );
    memory.write_u64(poll, receiver).unwrap();
    memory.write_u16(poll + 8, 0x0100).unwrap();
    memory.write_u64(poll + 16, sender).unwrap();
    memory.write_u16(poll + 24, 0x0010).unwrap();
    assert_eq!(call(&mut memory, "WSAPoll", &[poll, 2, 0]), 1);
    assert_eq!(memory.read_u16(poll + 10).unwrap(), 0);
    assert_eq!(memory.read_u16(poll + 26).unwrap(), 0x0010);
    memory.write_bytes(outgoing, b"loop").unwrap();
    for _ in 0..16 {
        assert_eq!(call(&mut memory, "send", &[sender, outgoing, 4, 0]), 4);
    }
    assert_eq!(
        call(&mut memory, "send", &[sender, outgoing, 4, 0]),
        u64::from(u32::MAX)
    );
    assert_eq!(call(&mut memory, "WSAGetLastError", &[]), 10055);
    assert_eq!(call(&mut memory, "WSAPoll", &[poll, 2, 0]), 1);
    assert_eq!(memory.read_u16(poll + 10).unwrap(), 0x0100);
    assert_eq!(memory.read_u16(poll + 26).unwrap(), 0);
    for _ in 0..16 {
        assert_eq!(call(&mut memory, "recv", &[receiver, incoming, 4, 0]), 4);
        let mut received = [0; 4];
        memory.read_bytes(incoming, &mut received).unwrap();
        assert_eq!(&received, b"loop");
        memory.write_u32(incoming, 0).unwrap();
    }
    assert_eq!(
        call(&mut memory, "recv", &[receiver, incoming, 4, 0]),
        u64::from(u32::MAX)
    );
    assert_eq!(call(&mut memory, "WSAGetLastError", &[]), 10035);
    assert_eq!(call(&mut memory, "WSAPoll", &[poll, 2, 0]), 1);
    assert_eq!(memory.read_u16(poll + 10).unwrap(), 0);
    assert_eq!(memory.read_u16(poll + 26).unwrap(), 0x0010);
    let started = std::time::Instant::now();
    assert_eq!(call(&mut memory, "WSAPoll", &[poll, 1, 10]), 0);
    assert!(started.elapsed() >= std::time::Duration::from_millis(10));
    assert_eq!(memory.read_u16(poll + 10).unwrap(), 0);
    assert_eq!(
        call(&mut memory, "WSAPoll", &[poll, 1, 1001]),
        u64::from(u32::MAX)
    );
    assert_eq!(call(&mut memory, "WSAGetLastError", &[]), 10045);
    assert_eq!(call(&mut memory, "WSACleanup", &[]), 0);
}

#[test]
fn last_error_isolated_across_guest_thread_switches() {
    let mut guest = Guest::new();
    guest.teb = 0x10000;
    guest.call("SetLastError", &[123]);
    guest.teb = 0x20000;
    assert_eq!(guest.last_error(), 0);
    assert_eq!(guest.call("CloseHandle", &[123]), 0);
    assert_eq!(guest.last_error(), 6);
    guest.teb = 0x10000;
    guest.call("GetCurrentProcessId", &[]);
    assert_eq!(guest.last_error(), 123);
    guest.call("SetLastError", &[0]);
    assert_eq!(guest.last_error(), 0);
    guest.teb = 0x20000;
    assert_eq!(guest.last_error(), 6);
}

/// The last-error code is documented as kept per thread, and most functions
/// set it only when they fail (errhandlingapi.h GetLastError).
#[test]
fn a_successful_call_keeps_another_threads_error_and_its_own() {
    let mut guest = Guest::new();
    guest.teb = 0x10000;
    assert_eq!(guest.call("VirtualAlloc", &[0, 0, 0x3000, 4]), 0);
    assert_eq!(guest.last_error(), 87); // ERROR_INVALID_PARAMETER
    guest.teb = 0x20000;
    guest.call("SetLastError", &[0xFFFF_FFFF]);
    assert_eq!(guest.call("GetCurrentProcess", &[]), PROCESS);
    assert_eq!(guest.call("GetCurrentThreadId", &[]), 0x4104);
    assert_eq!(
        guest.last_error(),
        0xFFFF_FFFF,
        "success keeps a nonzero error"
    );
    guest.teb = 0x10000;
    assert_eq!(guest.last_error(), 87);
}

#[test]
fn a_retired_thread_starts_clean_when_its_teb_address_is_reused() {
    let mut guest = Guest::new();
    guest.teb = 0x10000;
    guest.call("SetLastError", &[998]);
    guest.teb = 0x20000;
    guest.call("CloseHandle", &[0x1234]);

    assert!(guest.state.retire_thread_last_error(0x10000));
    assert!(!guest.state.retire_thread_last_error(0x10000));
    assert!(
        !guest.state.retire_thread_last_error(0x30000),
        "a thread that never failed holds no value"
    );
    assert_eq!(guest.last_error(), 6, "the other thread is untouched");
    guest.teb = 0x10000;
    assert_eq!(guest.last_error(), 0);
    guest.call("SetLastError", &[5]);
    assert_eq!(guest.last_error(), 5);
}

/// Guest memory for format strings, argument lists and strings.
const TEXT: u64 = 0x100_0000;
const TEXT_LEN: usize = 0x10_0000 + 0x1000;
/// Where `print` puts the `va_list`, and where string arguments start.
const VA_LIST: u64 = TEXT + 0x400;
const STRINGS: u64 = TEXT + 0x800;
/// What a program built with mingw-w64 passes as the options of
/// `__stdio_common_vfprintf`.
const MINGW_OPTIONS: u64 = 0x24;
const LIMIT: ExitReason = ExitReason::IllegalInstruction(0xFE);
const STDIO_EINVAL: u32 = 22;
/// The low 32 bits of an `int` result of -1, which is also `EOF`.
const STDIO_MINUS_ONE: u64 = 0xFFFF_FFFF;

/// A guest with its three standard streams and room for text.
fn stdio_guest() -> (Guest, [u64; 3]) {
    let mut guest = Guest::new();
    guest
        .memory
        .map_region(TEXT, TEXT_LEN, MemoryPermissions::READ_WRITE)
        .unwrap();
    let streams = [0, 1, 2].map(|index| guest.call("__acrt_iob_func", &[index]));
    (guest, streams)
}

/// Put a NUL-terminated string in guest memory and return its address.
fn place(guest: &mut Guest, at: u64, text: &[u8]) -> u64 {
    guest.memory.write_bytes(at, text).unwrap();
    guest.memory.write_u8(at + text.len() as u64, 0).unwrap();
    at
}

/// Call `__stdio_common_vfprintf` as compiled code does: the format string
/// and the `va_list` are in guest memory, and the fifth argument is on the
/// stack above the shadow space.
fn print_with(
    guest: &mut Guest,
    options: u64,
    stream: u64,
    format: &[u8],
    slots: &[u64],
) -> (u64, ExitReason) {
    let format = place(guest, TEXT, format);
    for (index, slot) in slots.iter().enumerate() {
        guest
            .memory
            .write_u64(VA_LIST + 8 * index as u64, *slot)
            .unwrap();
    }
    guest.memory.write_u64(STACK_TOP + 32, VA_LIST).unwrap();
    let (cpu, exit) = guest.run("__stdio_common_vfprintf", &[options, stream, format, 0]);
    (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit)
}

fn print(guest: &mut Guest, stream: u64, format: &[u8], slots: &[u64]) -> u64 {
    let (count, exit) = print_with(guest, MINGW_OPTIONS, stream, format, slots);
    assert_eq!(
        exit,
        ExitReason::Halt,
        "{}",
        String::from_utf8_lossy(format)
    );
    count
}

/// The options of one `__stdio_common_vsprintf` family call, and what it
/// returned: the result and the exit. `count` is the third argument, and the
/// locale and the va_list pointer are the two stack slots, as the generated
/// code of mingw-w64 passes them.
fn buffer_print_with(
    guest: &mut Guest,
    symbol: &str,
    options: u64,
    buffer: u64,
    count: u64,
    format: &[u8],
    slots: &[u64],
) -> (u64, ExitReason) {
    let format = place(guest, TEXT, format);
    for (index, slot) in slots.iter().enumerate() {
        guest
            .memory
            .write_u64(VA_LIST + 8 * index as u64, *slot)
            .unwrap();
    }
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    guest.memory.write_u64(STACK_TOP + 40, VA_LIST).unwrap();
    let (cpu, exit) = guest.run(symbol, &[options, buffer, count, format]);
    (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit)
}

const STANDARD: u64 = MINGW_OPTIONS | 0x2;
const LEGACY: u64 = MINGW_OPTIONS | 0x1;

fn buffer_print(
    guest: &mut Guest,
    options: u64,
    buffer: u64,
    count: u64,
    format: &[u8],
    slots: &[u64],
) -> u64 {
    let (result, exit) = buffer_print_with(
        guest,
        "__stdio_common_vsprintf",
        options,
        buffer,
        count,
        format,
        slots,
    );
    assert_eq!(
        exit,
        ExitReason::Halt,
        "{}",
        String::from_utf8_lossy(format)
    );
    result
}

/// The bytes at `buffer` as the guest sees them, terminator included.
fn buffer_bytes(guest: &Guest, buffer: u64, count: usize) -> Vec<u8> {
    let mut bytes = vec![0xCC; count];
    guest.memory.read_bytes(buffer, &mut bytes).unwrap();
    bytes
}

/// A guest with the text region the buffer tests write to. The scratch
/// region is part of every guest.
fn buffer_guest() -> Guest {
    let mut guest = Guest::new();
    guest
        .memory
        .map_region(TEXT, TEXT_LEN, MemoryPermissions::READ_WRITE)
        .unwrap();
    guest
}

/// `__acrt_iob_func` (corecrt_wstdio.h) is what `stdin`, `stdout` and
/// `stderr` expand to: indices 0, 1 and 2. A `FILE` is one pointer wide.
#[test]
fn standard_streams_are_three_stable_file_objects() {
    let (mut guest, streams) = stdio_guest();
    let mut sorted = streams;
    sorted.sort_unstable();
    assert!(sorted[0] != 0 && sorted[1] - sorted[0] >= 8 && sorted[2] - sorted[1] >= 8);
    // Each call returns the same object, and the index is an unsigned int.
    for (index, stream) in streams.into_iter().enumerate() {
        let index = index as u64;
        assert_eq!(guest.call("__acrt_iob_func", &[index]), stream);
        assert_eq!(
            guest.call("__acrt_iob_func", &[0xFFFF_FFFF_0000_0000 | index]),
            stream
        );
    }
    // There is no fourth standard stream.
    for index in [3, 4, 0x8000_0000, 0xFFFF_FFFF] {
        assert_eq!(
            guest.run("__acrt_iob_func", &[index]).1,
            LIMIT,
            "{index:#x}"
        );
    }
    // Asking for a stream writes nothing to it.
    assert!(guest.state.standard_output().is_empty());
    assert!(guest.state.standard_error().is_empty());
}

/// `__stdio_common_vfprintf` is what `printf` and `fprintf` call. It returns
/// "the number of characters written" (Microsoft Learn, vfprintf). The
/// standard streams are text-mode streams, where "each line feed is replaced
/// with a carriage return-line feed pair" that "has no effect on the return
/// value" (fwrite). Expected text follows the format specification page.
#[test]
fn formatted_output_reaches_the_captured_standard_streams() {
    let (mut guest, [_, out, err]) = stdio_guest();
    // The calls the Gate A2 program makes, with the options mingw-w64 passes.
    assert_eq!(print(&mut guest, out, b"gate a2: %d arguments\n", &[3]), 21);
    let one = place(&mut guest, STRINGS, b"one");
    assert_eq!(print(&mut guest, out, b"arg %d = %s\n", &[1, one]), 12);
    assert_eq!(
        guest.state.standard_output(),
        b"gate a2: 3 arguments\r\narg 1 = one\r\n"
    );
    assert!(guest.state.standard_error().is_empty());

    // stderr is a separate buffer.
    assert_eq!(print(&mut guest, err, b"%s: %#x\n", &[one, 0xa2]), 10);
    assert_eq!(guest.state.standard_error(), b"one: 0xa2\r\n");
    assert_eq!(guest.state.standard_output().len(), 35);

    // The arguments are 8-byte slots read in order from the va_list: a width
    // from *, an int whose upper half is junk, a 64-bit value, a string with
    // a precision, a character and a pointer.
    let junk = 0xDEAD_BEEF_0000_0000;
    let slots = [
        6,
        junk | 0xFFFF_FFFE,
        u64::MAX,
        one,
        u64::from(b'!'),
        0x1_4000_2000,
    ];
    let (mut fresh, [_, out, _]) = stdio_guest();
    let one = place(&mut fresh, STRINGS, b"one");
    let slots = [slots[0], slots[1], slots[2], one, slots[4], slots[5]];
    let text: &[u8] = b"[%*d] %llu %.2s%c %p";
    // The result is the number of characters in the text below: 50.
    let expected: &[u8] = b"[    -2] 18446744073709551615 on! 0000000140002000";
    assert_eq!(print(&mut fresh, out, text, &slots), 50);
    assert_eq!(expected.len(), 50);
    assert_eq!(fresh.state.standard_output(), expected);

    // A double is one slot of the va_list too: its bits, between an int and
    // a string. 0.1 is not exact, and prints as its nearest decimal.
    let (mut fresh, [_, out, _]) = stdio_guest();
    let one = place(&mut fresh, STRINGS, b"one");
    let slots = [
        7,
        3.25f64.to_bits(),
        one,
        0.1f64.to_bits(),
        (-1e100f64).to_bits(),
    ];
    let text: &[u8] = b"%d %.2f %s %g %e";
    let expected: &[u8] = b"7 3.25 one 0.1 -1.000000e+100";
    assert_eq!(print(&mut fresh, out, text, &slots), 29);
    assert_eq!(expected.len(), 29);
    assert_eq!(fresh.state.standard_output(), expected);

    // The option bits that concern floating point. With the three-digit
    // exponent bit the e style has three; without the standard rounding bit
    // the conversion still prints, rounding ties away from zero instead of
    // to the even digit - and 1.5 at six fractional digits is exact, so the
    // two modes agree here.
    let (mut fresh, [_, out, _]) = stdio_guest();
    let slots = [1.5f64.to_bits()];
    let (count, exit) = print_with(&mut fresh, MINGW_OPTIONS | 0x10, out, b"%e", &slots);
    assert_eq!((count, exit), (13, ExitReason::Halt));
    assert_eq!(fresh.state.standard_output(), b"1.500000e+000");
    for options in [0x04, 0x00, 0x14] {
        let (count, exit) = print_with(&mut fresh, options, out, b" %d", &[7]);
        assert_eq!((count, exit), (2, ExitReason::Halt), "{options:#x}");
        let (count, exit) = print_with(&mut fresh, options, out, b"%f", &slots);
        assert_eq!((count, exit), (8, ExitReason::Halt), "{options:#x}");
    }
    assert_eq!(
        fresh.state.standard_output(),
        b"1.500000e+000 71.500000 71.500000 71.500000"
    );

    // Several line feeds in one call, text with none, and an empty format.
    let (mut guest, [_, out, _]) = stdio_guest();
    assert_eq!(print(&mut guest, out, b"a\n\nb\n", &[]), 5);
    assert_eq!(print(&mut guest, out, b"no newline", &[]), 10);
    assert_eq!(print(&mut guest, out, b"", &[]), 0);
    // A carriage return the program wrote itself is kept as it is.
    assert_eq!(print(&mut guest, out, b"\r\n", &[]), 2);
    assert_eq!(
        guest.state.standard_output(),
        b"a\r\n\r\nb\r\nno newline\r\r\n"
    );

    // The option bits that concern wide functions and floating point change
    // nothing here.
    for options in [0, 0x04, 0x10, 0x20, 0x24, 0x34] {
        let (mut guest, [_, out, _]) = stdio_guest();
        let (count, exit) = print_with(&mut guest, options, out, b"%5.3d|%-4x|", &[7, 255]);
        assert_eq!((count, exit), (11, ExitReason::Halt), "{options:#x}");
        assert_eq!(
            guest.state.standard_output(),
            b"  007|ff  |",
            "{options:#x}"
        );
    }
}

#[test]
fn hexadecimal_float_rounding_follows_the_rounding_mode() {
    // 1.53125 is exactly 0x1.88p+0: at precision 1 the first dropped digit
    // is exactly half a unit of the last kept one. Ties-to-even keeps the
    // even digit 8; the legacy mode rounds away from zero, up to 9. The
    // pre-2015 library never printed hexadecimal floating-point at all, so
    // the legacy answer is Xenora's consistent extension of its documented
    // decimal rounding rule, not measured behavior.
    let (mut fresh, [_, out, _]) = stdio_guest();
    let slots = [1.53125f64.to_bits()];
    let (count, exit) = print_with(&mut fresh, MINGW_OPTIONS, out, b"%.1a", &slots);
    assert_eq!((count, exit), (8, ExitReason::Halt));
    assert_eq!(fresh.state.standard_output(), b"0x1.8p+0");
    let (mut fresh, [_, out, _]) = stdio_guest();
    let (count, exit) = print_with(&mut fresh, MINGW_OPTIONS & !0x20, out, b"%.1a", &slots);
    assert_eq!((count, exit), (8, ExitReason::Halt));
    assert_eq!(fresh.state.standard_output(), b"0x1.9p+0");

    // The halfway case at the leading digit: 1.5 is exactly 0x1.8p+0, and
    // the kept digit 1 is odd, so both modes round it up.
    let (mut fresh, [_, out, _]) = stdio_guest();
    let slots = [1.5f64.to_bits()];
    for options in [MINGW_OPTIONS, MINGW_OPTIONS & !0x20] {
        let before = fresh.state.standard_output().len();
        let (count, exit) = print_with(&mut fresh, options, out, b"%.0A", &slots);
        assert_eq!((count, exit), (6, ExitReason::Halt), "{options:#x}");
        assert_eq!(&fresh.state.standard_output()[before..], b"0X2P+0");
    }
    // 1.25 is 0x1.4p+0: the dropped digit is below half, so both modes
    // round it down.
    let (mut fresh, [_, out, _]) = stdio_guest();
    let slots = [1.25f64.to_bits()];
    for options in [MINGW_OPTIONS, MINGW_OPTIONS & !0x20] {
        let before = fresh.state.standard_output().len();
        let (count, exit) = print_with(&mut fresh, options, out, b"%.0a", &slots);
        assert_eq!((count, exit), (6, ExitReason::Halt), "{options:#x}");
        assert_eq!(&fresh.state.standard_output()[before..], b"0x1p+0");
    }
}

#[test]
fn closing_a_standard_descriptor_succeeds_and_fails_everything_after() {
    let (mut guest, [input, out, err]) = stdio_guest();
    guest.state.set_standard_input(b"abc");
    let fd = guest.call("_fileno", &[input]) & 0xFFFF_FFFF;
    assert_eq!(fd, 0);
    // Closing descriptor 0 succeeds, as the CRT allows it.
    assert_eq!(guest.call("_close", &[0]) & 0xFFFF_FFFF, 0);
    // Every later operation on it fails with EBADF: the descriptor read,
    // the stream reads and the terminal query. A second close has nothing.
    guest.set_errno(0);
    let buf = TEXT + 0x4000;
    assert_eq!(guest.call("_read", &[0, buf, 4]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    assert_eq!(guest.call("_filbuf", &[input]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    assert_eq!(guest.call("fgetc", &[input]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    assert_eq!(guest.call("_isatty", &[0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.errno(), EBADF);
    assert_eq!(guest.call("_close", &[0]) & 0xFFFF_FFFF, 0xFFFF_FFFF);

    // The same for the output side: closing descriptor 1 succeeds, writes
    // through the descriptor and the stream fail, and nothing is captured.
    assert_eq!(guest.call("_close", &[1]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(buf, b"xy").unwrap();
    guest.set_errno(0);
    assert_eq!(
        guest.call("_write", &[1, buf, 2]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    assert_eq!(
        guest.call("_flsbuf", &[b'x' as u64, out]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), EBADF);
    assert!(guest.state.standard_output().is_empty());
    // stderr is untouched: its descriptor still writes and captures.
    assert_eq!(guest.call("_write", &[2, buf, 2]) & 0xFFFF_FFFF, 2);
    assert_eq!(guest.state.standard_error(), b"xy");
    let _ = err;
}

#[test]
fn the_nul_device_is_open_read_and_written_through_the_crt() {
    let (mut guest, [_, _, _]) = stdio_guest();
    let buf = TEXT + 0x4000;
    // `_open` of the device names succeeds for reading and writing alike,
    // in any directory position and with the extension the name rules strip.
    for name in [b"nul\0".as_slice(), b"NUL.TXT\0", b"dev\\nul\0"] {
        guest.memory.write_bytes(NAME, name).unwrap();
        let fd = guest.call("_open", &[NAME, 2 | 0x8000, 0]) & 0xFFFF_FFFF;
        assert!((3..0x8000).contains(&fd), "{fd:x} for {name:?}");
        // A write discards and reports the count.
        guest.memory.write_bytes(buf, b"noise").unwrap();
        assert_eq!(guest.call("_write", &[fd, buf, 5]) & 0xFFFF_FFFF, 5);
        // A read is end of file: a zero count, no error.
        assert_eq!(guest.call("_read", &[fd, buf, 8]) & 0xFFFF_FFFF, 0);
        assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    }
    // The device is no drive file: `_access` of the plain name misses it,
    // exactly as the drive has no such entry.
    guest.memory.write_bytes(NAME, b"nul\0").unwrap();
    guest.set_errno(0);
    assert_eq!(
        guest.call("_access", &[NAME, 0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    // A component after the device name cannot resolve, and the other DOS
    // device names stay rejected.
    for bad in [b"nul\\child\0".as_slice(), b"con\0", b"com1\0"] {
        guest.memory.write_bytes(NAME, bad).unwrap();
        guest.set_errno(0);
        let fd = guest.call("_open", &[NAME, 2, 0]) & 0xFFFF_FFFF;
        assert_eq!(fd, (-1i32) as u32 as u64, "{bad:?}");
    }
}

#[test]
fn snprintf_writes_inside_the_buffer_and_returns_the_would_be_length() {
    let one_slot = &[42];
    // A fit: the text, its terminator, and the result is the length. The
    // guard byte after the terminator is not touched.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCRATCH, &[0xAA; 0x20]).unwrap();
    let result = buffer_print(&mut guest, STANDARD, SCRATCH + 4, 8, b"<%d>", one_slot);
    assert_eq!(result, 4);
    assert_eq!(
        buffer_bytes(&guest, SCRATCH, 16),
        *b"\xaa\xaa\xaa\xaa<42>\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    );

    // An exact fit: the terminator is the last byte of the buffer.
    let mut guest = buffer_guest();
    assert_eq!(
        buffer_print(&mut guest, STANDARD, SCRATCH, 5, b"<%d>", one_slot),
        4
    );
    assert_eq!(buffer_bytes(&guest, SCRATCH, 5), *b"<42>\x00");

    // One byte short, and more: the terminator is still written, over the
    // last character, and the result is the length the text would have.
    let mut guest = buffer_guest();
    assert_eq!(
        buffer_print(&mut guest, STANDARD, SCRATCH, 4, b"<%d>", one_slot),
        4
    );
    assert_eq!(buffer_bytes(&guest, SCRATCH, 4), *b"<42\x00");
    let mut guest = buffer_guest();
    assert_eq!(
        buffer_print(&mut guest, STANDARD, SCRATCH, 2, b"<%d>", one_slot),
        4
    );
    assert_eq!(buffer_bytes(&guest, SCRATCH, 2), *b"<\x00");

    // A zero count writes nothing, not even the terminator, and still
    // returns the length. A null buffer with a zero count is the size query.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCRATCH, &[0xAA; 4]).unwrap();
    assert_eq!(
        buffer_print(&mut guest, STANDARD, SCRATCH, 0, b"<%d>", one_slot),
        4
    );
    assert_eq!(buffer_bytes(&guest, SCRATCH, 4), [0xAA; 4]);
    let mut guest = buffer_guest();
    assert_eq!(
        buffer_print(&mut guest, STANDARD, 0, 0, b"<%d>", one_slot),
        4
    );

    // sprintf passes the standard bit with a count of SIZE_MAX: no
    // truncation is possible, as the formatter itself is bounded.
    let mut guest = buffer_guest();
    assert_eq!(
        buffer_print(&mut guest, STANDARD, SCRATCH, u64::MAX, b"<%d>", one_slot),
        4
    );
    assert_eq!(buffer_bytes(&guest, SCRATCH, 5), *b"<42>\x00");

    // A null buffer with a nonzero count, or a null format: -1 with EINVAL.
    let mut guest = buffer_guest();
    assert_eq!(
        buffer_print(&mut guest, STANDARD, 0, 8, b"<%d>", one_slot),
        u32::MAX as u64
    );
    assert_eq!(guest.errno(), 22);
    let mut guest = buffer_guest();
    assert_eq!(buffer_print(&mut guest, STANDARD, SCRATCH, 8, b"", &[]), 0);
    assert_eq!(buffer_bytes(&guest, SCRATCH, 1), *b"\x00");
}

#[test]
fn legacy_snprintf_truncates_without_a_terminator_and_returns_minus_one() {
    let one_slot = &[42];
    // Microsoft's _snprintf page: len < count stores len characters, appends
    // the terminator and returns len.
    let mut guest = buffer_guest();
    assert_eq!(
        buffer_print(&mut guest, LEGACY, SCRATCH, 6, b"<%d>", one_slot),
        4
    );
    assert_eq!(buffer_bytes(&guest, SCRATCH, 6), *b"<42>\x00\x00");
    // An exact fit returns the length and leaves the next byte untouched.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCRATCH, &[0xAA; 5]).unwrap();
    assert_eq!(
        buffer_print(&mut guest, LEGACY, SCRATCH, 4, b"<%d>", one_slot),
        4
    );
    assert_eq!(buffer_bytes(&guest, SCRATCH, 5), *b"<42>\xAA");
    // A shorter buffer stores count characters and returns a negative value.
    for count in [3u64, 1] {
        let mut guest = buffer_guest();
        guest.memory.write_bytes(SCRATCH, &[0xAA; 8]).unwrap();
        assert_eq!(
            buffer_print(&mut guest, LEGACY, SCRATCH, count, b"<%d>", one_slot),
            u32::MAX as u64,
            "count {count}"
        );
        let expect: Vec<u8> = b"<42>".iter().copied().take(count as usize).collect();
        assert_eq!(
            buffer_bytes(&guest, SCRATCH, count as usize),
            expect,
            "count {count}"
        );
        assert_eq!(
            buffer_bytes(&guest, SCRATCH, 8)[count as usize],
            0xAA,
            "count {count}"
        );
    }
    // Truncation is no errno error: the guest's errno is left alone.
    let mut guest = buffer_guest();
    guest.set_errno(42);
    assert_eq!(
        buffer_print(&mut guest, LEGACY, SCRATCH, 2, b"<%d>", one_slot),
        u32::MAX as u64
    );
    assert_eq!(guest.errno(), 42);
    // An empty result exactly fits zero bytes, with no memory access.
    let mut guest = buffer_guest();
    let unmapped = 0x1000;
    assert!(guest.memory.read_u8(unmapped).is_err());
    assert_eq!(buffer_print(&mut guest, LEGACY, unmapped, 0, b"", &[]), 0);
    assert_eq!(
        buffer_print(&mut guest, LEGACY, unmapped, 0, b"<%d>", one_slot),
        u32::MAX as u64
    );
    let mut guest = buffer_guest();
    guest.set_errno(42);
    assert_eq!(buffer_print(&mut guest, LEGACY, 0, 0, b"<%d>", one_slot), 4);
    assert_eq!(guest.errno(), 42);
    assert_eq!(
        buffer_print(&mut guest, LEGACY, 0, 4, b"<%d>", one_slot),
        u32::MAX as u64
    );
    assert_eq!(guest.errno(), 22);
    // Both behaviour bits at once contradict each other and stop the guest.
    let mut guest = buffer_guest();
    let (_, exit) = buffer_print_with(
        &mut guest,
        "__stdio_common_vsprintf",
        STANDARD | 0x1,
        SCRATCH,
        8,
        b"x",
        &[],
    );
    assert_eq!(exit, LIMIT);
}

#[test]
fn secure_sprintf_empties_the_buffer_and_reports_the_error() {
    let one_slot = &[42];
    // sprintf_s passes neither behaviour bit. A fit writes the text and its
    // terminator and returns the length; the exact fit included.
    for count in [6u64, 5] {
        let mut guest = buffer_guest();
        let (result, exit) = buffer_print_with(
            &mut guest,
            "__stdio_common_vsprintf_s",
            MINGW_OPTIONS,
            SCRATCH,
            count,
            b"<%d>",
            one_slot,
        );
        assert_eq!((result, exit), (4, ExitReason::Halt), "count {count}");
        assert_eq!(
            buffer_bytes(&guest, SCRATCH, 5),
            *b"<42>\x00",
            "count {count}"
        );
    }
    // A buffer too small for the text and its terminator becomes the empty
    // string, the result is -1 and errno is ERANGE.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCRATCH, b"abcdef\x00").unwrap();
    let (result, exit) = buffer_print_with(
        &mut guest,
        "__stdio_common_vsprintf_s",
        MINGW_OPTIONS,
        SCRATCH,
        4,
        b"<%d>",
        one_slot,
    );
    assert_eq!((result, exit), (u32::MAX as u64, ExitReason::Halt));
    assert_eq!(guest.errno(), 34);
    assert_eq!(buffer_bytes(&guest, SCRATCH, 7), *b"\x00bcdef\x00");
    // A null buffer or format or a zero count: -1 with EINVAL.
    let mut guest = buffer_guest();
    for (buffer, count) in [(0, 8), (SCRATCH, 0)] {
        let (result, exit) = buffer_print_with(
            &mut guest,
            "__stdio_common_vsprintf_s",
            MINGW_OPTIONS,
            buffer,
            count,
            b"<%d>",
            one_slot,
        );
        assert_eq!((result, exit), (u32::MAX as u64, ExitReason::Halt));
        assert_eq!(guest.errno(), 22);
    }
    // An invalid format empties the buffer too.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCRATCH, b"abcdef\x00").unwrap();
    let (result, exit) = buffer_print_with(
        &mut guest,
        "__stdio_common_vsprintf_s",
        MINGW_OPTIONS,
        SCRATCH,
        8,
        b"%n",
        &[SCRATCH],
    );
    assert_eq!((result, exit), (u32::MAX as u64, ExitReason::Halt));
    assert_eq!(guest.errno(), 22);
    assert_eq!(buffer_bytes(&guest, SCRATCH, 7), *b"\x00bcdef\x00");
}

#[test]
fn sprintf_faults_inside_the_buffer_stop_the_guest_and_nothing_leaves_it() {
    // A buffer that is not mapped at all: the write faults and the guest
    // stops instead of losing the text.
    let mut guest = buffer_guest();
    let (_, exit) = buffer_print_with(
        &mut guest,
        "__stdio_common_vsprintf",
        STANDARD,
        0x10,
        8,
        b"<%d>",
        &[42],
    );
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
    // If the payload fits in mapped storage but its terminator does not,
    // the checked write faults before it changes any payload bytes.
    for (service, options) in [
        ("__stdio_common_vsprintf", STANDARD),
        ("__stdio_common_vsprintf", LEGACY),
        ("__stdio_common_vsprintf_s", MINGW_OPTIONS),
    ] {
        let mut guest = buffer_guest();
        let buffer = TEXT + TEXT_LEN as u64 - 4;
        assert!(guest.memory.read_u8(buffer + 4).is_err());
        guest.memory.write_bytes(buffer, &[0xAA; 4]).unwrap();
        let (_, exit) = buffer_print_with(&mut guest, service, options, buffer, 5, b"<%d>", &[42]);
        assert!(
            matches!(exit, ExitReason::MemoryFault(_)),
            "{service}: {exit:?}"
        );
        assert_eq!(buffer_bytes(&guest, buffer, 4), [0xAA; 4]);
    }
    // A truncated write touches neither the byte before the buffer nor the
    // first byte past it.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCRATCH, &[0xAA; 0x20]).unwrap();
    let result = buffer_print(&mut guest, STANDARD, SCRATCH + 1, 3, b"<%d>", &[42]);
    assert_eq!(result, 4);
    let bytes = buffer_bytes(&guest, SCRATCH, 8);
    assert_eq!(bytes[0], 0xAA);
    assert_eq!(&bytes[1..4], b"<4\x00");
    assert_eq!(bytes[4], 0xAA);
    // And the legacy form, which writes up to count characters.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCRATCH, &[0xAA; 0x20]).unwrap();
    let result = buffer_print(&mut guest, LEGACY, SCRATCH + 1, 2, b"<%d>", &[42]);
    assert_eq!(result, u32::MAX as u64);
    let bytes = buffer_bytes(&guest, SCRATCH, 8);
    assert_eq!(bytes[0], 0xAA);
    assert_eq!(&bytes[1..3], b"<4");
    assert_eq!(bytes[3], 0xAA);
}

#[test]
fn puts_writes_the_line_to_the_captured_stdout() {
    let (mut guest, _) = stdio_guest();
    let text = place(&mut guest, STRINGS, b"a line");
    let (cpu, exit) = guest.run("puts", &[text]);
    assert_eq!(
        (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit),
        (0, ExitReason::Halt)
    );
    // The newline is written in text mode like any other output.
    assert_eq!(guest.state.standard_output(), b"a line\r\n");
    // A null string is EOF with EINVAL.
    let (cpu, exit) = guest.run("puts", &[0]);
    assert_eq!(
        (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit),
        (u32::MAX as u64, ExitReason::Halt)
    );
}

#[test]
fn vfprintf_s_and_putchar_write_to_the_streams() {
    let (mut guest, [_, out, _]) = stdio_guest();
    let one = place(&mut guest, STRINGS, b"one");
    let slots = [7, one];
    let format = place(&mut guest, TEXT, b"%d %s\n");
    for (index, slot) in slots.iter().enumerate() {
        guest
            .memory
            .write_u64(VA_LIST + 8 * index as u64, *slot)
            .unwrap();
    }
    guest.memory.write_u64(STACK_TOP + 32, VA_LIST).unwrap();
    let (cpu, exit) = guest.run(
        "__stdio_common_vfprintf_s",
        &[MINGW_OPTIONS, out, format, 0],
    );
    assert_eq!(
        (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit),
        (6, ExitReason::Halt)
    );
    // putchar returns its character and writes it. A line feed is written in
    // text mode, as in any other output.
    for character in [u64::from(b'A'), u64::from(b'\n')] {
        let (cpu, exit) = guest.run("putchar", &[character]);
        assert_eq!(
            (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit),
            (character, ExitReason::Halt)
        );
    }
    assert_eq!(guest.state.standard_output(), b"7 one\r\nA\r\n");
    // A null format is invalid in the secure form too: -1 with EINVAL.
    let (cpu, exit) = guest.run("__stdio_common_vfprintf_s", &[MINGW_OPTIONS, out, 0, 0]);
    assert_eq!(
        (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit),
        (u32::MAX as u64, ExitReason::Halt)
    );
    assert_eq!(guest.errno(), 22);
}

/// What mingw-w64's `sscanf`, `vsscanf`, `scanf` and `fscanf` pass as the
/// options of the scanf entry points: `_CRT_INTERNAL_SCANF_LEGACY_WIDE_SPECIFIERS`
/// (corecrt_stdio_config.h). `sscanf_s` and `scanf_s` pass
/// `_CRT_INTERNAL_SCANF_SECURECRT` alone.
const SCANF_OPTIONS: u64 = 0x2;
const SCANF_SECURE: u64 = 0x1;
/// Where the scanf tests let the guest's conversions assign.
const SCANNED: u64 = TEXT + 0x2000;
const SCANF_EOF: u64 = 0xFFFF_FFFF;

/// Call `__stdio_common_vsscanf` as compiled code does: the input and the
/// format in guest memory, the locale and the `va_list` pointer in the two
/// stack slots above the shadow space. The result's low half and the exit.
fn scan_string_with(
    guest: &mut Guest,
    options: u64,
    input: Option<&[u8]>,
    count: u64,
    format: &[u8],
    slots: &[u64],
) -> (u64, ExitReason) {
    let format = place(guest, TEXT, format);
    let input = input.map_or(0, |input| place(guest, STRINGS, input));
    for (index, slot) in slots.iter().enumerate() {
        guest
            .memory
            .write_u64(VA_LIST + 8 * index as u64, *slot)
            .unwrap();
    }
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    guest.memory.write_u64(STACK_TOP + 40, VA_LIST).unwrap();
    let (cpu, exit) = guest.run("__stdio_common_vsscanf", &[options, input, count, format]);
    (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit)
}

fn scan_string(guest: &mut Guest, input: &[u8], format: &[u8], slots: &[u64]) -> u64 {
    let (result, exit) =
        scan_string_with(guest, SCANF_OPTIONS, Some(input), u64::MAX, format, slots);
    assert_eq!(
        exit,
        ExitReason::Halt,
        "{}",
        String::from_utf8_lossy(format)
    );
    result
}

/// `sscanf` reads the guest string and assigns each converted item through
/// the next pointer of the `va_list` (ISO C 7.21.6.2). Expected values are
/// those the standard's conversions define for the input written here.
#[test]
fn sscanf_converts_a_guest_string_and_assigns_through_the_va_list() {
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCANNED, &[0xAA; 0x80]).unwrap();
    let slots = [
        SCANNED,
        SCANNED + 8,
        SCANNED + 16,
        SCANNED + 32,
        SCANNED + 40,
        SCANNED + 48,
    ];
    let result = scan_string(
        &mut guest,
        b"  -17 0x1F word 2.5 0x1.8p1 tail",
        b"%d %i %s %f %la%n",
        &slots,
    );
    assert_eq!(result, 5);
    let mut bytes = [0u8; 0x40];
    guest.memory.read_bytes(SCANNED, &mut bytes).unwrap();
    assert_eq!(bytes[0..4], (-17i32).to_le_bytes());
    assert_eq!(bytes[4..8], [0xAA; 4], "an int is four bytes");
    assert_eq!(bytes[8..12], 31i32.to_le_bytes());
    assert_eq!(bytes[16..21], *b"word\0");
    assert_eq!(bytes[21], 0xAA);
    assert_eq!(bytes[32..36], 2.5f32.to_bits().to_le_bytes());
    assert_eq!(bytes[40..48], 3.0f64.to_bits().to_le_bytes());
    // %n: the characters read up to it, not counted in the result.
    assert_eq!(bytes[48..52], 27i32.to_le_bytes());

    // The count of `_snscanf` limits the input as its end would, and the
    // terminator ends it before the count.
    let mut guest = buffer_guest();
    let (result, exit) = scan_string_with(
        &mut guest,
        SCANF_OPTIONS,
        Some(b"1234"),
        2,
        b"%d%n",
        &[SCANNED, SCANNED + 4],
    );
    assert_eq!((result, exit), (1, ExitReason::Halt));
    assert_eq!(guest.memory.read_u32(SCANNED).unwrap(), 12);
    assert_eq!(guest.memory.read_u32(SCANNED + 4).unwrap(), 2);
    let (result, _) = scan_string_with(
        &mut guest,
        SCANF_OPTIONS,
        Some(b"56"),
        100,
        b"%d%n",
        &[SCANNED, SCANNED + 4],
    );
    assert_eq!(result, 1);
    assert_eq!(guest.memory.read_u32(SCANNED + 4).unwrap(), 2);

    // Options 0 and the legacy wide-specifier bit change nothing for the
    // narrow functions.
    for options in [0, SCANF_OPTIONS] {
        let mut guest = buffer_guest();
        let (result, exit) = scan_string_with(
            &mut guest,
            options,
            Some(b"x=9"),
            u64::MAX,
            b"x=%u",
            &[SCANNED],
        );
        assert_eq!((result, exit), (1, ExitReason::Halt), "{options:#x}");
        assert_eq!(guest.memory.read_u32(SCANNED).unwrap(), 9);
    }

    // An item is assigned when its conversion completes: the first stays
    // when the second fails to match.
    let mut guest = buffer_guest();
    assert_eq!(
        scan_string(&mut guest, b"8 x", b"%d %d", &[SCANNED, SCANNED + 4]),
        1
    );
    assert_eq!(guest.memory.read_u32(SCANNED).unwrap(), 8);

    // A destination the guest cannot write, and input it cannot read, stop
    // it with a memory fault.
    let mut guest = buffer_guest();
    let (_, exit) = scan_string_with(
        &mut guest,
        SCANF_OPTIONS,
        Some(b"5"),
        u64::MAX,
        b"%d",
        &[0x10],
    );
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
    let format = place(&mut guest, TEXT, b"%d");
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    guest.memory.write_u64(STACK_TOP + 40, VA_LIST).unwrap();
    let (_, exit) = guest.run(
        "__stdio_common_vsscanf",
        &[SCANF_OPTIONS, 0x10, u64::MAX, format],
    );
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
}

/// The result is EOF only for an input failure before the first conversion
/// has completed (ISO C 7.21.6.2p16). A null buffer or format returns -1 and
/// sets `errno` to `EINVAL` (Microsoft Learn, sscanf_s). What neither page
/// defines stops the guest.
#[test]
fn sscanf_returns_eof_only_for_an_input_failure_before_any_conversion() {
    let mut guest = buffer_guest();
    assert_eq!(scan_string(&mut guest, b"", b"%d", &[SCANNED]), SCANF_EOF);
    assert_eq!(
        scan_string(&mut guest, b" \t\n", b"%d", &[SCANNED]),
        SCANF_EOF
    );
    assert_eq!(scan_string(&mut guest, b"x", b"%d", &[SCANNED]), 0);
    assert_eq!(scan_string(&mut guest, b"", b"", &[]), 0);
    assert_eq!(
        scan_string(&mut guest, b"7", b"%d%d", &[SCANNED, SCANNED + 4]),
        1
    );

    // A null buffer, then a null format.
    let mut guest = buffer_guest();
    guest.set_errno(0);
    let (result, exit) =
        scan_string_with(&mut guest, SCANF_OPTIONS, None, u64::MAX, b"%d", &[SCANNED]);
    assert_eq!((result, exit), (SCANF_EOF, ExitReason::Halt));
    assert_eq!(guest.errno(), STDIO_EINVAL);
    let mut guest = buffer_guest();
    guest.set_errno(0);
    let input = place(&mut guest, STRINGS, b"1");
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    guest.memory.write_u64(STACK_TOP + 40, VA_LIST).unwrap();
    let (cpu, exit) = guest.run(
        "__stdio_common_vsscanf",
        &[SCANF_OPTIONS, input, u64::MAX, 0],
    );
    assert_eq!(
        (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit),
        (SCANF_EOF, ExitReason::Halt)
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);

    // Unknown bits and a locale object are not modelled. The msvcrt
    // compatibility bit is accepted, as the merged string adapter does.
    for options in [0x8, 1 << 40] {
        let mut guest = buffer_guest();
        let (_, exit) =
            scan_string_with(&mut guest, options, Some(b"1"), u64::MAX, b"%d", &[SCANNED]);
        assert_eq!(exit, LIMIT, "{options:#x}");
    }
    let mut guest = buffer_guest();
    let format = place(&mut guest, TEXT, b"%d");
    let input = place(&mut guest, STRINGS, b"1");
    guest.memory.write_u64(VA_LIST, SCANNED).unwrap();
    guest.memory.write_u64(STACK_TOP + 32, 0x1234).unwrap();
    guest.memory.write_u64(STACK_TOP + 40, VA_LIST).unwrap();
    assert_eq!(
        guest
            .run(
                "__stdio_common_vsscanf",
                &[SCANF_OPTIONS, input, u64::MAX, format]
            )
            .1,
        LIMIT
    );

    // ISO C leaves a value the destination cannot hold undefined, and
    // narrow scanf would need a locale for wide characters.
    for (input, format) in [
        (&b"2147483648"[..], &b"%d"[..]),
        (b"-1", b"%hu"),
        (b"a", b"%ls"),
        (b"a", b"%C"),
        (b"1", b"%0d"),
    ] {
        let mut guest = buffer_guest();
        let (_, exit) = scan_string_with(
            &mut guest,
            SCANF_OPTIONS,
            Some(input),
            u64::MAX,
            format,
            &[SCANNED],
        );
        assert_eq!(exit, LIMIT, "{}", String::from_utf8_lossy(format));
    }
}

/// `sscanf_s` passes the secure bit alone. Each `c`, `s` and `[` buffer is
/// followed by its size, "of type unsigned, not size_t", that "includes the
/// terminal null" for a string (Microsoft Learn, scanf_s). For a field that
/// does not fit, the page says only that nothing is written; the guest
/// stops rather than continue on a guessed result.
#[test]
fn secure_sscanf_takes_unsigned_buffer_sizes_and_stops_on_overflow() {
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCANNED, &[0xAA; 0x40]).unwrap();
    let slots = [SCANNED, JUNK_HIGH | 4, SCANNED + 8, 2, SCANNED + 16];
    let (result, exit) = scan_string_with(
        &mut guest,
        SCANF_SECURE,
        Some(b"abc xy 12"),
        u64::MAX,
        b"%s %2c %d",
        &slots,
    );
    assert_eq!((result, exit), (3, ExitReason::Halt));
    let mut bytes = [0u8; 20];
    guest.memory.read_bytes(SCANNED, &mut bytes).unwrap();
    assert_eq!(bytes[0..5], *b"abc\0\xAA");
    assert_eq!(bytes[8..11], *b"xy\xAA");
    assert_eq!(bytes[16..20], 12i32.to_le_bytes());

    // Too long for its buffer: the earlier item stays assigned, the buffer
    // is untouched, and the guest stops.
    let mut guest = buffer_guest();
    guest.memory.write_bytes(SCANNED, &[0xAA; 0x40]).unwrap();
    let (_, exit) = scan_string_with(
        &mut guest,
        SCANF_SECURE,
        Some(b"5 toolong"),
        u64::MAX,
        b"%d %s",
        &[SCANNED, SCANNED + 8, 4],
    );
    assert_eq!(exit, LIMIT);
    assert_eq!(guest.memory.read_u32(SCANNED).unwrap(), 5);
    assert_eq!(
        guest.memory.read_u64(SCANNED + 8).unwrap(),
        u64::from_le_bytes([0xAA; 8])
    );
}

/// Call `__stdio_common_vfscanf` as compiled code does: the format in guest
/// memory, no locale, and the `va_list` pointer in the stack slot above the
/// shadow space. The result's low half and the exit.
fn scan_stream_with(
    guest: &mut Guest,
    options: u64,
    stream: u64,
    format: &[u8],
    slots: &[u64],
) -> (u64, ExitReason) {
    let format = place(guest, TEXT, format);
    for (index, slot) in slots.iter().enumerate() {
        guest
            .memory
            .write_u64(VA_LIST + 8 * index as u64, *slot)
            .unwrap();
    }
    guest.memory.write_u64(STACK_TOP + 32, VA_LIST).unwrap();
    let (cpu, exit) = guest.run("__stdio_common_vfscanf", &[options, stream, format, 0]);
    (cpu.get(Register::Rax) & 0xFFFF_FFFF, exit)
}

fn scan_stream(guest: &mut Guest, stream: u64, format: &[u8], slots: &[u64]) -> u64 {
    let (result, exit) = scan_stream_with(guest, SCANF_OPTIONS, stream, format, slots);
    assert_eq!(
        exit,
        ExitReason::Halt,
        "{}",
        String::from_utf8_lossy(format)
    );
    result
}

/// `SCANNED` and the bytes after it.
fn scanned(guest: &Guest, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    guest.memory.read_bytes(SCANNED, &mut bytes).unwrap();
    bytes
}

/// `scanf` on the standard input. A conversion leaves the character after
/// its item unread (ISO C 7.21.6.2), so the next read of any kind starts
/// there; CR LF arrives as one line feed, as for `fgets`. The end-of-file
/// indicator is set when a conversion meets the end, even one that
/// succeeded.
#[test]
fn scanf_reads_stdin_from_where_the_last_read_stopped() {
    let (mut guest, [stdin, _, _]) = stdio_guest();
    guest.memory.write_bytes(SCANNED, &[0xAA; 0x40]).unwrap();
    guest
        .state
        .set_standard_input(b"12 abc\r\n3.5 rest\nlast 7");
    assert_eq!(
        scan_stream(&mut guest, stdin, b"%d%s", &[SCANNED, SCANNED + 8]),
        2
    );
    let bytes = scanned(&guest, 16);
    assert_eq!(bytes[0..4], 12i32.to_le_bytes());
    assert_eq!(bytes[8..12], *b"abc\0");
    assert_eq!(guest.call("getchar", &[]), u64::from(b'\n'), "left unread");
    assert_eq!(scan_stream(&mut guest, stdin, b"%f", &[SCANNED + 16]), 1);
    assert_eq!(
        guest.memory.read_u32(SCANNED + 16).unwrap(),
        3.5f32.to_bits()
    );
    assert_eq!(guest.call("fgets", &[SCRATCH, 16, stdin]), SCRATCH);
    let mut line = [0u8; 7];
    guest.memory.read_bytes(SCRATCH, &mut line).unwrap();
    assert_eq!(line, *b" rest\n\0");
    assert_eq!(guest.call("feof", &[stdin]), 0);
    // A literal that does not match stays unread, and nothing is assigned.
    assert_eq!(scan_stream(&mut guest, stdin, b"x%d", &[SCANNED + 24]), 0);
    assert_eq!(guest.call("getchar", &[]), u64::from(b'l'));
    // The number ends at the end of the input: assigned, and the indicator
    // is set.
    assert_eq!(scan_stream(&mut guest, stdin, b"%*s%d", &[SCANNED + 24]), 1);
    assert_eq!(guest.memory.read_u32(SCANNED + 24).unwrap(), 7);
    assert_ne!(guest.call("feof", &[stdin]), 0);
    assert_eq!(
        scan_stream(&mut guest, stdin, b"%d", &[SCANNED + 28]),
        SCANF_EOF
    );
    assert_eq!(
        guest.memory.read_u32(SCANNED + 28).unwrap(),
        0xAAAA_AAAA,
        "nothing assigned at the end"
    );

    // scanf_s passes SECURECRT: each buffer is followed by its size.
    let (mut guest, [stdin, _, _]) = stdio_guest();
    guest.memory.write_bytes(SCANNED, &[0xAA; 0x10]).unwrap();
    guest.state.set_standard_input(b"hello");
    let (result, exit) = scan_stream_with(&mut guest, SCANF_SECURE, stdin, b"%s", &[SCANNED, 6]);
    assert_eq!((result, exit), (1, ExitReason::Halt));
    assert_eq!(scanned(&guest, 7), b"hello\0\xAA");
}

/// `fscanf` on a file from `fopen`. In text mode CR LF is read as a line
/// feed and CTRL+Z ends the input; in binary mode both are characters
/// (Microsoft Learn, fopen). The position afterwards is the byte offset
/// after the last character consumed, which `_ftelli64` reports.
#[test]
fn fscanf_reads_a_text_file_and_leaves_the_position_after_the_input() {
    let (mut guest, _) = stdio_guest();
    store(&mut guest, "data.txt", b"10 20\r\nname\x1aafter");
    guest.memory.write_bytes(SCANNED, &[0xAA; 0x40]).unwrap();

    let text = opened(&mut guest, "data.txt", "r");
    assert_eq!(
        scan_stream(&mut guest, text, b"%d %d", &[SCANNED, SCANNED + 4]),
        2
    );
    assert_eq!(scanned(&guest, 8)[..], [10, 0, 0, 0, 20, 0, 0, 0]);
    assert_eq!(guest.call("_ftelli64", &[text]), 5, "the CR LF is unread");
    assert_eq!(scan_stream(&mut guest, text, b"%c", &[SCANNED + 8]), 1);
    assert_eq!(scanned(&guest, 9)[8], b'\n', "CR LF is one line feed");
    assert_eq!(guest.call("_ftelli64", &[text]), 7, "two bytes consumed");
    assert_eq!(scan_stream(&mut guest, text, b"%s", &[SCANNED + 16]), 1);
    assert_eq!(scanned(&guest, 21)[16..], *b"name\0");
    assert_eq!(guest.call("_ftelli64", &[text]), 11);
    assert_eq!(
        scan_stream(&mut guest, text, b"%s", &[SCANNED + 24]),
        SCANF_EOF,
        "CTRL+Z is the end of a text stream"
    );
    assert_eq!(guest.call("_ftelli64", &[text]), 11);
    close(&mut guest, text);

    let binary = opened(&mut guest, "data.txt", "rb");
    assert_eq!(
        scan_stream(&mut guest, binary, b"%*d %*d%2c", &[SCANNED + 32]),
        1
    );
    assert_eq!(scanned(&guest, 35)[32..], *b"\r\n\xAA");
    assert_eq!(scan_stream(&mut guest, binary, b"%s", &[SCANNED]), 1);
    assert_eq!(scanned(&guest, 12)[..], *b"name\x1aafter\0\xAA");
    assert_eq!(guest.call("_ftelli64", &[binary]), 17);
    close(&mut guest, binary);
}

/// What `__stdio_common_vfscanf` refuses. A null stream or format returns
/// `EOF` with `errno` `EINVAL` (Microsoft Learn, fscanf). The output streams
/// and a stream opened only for writing cannot be read: `EOF` with `EBADF`,
/// as `fgets` gives here. A pointer that is no stream and a locale object
/// stop the guest. Nothing is assigned in any case.
#[test]
fn fscanf_fails_on_streams_that_cannot_be_read() {
    const EBADF: u32 = 9;
    let (mut guest, [stdin, out, error]) = stdio_guest();
    guest.state.set_standard_input(b"5");
    guest.memory.write_bytes(SCANNED, &[0xAA; 8]).unwrap();
    let written = opened(&mut guest, "out.txt", "w");
    for (stream, format, errno) in [
        (0, Some(b"%d".as_slice()), STDIO_EINVAL),
        (stdin, None, STDIO_EINVAL),
        (out, Some(b"%d".as_slice()), EBADF),
        (error, Some(b"%d".as_slice()), EBADF),
        (written, Some(b"%d".as_slice()), EBADF),
    ] {
        guest.set_errno(0);
        guest.memory.write_u64(STACK_TOP + 32, VA_LIST).unwrap();
        guest.memory.write_u64(VA_LIST, SCANNED).unwrap();
        let format = format.map_or(0, |format| place(&mut guest, TEXT, format));
        let result = guest.call(
            "__stdio_common_vfscanf",
            &[SCANF_OPTIONS, stream, format, 0],
        );
        assert_eq!(result & 0xFFFF_FFFF, SCANF_EOF, "{stream:x}");
        assert_eq!(guest.errno(), errno, "{stream:x}");
    }
    assert_eq!(scanned(&guest, 8), [0xAA; 8]);
    let (_, exit) = scan_stream_with(&mut guest, SCANF_OPTIONS, SCANNED, b"%d", &[SCANNED]);
    assert_eq!(exit, LIMIT, "no stream");
    let format = place(&mut guest, TEXT, b"%d");
    guest.memory.write_u64(STACK_TOP + 32, VA_LIST).unwrap();
    let (_, exit) = guest.run(
        "__stdio_common_vfscanf",
        &[SCANF_OPTIONS, stdin, format, SCANNED],
    );
    assert_eq!(exit, LIMIT, "a locale object");
    assert_eq!(scanned(&guest, 8), [0xAA; 8]);
    assert_eq!(guest.call("getchar", &[]), u64::from(b'5'), "nothing read");
}

/// What `__stdio_common_vfprintf` refuses. A null stream or format returns -1
/// with `errno` `EINVAL` (Microsoft Learn, vfprintf). An invalid format calls
/// the invalid parameter handler on Windows; here it returns the same -1 and
/// writes nothing. What the runtime does not model stops the guest. In every
/// case nothing reaches either stream.
/// `_ftelli64`, `_fseeki64`, `fgetpos` and `fsetpos` on a file stream, and
/// `remove` and `rename` on the drive (#493). Expected values are derived
/// from the Microsoft pages for each function and the bytes written here.
#[test]
fn file_positions_round_trip_and_files_are_removed_and_renamed() {
    const EACCES: u32 = 13;
    const POS: u64 = TEXT + 0x3000;
    const OTHER: u64 = TEXT + 0x1400;
    let (mut guest, [stdin, _, _]) = stdio_guest();
    store(&mut guest, "pos.bin", b"0123456789");
    let file = opened(&mut guest, "pos.bin", "rb");
    let minus_one = u64::MAX;
    // A new stream is at the start; a line read moves it.
    assert_eq!(guest.call("_ftelli64", &[file]), 0);
    assert_eq!(line(&mut guest, file, 5).unwrap(), b"0123");
    assert_eq!(guest.call("_ftelli64", &[file]), 4);
    // fgetpos stores the position; fsetpos goes back to it after a seek.
    assert_eq!(guest.call("fgetpos", &[file, POS]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.memory.read_u64(POS).unwrap(), 4);
    assert_eq!(guest.call("_fseeki64", &[file, 0, 2]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_ftelli64", &[file]), 10);
    assert_eq!(line(&mut guest, file, 8), None, "at the end");
    assert_eq!(guest.call("fsetpos", &[file, POS]) & 0xFFFF_FFFF, 0);
    assert_eq!(line(&mut guest, file, 3).unwrap(), b"45");
    // SEEK_CUR with a negative offset, and SEEK_END backwards.
    assert_eq!(
        guest.call("_fseeki64", &[file, (-3i64) as u64, 1]) & 0xFFFF_FFFF,
        0
    );
    assert_eq!(guest.call("_ftelli64", &[file]), 3);
    assert_eq!(
        guest.call("_fseeki64", &[file, (-1i64) as u64, 2]) & 0xFFFF_FFFF,
        0
    );
    assert_eq!(line(&mut guest, file, 8).unwrap(), b"9");
    // Before the start, an unknown origin and null arguments: -1, EINVAL,
    // and the position is unchanged.
    for args in [[file, (-11i64) as u64, 2], [file, 0, 3], [0, 0, 0]] {
        guest.set_errno(0);
        assert_eq!(
            guest.call("_fseeki64", &args) & 0xFFFF_FFFF,
            minus_one & 0xFFFF_FFFF,
            "{args:x?}"
        );
        assert_eq!(guest.errno(), STDIO_EINVAL, "{args:x?}");
    }
    assert_eq!(guest.call("_ftelli64", &[file]), 10);
    guest.set_errno(0);
    assert_eq!(guest.call("_ftelli64", &[0]), minus_one);
    assert_eq!(guest.errno(), STDIO_EINVAL);
    for symbol in ["fgetpos", "fsetpos"] {
        for args in [[0, POS], [file, 0]] {
            guest.set_errno(0);
            assert_eq!(
                guest.call(symbol, &args) & 0xFFFF_FFFF,
                minus_one & 0xFFFF_FFFF
            );
            assert_eq!(guest.errno(), STDIO_EINVAL, "{symbol} {args:x?}");
        }
    }
    // A negative stored position is refused like a seek before the start.
    guest.memory.write_u64(POS, (-1i64) as u64).unwrap();
    guest.set_errno(0);
    assert_eq!(
        guest.call("fsetpos", &[file, POS]) & 0xFFFF_FFFF,
        minus_one & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    // A seek past the end is allowed, and a write there fills the gap.
    let writer = opened(&mut guest, "gap.bin", "w+b");
    assert_eq!(guest.call("_fseeki64", &[writer, 3, 0]) & 0xFFFF_FFFF, 0);
    write(&mut guest, writer, b"Z");
    assert_eq!(guest.call("_fseeki64", &[writer, 0, 0]) & 0xFFFF_FFFF, 0);
    // The line holds NUL bytes, so it is read from memory, not as a string.
    assert_eq!(guest.call("fgets", &[LINE, 8, writer]), LINE);
    let mut gap = [0xFFu8; 5];
    guest.memory.read_bytes(LINE, &mut gap).unwrap();
    assert_eq!(gap, *b"\0\0\0Z\0");
    close(&mut guest, writer);
    // Positions of a standard stream, an unwritable fpos_t and a pointer that
    // is no stream stop the guest.
    assert_eq!(guest.run("_ftelli64", &[stdin]).1, LIMIT);
    assert_eq!(guest.run("_fseeki64", &[stdin, 0, 0]).1, LIMIT);
    assert_eq!(guest.run("_ftelli64", &[TEXT]).1, LIMIT);
    let exit = guest.run("fgetpos", &[file, 0x9_0000_0000]).1;
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");

    // rename: the old name holds nothing afterwards, the new one the bytes.
    guest.memory.write_bytes(NAME, b"pos.bin\0").unwrap();
    guest.memory.write_bytes(OTHER, b"moved.bin\0").unwrap();
    assert_eq!(guest.call("rename", &[NAME, OTHER]) & 0xFFFF_FFFF, 0);
    // The stream that had the old name open now fails.
    guest.set_errno(0);
    assert_eq!(
        guest.call("_fseeki64", &[file, 0, 2]) & 0xFFFF_FFFF,
        minus_one & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), EBADF);
    close(&mut guest, file);
    let moved = opened(&mut guest, "moved.bin", "rb");
    assert_eq!(line(&mut guest, moved, 16).unwrap(), b"0123456789");
    close(&mut guest, moved);
    // The old name is gone, a target that exists is refused, and so is a
    // target in a directory that does not exist.
    let failures: [(&[u8], &[u8], u32); 4] = [
        (b"pos.bin\0", b"x.bin\0", ENOENT),
        (b"moved.bin\0", b"gap.bin\0", EACCES),
        (b"moved.bin\0", b"nodir\\x.bin\0", EACCES),
        (b"\0", b"x.bin\0", STDIO_EINVAL),
    ];
    for (from, to, errno) in failures {
        guest.memory.write_bytes(NAME, from).unwrap();
        guest.memory.write_bytes(OTHER, to).unwrap();
        guest.set_errno(0);
        assert_eq!(
            guest.call("rename", &[NAME, OTHER]) & 0xFFFF_FFFF,
            minus_one & 0xFFFF_FFFF
        );
        assert_eq!(guest.errno(), errno, "{from:?} -> {to:?}");
    }
    guest.set_errno(0);
    assert_eq!(
        guest.call("rename", &[0, OTHER]) & 0xFFFF_FFFF,
        minus_one & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);

    // remove: once, then ENOENT; a null name is EINVAL.
    guest.memory.write_bytes(NAME, b"moved.bin\0").unwrap();
    assert_eq!(guest.call("remove", &[NAME]) & 0xFFFF_FFFF, 0);
    guest.set_errno(0);
    assert_eq!(
        guest.call("remove", &[NAME]) & 0xFFFF_FFFF,
        minus_one & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), ENOENT);
    assert_eq!(open(&mut guest, "moved.bin", "rb"), 0, "the file is gone");
    guest.set_errno(0);
    assert_eq!(
        guest.call("remove", &[0]) & 0xFFFF_FFFF,
        minus_one & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
}

#[test]
fn stdin_lines_follow_iso_c_at_the_edges() {
    // fgets on the standard input: lines end at a line feed that is kept,
    // CR LF pairs arrive as one line feed, a last line without a newline is
    // a line, and null at end of file.
    let stdin_lines = |input: &[u8]| {
        let (mut guest, [stdin, _, _]) = stdio_guest();
        guest.state.set_standard_input(input);
        let mut lines = Vec::new();
        loop {
            let result = guest.call("fgets", &[SCRATCH, 16, stdin]);
            if result == 0 {
                break;
            }
            let mut bytes = Vec::new();
            for at in 0..16u64 {
                match guest.memory.read_u8(SCRATCH + at).unwrap() {
                    0 => break,
                    byte => bytes.push(byte),
                }
            }
            lines.push(bytes);
        }
        (guest, lines)
    };
    // Two lines, one in CR LF, and a last line without a newline.
    let (_guest, lines) = stdin_lines(b"one\r\ntwo\nthree");
    assert_eq!(
        lines,
        [
            b"one\n".as_slice(),
            b"two\n".as_slice(),
            b"three".as_slice()
        ]
    );
    // The indicator is set only when a read meets the end.
    let (mut guest, [stdin, _, _]) = stdio_guest();
    assert_eq!(guest.call("feof", &[stdin]), 0);
    guest.state.set_standard_input(b"x\n");
    assert_eq!(guest.call("fgets", &[SCRATCH, 16, stdin]), SCRATCH);
    // The read stopped at the line feed, before the end: no indicator yet.
    assert_eq!(guest.call("feof", &[stdin]), 0);
    assert_eq!(guest.call("fgets", &[SCRATCH, 16, stdin]), 0);
    assert_ne!(guest.call("feof", &[stdin]), 0, "a read met the end");
    // An empty input is end of file at once.
    let (mut guest, [stdin, _, _]) = stdio_guest();
    assert_eq!(guest.call("fgets", &[SCRATCH, 16, stdin]), 0);
    assert_ne!(guest.call("feof", &[stdin]), 0);
    // A line longer than the buffer comes in pieces of count - 1 characters,
    // without losing any.
    let mut pieces = Vec::new();
    let (mut guest, [stdin, _, _]) = stdio_guest();
    guest.state.set_standard_input(b"abcdefghij\n");
    loop {
        if guest.call("fgets", &[SCRATCH, 5, stdin]) == 0 {
            break;
        }
        let mut bytes = Vec::new();
        for at in 0..5u64 {
            match guest.memory.read_u8(SCRATCH + at).unwrap() {
                0 => break,
                byte => bytes.push(byte),
            }
        }
        pieces.push(bytes);
    }
    assert_eq!(
        pieces,
        [b"abcd".as_slice(), b"efgh".as_slice(), b"ij\n".as_slice()]
    );
    // A CR alone is not translated away.
    let (_guest, lines) = stdin_lines(b"a\rb\n");
    assert_eq!(lines, [b"a\rb\n".as_slice()]);
    // getchar reads one character after the same replacement, then EOF.
    // feof of an output stream is 0; of a null stream -1 with EINVAL.
    let (mut guest, [stdin, out, _]) = stdio_guest();
    guest.state.set_standard_input(b"\r\nq");
    assert_eq!(guest.call("getchar", &[]), u64::from(b'\n'));
    assert_eq!(guest.call("getchar", &[]), u64::from(b'q'));
    assert_eq!(guest.call("getchar", &[]) & 0xFFFF_FFFF, u32::MAX as u64);
    assert_ne!(guest.call("feof", &[stdin]), 0);
    assert_eq!(guest.call("feof", &[out]), 0);
    assert_eq!(guest.call("feof", &[0]) & 0xFFFF_FFFF, u32::MAX as u64);
    assert_eq!(guest.errno(), 22);
}

/// `tmpnam` and `tmpfile` (#493, last part). The expectations are the
/// Microsoft pages for the two functions: names that hold no file, a
/// binary stream for reading and writing, and deletion when it closes.
#[test]
fn temporary_files_are_uniquely_named_and_deleted_on_close() {
    let (mut guest, _) = stdio_guest();
    store(&mut guest, "tmp1", b"taken");
    // The first generated name skips the file the drive already holds.
    assert_eq!(guest.call("tmpnam", &[LINE]), LINE);
    let mut name = [0u8; 8];
    guest.memory.read_bytes(LINE, &mut name).unwrap();
    assert_eq!(&name[..5], b"tmp2\0", "{name:?}");
    // The next is different again; a null argument reuses one static
    // buffer, as the CRT does.
    assert_eq!(guest.call("tmpnam", &[LINE]), LINE);
    guest.memory.read_bytes(LINE, &mut name).unwrap();
    assert_eq!(&name[..5], b"tmp3\0", "{name:?}");
    let first_static = guest.call("tmpnam", &[0]);
    assert_ne!(first_static, 0);
    assert_eq!(
        guest.call("tmpnam", &[0]),
        first_static,
        "one static buffer"
    );
    guest.memory.read_bytes(first_static, &mut name).unwrap();
    assert_eq!(&name[..5], b"tmp5\0", "{name:?}");

    // `tmpfile` reads and writes like any binary stream...
    let file = guest.call("tmpfile", &[]);
    assert_ne!(file, 0);
    write(&mut guest, file, b"temp-bytes");
    assert_eq!(line(&mut guest, file, 16), None, "at the end after writing");
    close(&mut guest, file);
    // ...and closing it deletes its file: whatever name it used is free
    // for the next temporary file, whose name repeats it.
    let again = guest.call("tmpfile", &[]);
    assert_ne!(again, 0);
    close(&mut guest, again);
    // Unwritable name buffers stop the guest with a fault.
    let exit = guest.run("tmpnam", &[0x9_0000_0000]).1;
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
}

/// The descriptor layer (#493, third part): `_open`, `_read`, `_write`,
/// `_lseek`, `_close`, `_fileno`, `_isatty`, `_access` and `_unlink`. The
/// expectations are the Microsoft pages for each function, the `<fcntl.h>`
/// values from mingw-w64, and the bytes written here.
#[test]
fn descriptors_share_files_with_streams() {
    const EEXIST: u32 = 17;
    let (mut guest, [stdin, out, err]) = stdio_guest();
    let buf = TEXT + 0x4000;
    // `_open` a new file for reading and writing, in binary, and write.
    guest.memory.write_bytes(NAME, b"fd.bin\0").unwrap();
    let fd = guest.call("_open", &[NAME, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    guest.memory.write_bytes(buf, b"abcdef").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf, 6]) & 0xFFFF_FFFF, 6);
    // `_lseek` back and `_read` the bytes; the end is a 0 count, no error.
    assert_eq!(guest.call("_lseek", &[fd, 0, 0]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(buf, &[0xEE; 8]).unwrap();
    assert_eq!(guest.call("_read", &[fd, buf, 8]) & 0xFFFF_FFFF, 6);
    let mut bytes = [0u8; 6];
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"abcdef");
    assert_eq!(guest.call("_read", &[fd, buf, 8]) & 0xFFFF_FFFF, 0);
    // Text mode: a line feed written is CR LF on the drive, and CR LF read
    // is one line feed.
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(NAME, b"fd.txt\0").unwrap();
    let text = guest.call("_open", &[NAME, 2 | 0x100 | 0x200, 0]) & 0xFFFF_FFFF;
    assert!(text >= 3, "{text:x}");
    guest.memory.write_bytes(buf, b"x\ny").unwrap();
    assert_eq!(guest.call("_write", &[text, buf, 3]) & 0xFFFF_FFFF, 3);
    assert_eq!(guest.call("_lseek", &[text, 0, 0]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(buf, &[0xEE; 8]).unwrap();
    assert_eq!(guest.call("_read", &[text, buf, 8]) & 0xFFFF_FFFF, 3);
    let mut bytes = [0u8; 3];
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"x\ny", "CR LF became one line feed");
    // The raw bytes on the drive, through the binary descriptor.
    assert_eq!(guest.call("_close", &[text]) & 0xFFFF_FFFF, 0);
    // A closed descriptor number fails with EBADF until it is recycled.
    assert_eq!(
        guest.call("_lseek", &[77, 0, 0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    guest.set_errno(0);
    assert_eq!(
        guest.call("_read", &[77, buf, 1]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), EBADF);
    guest.memory.write_bytes(NAME, b"fd.txt\0").unwrap();
    let raw = guest.call("_open", &[NAME, 0x8000, 0]) & 0xFFFF_FFFF;
    guest.memory.write_bytes(buf, &[0xEE; 8]).unwrap();
    assert_eq!(guest.call("_read", &[raw, buf, 8]) & 0xFFFF_FFFF, 4);
    let mut bytes = [0u8; 4];
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"x\r\ny", "the drive holds CR LF");
    assert_eq!(guest.call("_close", &[raw]) & 0xFFFF_FFFF, 0);

    // `_fileno` shares the stream's state: a write through the descriptor
    // moves where `fgets` reads.
    store(&mut guest, "shared.bin", b"0123456789");
    let stream = opened(&mut guest, "shared.bin", "r+b");
    let shared = guest.call("_fileno", &[stream]) & 0xFFFF_FFFF;
    assert!(shared >= 3, "{shared:x}");
    assert_eq!(line(&mut guest, stream, 4).unwrap(), b"012");
    // The lowest free descriptor is reused: the fd just closed.
    assert_eq!(shared, raw, "the lowest free descriptor");
    guest.memory.write_bytes(buf, b"ZZ").unwrap();
    assert_eq!(guest.call("_lseek", &[shared, 3, 0]) & 0xFFFF_FFFF, 3);
    assert_eq!(guest.call("_write", &[shared, buf, 2]) & 0xFFFF_FFFF, 2);
    // The stream's position moved with the descriptor's write.
    assert_eq!(line(&mut guest, stream, 8).unwrap(), b"56789");
    // The same stream gives the same descriptor again.
    assert_eq!(guest.call("_fileno", &[stream]) & 0xFFFF_FFFF, shared);
    // `_fileno` of the standard streams, of null and of no stream.
    assert_eq!(guest.call("_fileno", &[stdin]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_fileno", &[out]) & 0xFFFF_FFFF, 1);
    assert_eq!(guest.call("_fileno", &[err]) & 0xFFFF_FFFF, 2);
    guest.set_errno(0);
    assert_eq!(
        guest.call("_fileno", &[0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    assert_eq!(guest.run("_fileno", &[TEXT]).1, LIMIT);
    // `_close` of the shared descriptor closes the underlying file: the
    // stream is dangling afterwards, and using it stops the guest like any
    // pointer that is no stream — in the CRT this is undefined behaviour.
    assert_eq!(guest.call("_close", &[shared]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.run("fclose", &[stream]).1, LIMIT);

    // Descriptor 0 reads what the host supplied; 1 and 2 write to the
    // captured streams; seeking them is EBADF.
    guest.state.set_standard_input(b"pipe\r\n");
    guest.memory.write_bytes(buf, &[0xEE; 8]).unwrap();
    assert_eq!(
        guest.call("_read", &[0, buf, 8]) & 0xFFFF_FFFF,
        5,
        "CR LF became one line feed at load"
    );
    let mut bytes = [0u8; 5];
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"pipe\n");
    guest.memory.write_bytes(buf, b"hi\n").unwrap();
    assert_eq!(guest.call("_write", &[1, buf, 3]) & 0xFFFF_FFFF, 3);
    assert!(guest.state.standard_output().ends_with(b"hi\r\n"));
    assert_eq!(guest.call("_write", &[2, buf, 3]) & 0xFFFF_FFFF, 3);
    assert!(guest.state.standard_error().ends_with(b"hi\r\n"));
    assert_eq!(
        guest.call("_write", &[0, buf, 3]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(
        guest.call("_read", &[1, buf, 3]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(
        guest.call("_lseek", &[0, 0, 0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    // `_isatty`: nothing is a character device; a bad fd is EBADF.
    assert_eq!(guest.call("_isatty", &[0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_isatty", &[1]) & 0xFFFF_FFFF, 0);
    guest.set_errno(0);
    assert_eq!(guest.call("_isatty", &[40]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.errno(), EBADF);

    // Failures: ENOENT without `_O_CREAT`, EEXIST with `_O_EXCL`, EINVAL for
    // access bits 3, EBADF for unknown descriptors, EINVAL before the start.
    guest.memory.write_bytes(NAME, b"nope.bin\0").unwrap();
    guest.set_errno(0);
    assert_eq!(
        guest.call("_open", &[NAME, 0, 0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), ENOENT);
    guest.memory.write_bytes(NAME, b"shared.bin\0").unwrap();
    guest.set_errno(0);
    assert_eq!(
        guest.call("_open", &[NAME, 0x100 | 0x400, 0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), EEXIST);
    guest.set_errno(0);
    assert_eq!(
        guest.call("_open", &[NAME, 3, 0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    assert_eq!(
        guest.call("_close", &[77]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    // Closing standard input succeeds, as the CRT allows it: the slot is
    // dead from then on, which the dedicated close test covers exhaustively.
    assert_eq!(guest.call("_close", &[0]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.run("_open", &[NAME, 0x1_0000, 0]).1,
        LIMIT,
        "wide text stops the guest"
    );
    // `_access`: 0 for a file in any mode, ENOENT when missing, EINVAL for
    // bits other than 0, 2, 4 and 6.
    guest.memory.write_bytes(NAME, b"shared.bin\0").unwrap();
    for mode in [0, 2, 4, 6] {
        assert_eq!(
            guest.call("_access", &[NAME, mode]) & 0xFFFF_FFFF,
            0,
            "{mode}"
        );
    }
    guest.memory.write_bytes(NAME, b"nope.bin\0").unwrap();
    guest.set_errno(0);
    assert_eq!(
        guest.call("_access", &[NAME, 0]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), ENOENT);
    guest.memory.write_bytes(NAME, b"shared.bin\0").unwrap();
    guest.set_errno(0);
    assert_eq!(
        guest.call("_access", &[NAME, 8]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    // `_unlink` is `remove` by another name.
    assert_eq!(guest.call("_unlink", &[NAME]) & 0xFFFF_FFFF, 0);
    guest.set_errno(0);
    assert_eq!(
        guest.call("_unlink", &[NAME]) & 0xFFFF_FFFF,
        (-1i32) as u32 as u64
    );
    assert_eq!(guest.errno(), ENOENT);
}

/// `fopen_s` gives the error number as its result and stores the stream
/// through the pointer, `feof` observes a file stream's indicator, and
/// `clearerr` clears it (#493, second part). The expectations are the
/// Microsoft pages for `fopen_s` and `clearerr`, and ISO C 7.21.7 for the
/// indicator.
#[test]
fn secure_fopen_and_stream_indicators_follow_iso_c() {
    const SLOT: u64 = TEXT + 0x3000;
    let (mut guest, [_, out, _]) = stdio_guest();
    store(&mut guest, "secure.bin", b"xy");
    guest.memory.write_bytes(NAME, b"secure.bin\0").unwrap();
    guest.memory.write_bytes(MODE, b"rb\0").unwrap();
    // A good open: 0, the slot holds the stream, and it reads.
    assert_eq!(guest.call("fopen_s", &[SLOT, NAME, MODE]) & 0xFFFF_FFFF, 0);
    let file = guest.memory.read_u64(SLOT).unwrap();
    assert_ne!(file, 0);
    assert_eq!(line(&mut guest, file, 8).unwrap(), b"xy");
    // Reading past the end sets the indicator; `feof` observes it and
    // `clearerr` clears it.
    assert_eq!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(line(&mut guest, file, 8), None, "at the end");
    assert_ne!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("clearerr", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    // A successful seek clears the indicator too (ISO C 7.21.9.2): read to
    // the end again, seek back to the start, and `feof` is clear.
    assert_eq!(line(&mut guest, file, 8), None, "at the end");
    assert_ne!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_fseeki64", &[file, 0, 0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(line(&mut guest, file, 8).unwrap(), b"xy");
    close(&mut guest, file);
    // `clearerr` of a null stream is a no-op with errno EINVAL; of the
    // output streams it has nothing to clear; of a pointer that is no
    // stream it stops the guest.
    guest.set_errno(0);
    assert_eq!(guest.call("clearerr", &[0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.errno(), STDIO_EINVAL);
    assert_eq!(guest.call("clearerr", &[out]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.run("clearerr", &[TEXT]).1, LIMIT);
    // A missing file: the result is ENOENT, errno matches, the slot is null.
    for (name, mode, errno) in [
        ("missing.bin\0", "rb\0", ENOENT),
        ("secure.bin\0", "zz\0", STDIO_EINVAL),
        ("\0", "rb\0", STDIO_EINVAL),
    ] {
        guest.memory.write_bytes(NAME, name.as_bytes()).unwrap();
        guest.memory.write_bytes(MODE, mode.as_bytes()).unwrap();
        guest.memory.write_u64(SLOT, 0xAA).unwrap();
        guest.set_errno(0);
        assert_eq!(
            guest.call("fopen_s", &[SLOT, NAME, MODE]) & 0xFFFF_FFFF,
            u64::from(errno) & 0xFFFF_FFFF,
            "{name:?} {mode:?}"
        );
        assert_eq!(guest.errno(), errno, "{name:?} {mode:?}");
        assert_eq!(guest.memory.read_u64(SLOT).unwrap(), 0, "{name:?} {mode:?}");
    }
    // Null arguments are EINVAL, with the slot nulled when there is one.
    guest.set_errno(0);
    assert_eq!(
        guest.call("fopen_s", &[SLOT, 0, MODE]) & 0xFFFF_FFFF,
        u64::from(STDIO_EINVAL) & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    guest.set_errno(0);
    assert_eq!(
        guest.call("fopen_s", &[SLOT, NAME, 0]) & 0xFFFF_FFFF,
        u64::from(STDIO_EINVAL) & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    guest.set_errno(0);
    assert_eq!(
        guest.call("fopen_s", &[0, NAME, MODE]) & 0xFFFF_FFFF,
        u64::from(STDIO_EINVAL) & 0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    // A directory is EACCES through the same passthrough; the runtime
    // registry has no way to make one here, so the fixture does not cover
    // it either — it is the same `errno` forwarding ENOENT exercises.
    // An unwritable output pointer stops the guest with a fault.
    let exit = guest.run("fopen_s", &[0x9_0000_0000, NAME, MODE]).1;
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
}

/// The C time services of package 5 of #459. The expectations are the
/// civil calendar itself: 2001-09-09 01:46:40 UTC is the second
/// 1_000_000_000, and 1970-01-01 was a Thursday.
#[test]
fn c_time_breaks_down_and_composes_the_injected_clock() {
    let (mut guest, _) = stdio_guest();
    // 1_000_000_000 seconds after the epoch.
    guest.memory.write_u64(LINE, 1_000_000_000).unwrap();
    let tm = guest.call("_gmtime64", &[LINE]);
    assert_ne!(tm, 0);
    fn field(guest: &Guest, tm: u64, index: u64) -> i32 {
        guest.memory.read_u32(tm + 4 * index).unwrap() as i32
    }
    macro_rules! field {
        ($index:expr) => {
            field(&guest, tm, $index)
        };
    }
    assert_eq!(field!(0), 40, "tm_sec");
    assert_eq!(field!(1), 46, "tm_min");
    assert_eq!(field!(2), 1, "tm_hour");
    assert_eq!(field!(3), 9, "tm_mday");
    assert_eq!(field!(4), 8, "tm_mon: September is 8");
    assert_eq!(field!(5), 101, "tm_year: 2001 is 101");
    assert_eq!(field!(6), 0, "tm_wday: a Sunday");
    assert_eq!(field!(7), 251, "tm_yday");
    assert_eq!(field!(8), 0, "tm_isdst: the clock is UTC");
    // The same address answers `_localtime64`: the machine's local time is
    // UTC, and one static buffer serves both, as the CRT keeps one.
    assert_eq!(guest.call("_localtime64", &[LINE]), tm);
    // The epoch itself: Thursday, January 1, 1970.
    guest.memory.write_u64(LINE, 0).unwrap();
    assert_eq!(guest.call("_gmtime64", &[LINE]), tm);
    assert_eq!(field!(6), 4, "the epoch was a Thursday");
    // Negative and post-3000 times are EINVAL with a null return.
    guest.memory.write_u64(LINE, u64::MAX).unwrap();
    assert_eq!(guest.call("_gmtime64", &[LINE]), 0);
    assert_eq!(guest.errno(), 22);
    guest.memory.write_u64(LINE, 32_535_216_000).unwrap();
    assert_eq!(guest.call("_gmtime64", &[LINE]), 0);
    assert_eq!(guest.errno(), 22);

    // `mktime` composes what `gmtime` breaks down, normalizes the fields in
    // place, and fills the weekday.
    guest.memory.write_u64(LINE, 1_000_000_000).unwrap();
    guest.call("_gmtime64", &[LINE]);
    // Copy the static tm into scratch memory mktime can normalize.
    let mut fields = [0u8; 36];
    guest.memory.read_bytes(tm, &mut fields).unwrap();
    guest.memory.write_bytes(LINE + 0x100, &fields).unwrap();
    let made = guest.call("_mktime64", &[LINE + 0x100]);
    assert_eq!(made, 1_000_000_000);
    // A month of 13 normalizes into the next year.
    guest.memory.write_u32(LINE + 0x100 + 16, 13).unwrap();
    guest.memory.write_u32(LINE + 0x100 + 20, 100).unwrap();
    let made = guest.call("_mktime64", &[LINE + 0x100]);
    // February of 2001, day 9, same time of day.
    guest.memory.write_u64(LINE, made).unwrap();
    guest.call("_gmtime64", &[LINE]);
    assert_eq!(field!(4), 1, "month 13 of 2000 is February 2001");
    assert_eq!(field!(5), 101);
    // 1969 is outside the CRT's range.
    guest.memory.write_u32(LINE + 0x100 + 20, 69).unwrap();
    assert_eq!(guest.call("_mktime64", &[LINE + 0x100]), u64::MAX);
    assert_eq!(guest.errno(), 22);
}

/// The string forms, `clock` and `difftime`, and the identity
/// `FileTimeToLocalFileTime`.
#[test]
fn c_time_formats_and_measures_as_the_crt_does() {
    let (mut guest, _) = stdio_guest();
    guest.memory.write_u64(LINE, 1_000_000_000).unwrap();
    let tm = guest.call("_gmtime64", &[LINE]);
    // `asctime` is the fixed 24-character shape the CRT writes.
    let text = guest.call("asctime", &[tm]);
    assert_ne!(text, 0);
    let mut bytes = [0u8; 26];
    guest.memory.read_bytes(text, &mut bytes).unwrap();
    assert_eq!(&bytes, b"Sun Sep  9 01:46:40 2001\n\0");
    // `_ctime64` of the same second is the same string, in the same buffer.
    assert_eq!(guest.call("_ctime64", &[LINE]), text);
    // Two-digit days pad with a zero, single-digit with a space: check the
    // tenth of September too.
    guest
        .memory
        .write_u64(LINE, 1_000_000_000 + 86_400)
        .unwrap();
    assert_eq!(guest.call("_ctime64", &[LINE]), text);
    guest.memory.read_bytes(text, &mut bytes).unwrap();
    assert_eq!(&bytes[8..10], b"10", "day 10");
    assert_eq!(&bytes[..19], b"Mon Sep 10 01:46:40");
    // `asctime_s` validates the buffer size and empties it on failure.
    let rc = guest.call("asctime_s", &[LINE + 0x200, 26, tm]);
    assert_eq!(rc, 0);
    guest.memory.read_bytes(LINE + 0x200, &mut bytes).unwrap();
    assert_eq!(&bytes[..5], b"Mon S");
    assert_eq!(guest.call("asctime_s", &[LINE + 0x200, 25, tm]), 22);
    assert_eq!(guest.memory.read_u8(LINE + 0x200).unwrap(), 0, "emptied");
    assert_eq!(guest.errno(), 22);
    // `strftime` for the C locale.
    let tm = guest.call("_gmtime64", &[LINE]);
    let format = LINE + 0x400;
    guest
        .memory
        .write_bytes(
            format,
            b"%Y-%m-%d %H:%M:%S %a %A %b %B %j %U %W %w %p %I %x %X %y %% %z %Z\0",
        )
        .unwrap();
    let len = guest.call("strftime", &[LINE + 0x600, 200, format, tm]);
    assert_ne!(len, 0);
    let mut out = vec![0u8; len as usize];
    guest.memory.read_bytes(LINE + 0x600, &mut out).unwrap();
    // 2001-09-10 01:46:40, Monday, the 253rd day, AM.
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "2001-09-10 01:46:40 Mon Monday Sep September 253 36 37 1 AM 01 09/10/01 01:46:40 01 % +0000 UTC"
    );
    // An unknown conversion copies verbatim, and too small a buffer is 0.
    guest.memory.write_bytes(format, b"%Q\0").unwrap();
    assert_eq!(guest.call("strftime", &[LINE + 0x600, 200, format, tm]), 2);
    assert_eq!(guest.call("strftime", &[LINE + 0x600, 2, format, tm]), 0);
    // `clock` reads the injected clock's performance count in milliseconds.
    assert_eq!(guest.call("clock", &[]), 0);
    // `difftime` subtracts. A double returns in XMM0, not the integer
    // register, so the call goes through the floating-point path.
    let diff = math_call(
        &mut guest,
        "_difftime64",
        &[],
        &[2_000_000_000, 1_500_000_000],
    );
    assert_eq!(
        f64::from_bits(diff as u64),
        500_000_000.0,
        "the difference is exact in a double"
    );
    // `FileTimeToLocalFileTime` copies: the machine's local time is UTC.
    guest.memory.write_u64(LINE, 123_456_789).unwrap();
    assert_eq!(guest.call("FileTimeToLocalFileTime", &[LINE, LINE + 8]), 1);
    assert_eq!(guest.memory.read_u64(LINE + 8).unwrap(), 123_456_789);
}

/// The wide conversions and classification of package 6 of #459. The
/// expectations are the C locale: every byte is the wide character of the
/// same value, a wide character above 255 has no multibyte form, and the
/// classes are the ASCII ones.
#[test]
fn wide_characters_convert_in_the_c_locale() {
    let (mut guest, _) = stdio_guest();
    // `mbstowcs` zero-extends every byte.
    guest.memory.write_bytes(LINE, b"abc\0").unwrap();
    assert_eq!(guest.call("mbstowcs", &[LINE + 0x100, LINE, 8]), 3);
    assert_eq!(
        guest.memory.read_u16(LINE + 0x100).unwrap(),
        u16::from(b'a')
    );
    assert_eq!(
        guest.memory.read_u16(LINE + 0x104).unwrap(),
        u16::from(b'c')
    );
    assert_eq!(
        guest.memory.read_u16(LINE + 0x106).unwrap(),
        0,
        "terminated"
    );
    // Fewer wide slots than bytes: no terminator, the count is the slots.
    assert_eq!(guest.call("mbstowcs", &[LINE + 0x100, LINE, 2]), 2);
    // A null destination is the length query.
    assert_eq!(guest.call("mbstowcs", &[0, LINE, 0]), 3);
    // `wcstombs` is the inverse, failing for a wide character above 255.
    assert_eq!(guest.call("wcstombs", &[LINE + 0x200, LINE + 0x100, 8]), 3);
    assert_eq!(
        &{
            let mut b = [0u8; 3];
            guest.memory.read_bytes(LINE + 0x200, &mut b).unwrap();
            b
        },
        b"abc"
    );
    guest.memory.write_u16(LINE + 0x100, 0x100).unwrap();
    assert_eq!(
        guest.call("wcstombs", &[LINE + 0x200, LINE + 0x100, 8]),
        u64::MAX
    );
    assert_eq!(guest.errno(), 42, "EILSEQ");
    // The single-character forms.
    guest.memory.write_bytes(LINE, b"z\0").unwrap();
    assert_eq!(guest.call("mbtowc", &[LINE + 0x100, LINE, 1]), 1);
    assert_eq!(
        guest.memory.read_u16(LINE + 0x100).unwrap(),
        u16::from(b'z')
    );
    assert_eq!(
        guest.call("mbtowc", &[LINE + 0x100, LINE, 0]),
        0xFFFF_FFFF,
        "-1 as an int"
    );
    assert_eq!(guest.call("wctomb", &[LINE + 0x300, u64::from(b'q')]), 1);
    assert_eq!(guest.memory.read_u8(LINE + 0x300).unwrap(), b'q');
    assert_eq!(
        guest.call("wctomb", &[LINE + 0x300, 0x100]),
        0xFFFF_FFFF,
        "-1 as an int"
    );
    assert_eq!(guest.call("mblen", &[LINE, 1]), 1);
    // The restartable forms advance their source pointer.
    guest.memory.write_bytes(LINE, b"xy\0").unwrap();
    guest.memory.write_u64(LINE + 0x400, LINE).unwrap();
    assert_eq!(
        guest.call("mbsrtowcs", &[LINE + 0x100, LINE + 0x400, 1, 0]),
        1
    );
    assert_eq!(
        guest.memory.read_u64(LINE + 0x400).unwrap(),
        LINE + 1,
        "advanced"
    );
    assert_eq!(
        guest.call("mbsrtowcs", &[LINE + 0x100, LINE + 0x400, 4, 0]),
        1
    );
    assert_eq!(
        guest.memory.read_u64(LINE + 0x400).unwrap(),
        0,
        "consumed the null"
    );

    // The classification is ASCII's, through `iswctype`'s bits.
    assert_eq!(
        guest.call("iswctype", &[u64::from(b'a'), 0x103]),
        1,
        "_ALPHA"
    );
    assert_eq!(
        guest.call("iswctype", &[u64::from(b'a'), 0x4]),
        0,
        "not a digit"
    );
    assert_eq!(guest.call("iswctype", &[u64::from(b'5'), 0x4]), 1, "_DIGIT");
    assert_eq!(
        guest.call("iswctype", &[0xE9, 0x103]),
        0,
        "no class above ASCII"
    );
    assert_eq!(
        guest.call("iswctype", &[u64::from(b' '), 0x40]),
        1,
        "_BLANK"
    );
    // The direct forms answer the same.
    assert_eq!(guest.call("iswalpha", &[u64::from(b'a')]), 1);
    assert_eq!(guest.call("iswalpha", &[u64::from(b'5')]), 0);
    assert_eq!(guest.call("iswspace", &[u64::from(b' ')]), 1);
    assert_eq!(guest.call("iswupper", &[u64::from(b'A')]), 1);
    assert_eq!(guest.call("towupper", &[u64::from(b'a')]), u64::from(b'A'));
    assert_eq!(guest.call("towlower", &[u64::from(b'A')]), u64::from(b'a'));
    assert_eq!(guest.call("towupper", &[u64::from(b'5')]), u64::from(b'5'));

    // `wcsncat` appends at most count units.
    let wide = |units: &[u16]| -> Vec<u8> { units.iter().flat_map(|u| u.to_le_bytes()).collect() };
    let mut start = wide(&[u16::from(b'a'), 0]);
    start.resize(16, 0);
    guest.memory.write_bytes(LINE + 0x500, &start).unwrap();
    let end = wide(&[u16::from(b'b'), u16::from(b'c'), u16::from(b'd'), 0]);
    guest.memory.write_bytes(LINE + 0x600, &end).unwrap();
    assert_eq!(
        guest.call("wcsncat", &[LINE + 0x500, LINE + 0x600, 2]),
        LINE + 0x500
    );
    assert_eq!(
        guest.memory.read_u16(LINE + 0x502).unwrap(),
        u16::from(b'b')
    );
    assert_eq!(
        guest.memory.read_u16(LINE + 0x504).unwrap(),
        u16::from(b'c')
    );
    assert_eq!(
        guest.memory.read_u16(LINE + 0x506).unwrap(),
        0,
        "terminated after count"
    );

    // `_wcsdup` copies.
    let dup = guest.call("_wcsdup", &[LINE + 0x600]);
    assert_ne!(dup, 0);
    assert_eq!(guest.memory.read_u16(dup).unwrap(), u16::from(b'b'));
    assert_eq!(guest.memory.read_u16(dup + 6).unwrap(), 0);
}

#[test]
fn formatted_output_refuses_what_it_cannot_print_correctly() {
    let (mut guest, [input, out, _]) = stdio_guest();
    let quiet = |guest: &Guest| {
        assert!(guest.state.standard_output().is_empty());
        assert!(guest.state.standard_error().is_empty());
    };

    // Null stream, null format.
    guest.set_errno(0);
    let format = place(&mut guest, TEXT, b"text");
    guest.memory.write_u64(STACK_TOP + 32, VA_LIST).unwrap();
    for args in [[MINGW_OPTIONS, 0, format, 0], [MINGW_OPTIONS, out, 0, 0]] {
        let result = guest.call("__stdio_common_vfprintf", &args);
        assert_eq!(result & 0xFFFF_FFFF, STDIO_MINUS_ONE, "{args:x?}");
        assert_eq!(guest.errno(), STDIO_EINVAL, "{args:x?}");
        guest.set_errno(0);
    }
    quiet(&guest);

    // %n is disabled by default, and a character with no meaning as a type
    // is invalid. The text before it is not written.
    for format in [&b"count%n"[..], b"before %d then %y", b"%", b"100%"] {
        let (count, exit) = print_with(&mut guest, MINGW_OPTIONS, out, format, &[1, 2]);
        assert_eq!((count, exit), (STDIO_MINUS_ONE, ExitReason::Halt));
        assert_eq!(guest.errno(), STDIO_EINVAL);
        guest.set_errno(0);
    }
    quiet(&guest);

    // Wide characters and strings are valid and not modelled, and nothing
    // before them is written.
    for format in [&b"%ls"[..], b"ok %d then %S", b"%f then %lc", b"%S", b"%lc"] {
        let (_, exit) = print_with(&mut guest, MINGW_OPTIONS, out, format, &[1, 2]);
        assert_eq!(exit, LIMIT, "{}", String::from_utf8_lossy(format));
    }
    // Option bits that change how the format is read or that belong to the
    // buffer functions, and unknown bits.
    for options in [0x01, 0x02, 0x08, 0x40, 0x25, 1 << 32, u64::MAX] {
        let (_, exit) = print_with(&mut guest, options, out, b"x", &[]);
        assert_eq!(exit, LIMIT, "{options:#x}");
    }
    // A locale object.
    let format = place(&mut guest, TEXT, b"x");
    let args = [MINGW_OPTIONS, out, format, STRINGS];
    assert_eq!(guest.run("__stdio_common_vfprintf", &args).1, LIMIT);
    // stdin, and pointers that are no stream: beside a FILE object, inside
    // one, and elsewhere.
    for stream in [input, out + 1, out + 24, out - 16, TEXT, 8] {
        let (_, exit) = print_with(&mut guest, MINGW_OPTIONS, stream, b"x", &[]);
        assert_eq!(exit, LIMIT, "{stream:#x}");
    }
    // Unreadable memory is a fault at the address that could not be read.
    let unmapped = 0x9_0000_0000;
    let (_, exit) = print_with(&mut guest, MINGW_OPTIONS, out, b"%s", &[unmapped]);
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
    guest.memory.write_u64(STACK_TOP + 32, unmapped).unwrap();
    for args in [
        [MINGW_OPTIONS, out, format, 0],
        [MINGW_OPTIONS, out, unmapped, 0],
    ] {
        let format_reads_arguments = place(&mut guest, TEXT, b"%d");
        assert_eq!(format_reads_arguments, format);
        let exit = guest.run("__stdio_common_vfprintf", &args).1;
        assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
    }
    quiet(&guest);
    // None of the stops set errno.
    assert_eq!(guest.errno(), 0);

    // A guest that never asked for its streams has none to write to.
    let mut fresh = Guest::new();
    fresh
        .memory
        .map_region(TEXT, TEXT_LEN, MemoryPermissions::READ_WRITE)
        .unwrap();
    let (_, exit) = print_with(&mut fresh, MINGW_OPTIONS, out, b"x", &[]);
    assert_eq!(exit, LIMIT);
}

/// `fwrite` "returns the number of full items the function writes" and, for a
/// null buffer or stream, sets `errno` to `EINVAL` and returns 0. `fputs`
/// returns "a nonnegative value if it's successful", copies no terminating
/// null, and returns `EOF` with `EINVAL` for a null pointer (Microsoft Learn).
#[test]
fn fwrite_and_fputs_write_to_the_captured_standard_streams() {
    let (mut guest, [input, out, err]) = stdio_guest();
    let text = place(&mut guest, TEXT, b"cleanup ran\nxyz");
    // Twelve items of one byte, then three items of four bytes to stderr.
    assert_eq!(guest.call("fwrite", &[text, 1, 12, out]), 12);
    assert_eq!(guest.call("fwrite", &[text, 4, 3, err]), 3);
    assert_eq!(guest.state.standard_output(), b"cleanup ran\r\n");
    assert_eq!(guest.state.standard_error(), b"cleanup ran\r\n");
    // No items or no size writes nothing and returns 0.
    for (size, count) in [(0, 5), (5, 0), (0, 0)] {
        assert_eq!(guest.call("fwrite", &[text, size, count, out]), 0);
    }
    assert_eq!(guest.state.standard_output().len(), 13);
    // A byte of zero is data to fwrite.
    assert_eq!(guest.call("fwrite", &[text + 14, 1, 2, out]), 2);
    assert_eq!(guest.state.standard_output()[13..], [b'z', 0]);

    guest.set_errno(0);
    for args in [[0, 1, 4, out], [text, 1, 4, 0]] {
        assert_eq!(guest.call("fwrite", &args), 0, "{args:x?}");
        assert_eq!(guest.errno(), STDIO_EINVAL, "{args:x?}");
        guest.set_errno(0);
    }
    // stdin, another pointer, more than this runtime transfers at once, a
    // product that overflows, and unreadable memory.
    for args in [
        [text, 1, 4, input],
        [text, 1, 4, TEXT],
        [text, 1, (1 << 20) + 1, out],
        [text, 1 << 33, 1 << 33, out],
    ] {
        assert_eq!(guest.run("fwrite", &args).1, LIMIT, "{args:x?}");
    }
    let exit = guest.run("fwrite", &[0x9_0000_0000, 1, 4, out]).1;
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
    assert_eq!(guest.state.standard_output().len(), 15);
    assert_eq!(guest.errno(), 0);

    // fputs writes up to the terminator and not the terminator itself.
    let (mut guest, [input, out, err]) = stdio_guest();
    let text = place(&mut guest, TEXT, b"cleanup ran\n");
    assert_eq!(guest.call("fputs", &[text, out]) & 0xFFFF_FFFF, 0);
    let empty = place(&mut guest, STRINGS, b"");
    assert_eq!(guest.call("fputs", &[empty, out]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("fputs", &[text + 8, err]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.state.standard_output(), b"cleanup ran\r\n");
    assert_eq!(guest.state.standard_error(), b"ran\r\n");
    guest.set_errno(0);
    for args in [[0, out], [text, 0]] {
        assert_eq!(guest.call("fputs", &args) & 0xFFFF_FFFF, STDIO_MINUS_ONE);
        assert_eq!(guest.errno(), STDIO_EINVAL, "{args:x?}");
        guest.set_errno(0);
    }
    for args in [[text, input], [text, TEXT]] {
        assert_eq!(guest.run("fputs", &args).1, LIMIT, "{args:x?}");
    }
    let exit = guest.run("fputs", &[0x9_0000_0000, out]).1;
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
    assert_eq!(guest.state.standard_output().len(), 13);
}

/// `fflush` "returns 0 if the buffer was successfully flushed", and a null
/// stream means every open stream. `setvbuf` "returns 0 if successful"; for a
/// null stream or a mode or size that is not valid it returns -1 and sets
/// `errno` to `EINVAL`. The modes are `_IOFBF` (0), `_IOLBF` (0x40) and
/// `_IONBF` (4), and the size must be from 2 to `INT_MAX` unless the mode is
/// `_IONBF` (Microsoft Learn; values from stdio.h).
#[test]
fn fflush_and_setvbuf_return_their_documented_results() {
    let (mut guest, [input, out, err]) = stdio_guest();
    for stream in [0, input, out, err] {
        assert_eq!(
            guest.call("fflush", &[stream]) & 0xFFFF_FFFF,
            0,
            "{stream:#x}"
        );
    }
    for stream in [TEXT, out + 4, 16] {
        assert_eq!(guest.run("fflush", &[stream]).1, LIMIT, "{stream:#x}");
    }

    const INT_MAX: u64 = 0x7FFF_FFFF;
    let junk = 0xFFFF_FFFF_0000_0000;
    guest.set_errno(0);
    for (args, result) in [
        // The call the mingw-w64 startup makes: stderr, unbuffered.
        ([err, 0, 4, 0], 0),
        // No buffer is used, regardless of buffer or size.
        ([out, TEXT, 4, 1], 0),
        ([out, 0, 4, u64::MAX], 0),
        ([out, 0, 0, 4096], 0),
        ([out, TEXT, 0, 2], 0),
        ([input, 0, 0x40, INT_MAX], 0),
        // The mode is an int.
        ([out, 0, junk | 0x40, 2], 0),
        // A size outside 2 to INT_MAX, and modes that are not one of the three.
        ([out, 0, 0, 1], STDIO_MINUS_ONE),
        ([out, 0, 0, 0], STDIO_MINUS_ONE),
        ([out, 0, 0x40, INT_MAX + 1], STDIO_MINUS_ONE),
        ([out, 0, 1, 4096], STDIO_MINUS_ONE),
        ([out, 0, 0x44, 4096], STDIO_MINUS_ONE),
        ([out, 0, 0xFFFF_FFFF, 4096], STDIO_MINUS_ONE),
        ([0, 0, 4, 0], STDIO_MINUS_ONE),
    ] {
        assert_eq!(
            guest.call("setvbuf", &args) & 0xFFFF_FFFF,
            result,
            "{args:x?}"
        );
        let errno = if result == 0 { 0 } else { STDIO_EINVAL };
        assert_eq!(guest.errno(), errno, "{args:x?}");
        guest.set_errno(0);
    }
    assert_eq!(guest.run("setvbuf", &[TEXT, 0, 4, 0]).1, LIMIT);

    // `setbuf` is the legacy reduction: the buffer pointer only chooses
    // between full and no buffering, and both are accepted for a real
    // stream because output is never held back either way.
    guest.set_errno(0);
    for stream in [input, out, err] {
        guest.call("setbuf", &[stream, TEXT]);
        assert_eq!(guest.errno(), 0, "{stream:#x}");
        guest.call("setbuf", &[stream, 0]);
        assert_eq!(guest.errno(), 0, "{stream:#x}");
    }
    // A null stream is errno EINVAL through the void return; a pointer
    // that is no stream stops the guest, as it does for `setvbuf`.
    guest.call("setbuf", &[0, TEXT]);
    assert_eq!(guest.errno(), STDIO_EINVAL);
    guest.set_errno(0);
    assert_eq!(guest.run("setbuf", &[TEXT, 0]).1, LIMIT);

    // Neither function holds output back or lets any through.
    assert!(guest.state.standard_output().is_empty());
    assert_eq!(print(&mut guest, out, b"now", &[]), 3);
    assert_eq!(guest.state.standard_output(), b"now");
}

/// Each captured stream keeps at most `MAX_CAPTURED_OUTPUT` bytes, counted
/// after the text-mode replacement, and a write that would pass it stops the
/// guest and adds nothing.
#[test]
fn captured_output_is_bounded() {
    let (mut guest, [_, out, err]) = stdio_guest();
    const CHUNK: u64 = 1 << 20;
    assert_eq!(MAX_CAPTURED_OUTPUT as u64, 16 * CHUNK);
    guest
        .memory
        .write_bytes(TEXT, &vec![b'x'; CHUNK as usize])
        .unwrap();
    for _ in 0..15 {
        assert_eq!(guest.call("fwrite", &[TEXT, 1, CHUNK, out]), CHUNK);
    }
    assert_eq!(guest.call("fwrite", &[TEXT, 1, CHUNK - 2, out]), CHUNK - 2);
    // Two bytes of room: a line feed takes both.
    guest.memory.write_bytes(TEXT, b"\n\nxx").unwrap();
    assert_eq!(guest.run("fwrite", &[TEXT, 1, 2, out]).1, LIMIT);
    assert_eq!(guest.run("fwrite", &[TEXT + 1, 1, 2, out]).1, LIMIT);
    assert_eq!(guest.state.standard_output().len(), MAX_CAPTURED_OUTPUT - 2);
    assert_eq!(guest.call("fwrite", &[TEXT, 1, 1, out]), 1);
    assert_eq!(guest.state.standard_output().len(), MAX_CAPTURED_OUTPUT);
    assert_eq!(guest.run("fwrite", &[TEXT + 2, 1, 1, out]).1, LIMIT);
    assert_eq!(guest.state.standard_output().len(), MAX_CAPTURED_OUTPUT);
    // The other stream has its own room.
    assert_eq!(guest.call("fwrite", &[TEXT + 2, 1, 2, err]), 2);
    assert_eq!(guest.state.standard_error(), b"xx");
}

const ENOENT: u32 = 2;
const EEXIST: u32 = 17;
const EBADF: u32 = 9;
const EMFILE: u32 = 24;
const ENOSPC: u32 = 28;
/// Where the file tests put a name, a mode and the buffer `fgets` fills.
const NAME: u64 = TEXT + 0x1000;
const MODE: u64 = TEXT + 0x1200;
const LINE: u64 = TEXT + 0x2000;
/// What the buffer holds before `fgets` is called.
const UNTOUCHED: u8 = 0xEE;

/// `fopen(name, mode)`, with both strings placed in guest memory.
fn open(guest: &mut Guest, name: &str, mode: &str) -> u64 {
    let name = place(guest, NAME, name.as_bytes());
    let mode = place(guest, MODE, mode.as_bytes());
    guest.call("fopen", &[name, mode])
}

/// `fopen` that must succeed.
fn opened(guest: &mut Guest, name: &str, mode: &str) -> u64 {
    let stream = open(guest, name, mode);
    assert_ne!(stream, 0, "fopen({name:?}, {mode:?})");
    stream
}

fn close(guest: &mut Guest, stream: u64) {
    assert_eq!(guest.call("fclose", &[stream]) & 0xFFFF_FFFF, 0);
}

/// Write `text` to a stream with `fwrite`, one item per byte.
fn write(guest: &mut Guest, stream: u64, text: &[u8]) {
    guest.memory.write_bytes(TEXT + 0x4000, text).unwrap();
    let count = text.len() as u64;
    assert_eq!(
        guest.call("fwrite", &[TEXT + 0x4000, 1, count, stream]),
        count
    );
}

/// Create or replace a file with exactly these bytes.
fn store(guest: &mut Guest, name: &str, bytes: &[u8]) {
    let stream = opened(guest, name, "wb");
    write(guest, stream, bytes);
    close(guest, stream);
}

/// `fgets(LINE, count, stream)`: the string it stored, or `None` for a null
/// result. Either way, the bytes it had no reason to write must be untouched.
fn line(guest: &mut Guest, stream: u64, count: u64) -> Option<Vec<u8>> {
    let room = (count as usize).min(0x400) + 16;
    guest
        .memory
        .write_bytes(LINE, &vec![UNTOUCHED; room])
        .unwrap();
    let result = guest.call("fgets", &[LINE, count, stream]);
    let mut after = vec![0; room];
    guest.memory.read_bytes(LINE, &mut after).unwrap();
    if result == 0 {
        assert!(
            after.iter().all(|byte| *byte == UNTOUCHED),
            "buffer written"
        );
        return None;
    }
    assert_eq!(result, LINE, "fgets returns its buffer");
    let end = after
        .iter()
        .position(|byte| *byte == 0)
        .expect("terminator");
    assert!(end < count as usize, "more than count - 1 characters");
    assert!(after[end + 1..].iter().all(|byte| *byte == UNTOUCHED));
    Some(after[..end].to_vec())
}

/// Every line of a file, read with `fgets` in the given mode.
fn lines(guest: &mut Guest, name: &str, mode: &str) -> Vec<Vec<u8>> {
    let stream = opened(guest, name, mode);
    let mut all = Vec::new();
    while let Some(text) = line(guest, stream, 96) {
        all.push(text);
        // A read that does not advance must fail, not loop for ever.
        assert!(all.len() <= 64, "{name}: fgets never reaches the end");
    }
    close(guest, stream);
    all
}

/// What the Gate A2 program does with a file: `fopen` for writing, `fprintf`,
/// `fclose`, `fopen` for reading, `fgets`, `fclose`. `fgets` reads "to and
/// including the first newline character, to the end of the stream, or until
/// the number of characters read is equal to numChars - 1", and returns null
/// at end of file (Microsoft Learn). Expected text is what the test wrote.
#[test]
fn a_file_written_through_a_stream_reads_back_line_by_line() {
    let (mut guest, streams) = stdio_guest();
    let file = opened(&mut guest, "gate-a2.txt", "w");
    assert!(!streams.contains(&file));
    let one = place(&mut guest, STRINGS, b"one");
    let first: &[u8] = b"sum 12345 hex a2 text one\n";
    let count = print(
        &mut guest,
        file,
        b"sum %llu hex %x text %s\n",
        &[12345, 0xa2, one],
    );
    assert_eq!(count, first.len() as u64);
    let second = place(&mut guest, STRINGS + 0x40, b"second line\n");
    assert_eq!(guest.call("fputs", &[second, file]) & 0xFFFF_FFFF, 0);
    write(&mut guest, file, b"third");
    assert_eq!(guest.call("fflush", &[file]) & 0xFFFF_FFFF, 0);
    close(&mut guest, file);
    // File output is not standard output.
    assert!(guest.state.standard_output().is_empty());
    assert!(guest.state.standard_error().is_empty());

    let file = opened(&mut guest, "gate-a2.txt", "r");
    assert_eq!(line(&mut guest, file, 96).as_deref(), Some(first));
    assert_eq!(
        line(&mut guest, file, 96).as_deref(),
        Some(&b"second line\n"[..])
    );
    // The last line has no newline: it ends at the end of the stream.
    assert_eq!(line(&mut guest, file, 96).as_deref(), Some(&b"third"[..]));
    assert_eq!(line(&mut guest, file, 96), None);
    assert_eq!(line(&mut guest, file, 96), None);
    close(&mut guest, file);
    assert_eq!(guest.errno(), 0);
}

/// The access types of the `fopen` page: "r" fails "if the file doesn't
/// exist"; with "w", "if the given file exists, its contents are destroyed";
/// "a" "creates the file if it doesn't exist" and "all write operations occur
/// at the end of the file"; "r+" needs the file to exist; "w+" and "a+" also
/// read. A null or empty name or mode returns null with `EINVAL`.
#[test]
fn fread_reads_whole_items_from_files_and_stdin() {
    let (mut guest, _) = stdio_guest();
    store(&mut guest, "read.bin", b"0123456789abcdef");
    let file = opened(&mut guest, "read.bin", "rb");

    // Four items of four bytes, then a partial read: only whole items count.
    assert_eq!(guest.call("fread", &[TEXT + 0x4000, 4, 4, file]), 4);
    let mut stored = [0u8; 16];
    guest.memory.read_bytes(TEXT + 0x4000, &mut stored).unwrap();
    assert_eq!(&stored, b"0123456789abcdef");
    assert_eq!(guest.call("fread", &[TEXT + 0x4000, 4, 4, file]), 0);
    assert_ne!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);

    // A five-byte remainder with four-byte items reads one whole item.
    close(&mut guest, file);
    store(&mut guest, "odd.bin", b"abcde");
    let file = opened(&mut guest, "odd.bin", "rb");
    assert_eq!(guest.call("fread", &[TEXT + 0x4000, 4, 4, file]), 1);
    let mut stored = [0u8; 4];
    guest.memory.read_bytes(TEXT + 0x4000, &mut stored).unwrap();
    assert_eq!(&stored, b"abcd");

    // fread may read stdin, a write-only stream may not be read.
    close(&mut guest, file);
    let file = opened(&mut guest, "writeonly.bin", "wb");
    assert_eq!(guest.call("fread", &[TEXT + 0x4000, 1, 4, file]), 0);
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    close(&mut guest, file);

    // A null buffer or stream is EINVAL; no items or no size reads nothing.
    for args in [[0, 1, 4, 1], [TEXT + 0x4000, 1, 4, 0]] {
        let file = opened(&mut guest, "odd.bin", "rb");
        let mut use_args = args;
        use_args[3] = if args[3] == 1 { file } else { 0 };
        assert_eq!(guest.call("fread", &use_args), 0);
        assert_eq!(guest.errno(), EINVAL);
        guest.set_errno(0);
        close(&mut guest, file);
    }

    // fgetc walks the file byte by byte and answers EOF at its end.
    let file = opened(&mut guest, "odd.bin", "rb");
    for expected in b"abcde".iter() {
        assert_eq!(
            guest.call("fgetc", &[file]) & 0xFFFF_FFFF,
            u64::from(*expected)
        );
    }
    assert_eq!(guest.call("fgetc", &[file]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    close(&mut guest, file);
    assert_eq!(guest.call("fgetc", &[0]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), EINVAL);
    guest.set_errno(0);
}

#[test]
fn fseek_ftell_and_rewind_move_through_file_streams() {
    let (mut guest, _) = stdio_guest();
    store(&mut guest, "seek.bin", b"0123456789abcdef");
    let file = opened(&mut guest, "seek.bin", "rb");

    // ftell starts at zero; SEEK_SET, SEEK_CUR and SEEK_END move as documented.
    assert_eq!(guest.call("ftell", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("fseek", &[file, 4, 0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("ftell", &[file]) & 0xFFFF_FFFF, 4);
    assert_eq!(guest.call("fseek", &[file, 2, 1]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("ftell", &[file]) & 0xFFFF_FFFF, 6);
    // SEEK_END minus four: the sign bit of the 32-bit form travels as unsigned.
    assert_eq!(
        guest.call("fseek", &[file, 0xFFFF_FFFC, 2]) & 0xFFFF_FFFF,
        0
    );
    assert_eq!(guest.call("ftell", &[file]) & 0xFFFF_FFFF, 12);
    assert_eq!(guest.call("fgetc", &[file]) & 0xFFFF_FFFF, u64::from(b'c'));

    // Reading past the position the seek set proves the move, and rewind
    // returns to the start while clearing the end-of-file indicator.
    assert_eq!(guest.call("fseek", &[file, 16, 0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("fgetc", &[file]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_ne!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    guest.call("rewind", &[file]);
    assert_eq!(guest.call("ftell", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("fgetc", &[file]) & 0xFFFF_FFFF, u64::from(b'0'));

    // A bad origin, a null stream and a position before the start are EINVAL.
    for args in [[file, 0, 7], [file, 0xFFFF_FFFF, 0]] {
        assert_eq!(
            guest.call("fseek", &args) & 0xFFFF_FFFF,
            0xFFFF_FFFF,
            "{args:x?}"
        );
        assert_eq!(guest.errno(), EINVAL, "{args:x?}");
        guest.set_errno(0);
    }
    assert_eq!(guest.call("ftell", &[0]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), EINVAL);
    guest.set_errno(0);
    close(&mut guest, file);
}

#[test]
fn fopen_modes_follow_the_documentation() {
    let (mut guest, _) = stdio_guest();
    guest.set_errno(0);
    for mode in ["r", "r+", "rb", "rt"] {
        assert_eq!(open(&mut guest, "missing.txt", mode), 0, "{mode}");
        assert_eq!(guest.errno(), ENOENT, "{mode}");
        guest.set_errno(0);
    }

    // "w" creates the file, and opening it again destroys what it held.
    store(&mut guest, "w.txt", b"old contents\n");
    assert_eq!(lines(&mut guest, "w.txt", "rb"), [b"old contents\n"]);
    let file = opened(&mut guest, "w.txt", "w");
    close(&mut guest, file);
    assert!(lines(&mut guest, "w.txt", "rb").is_empty());

    // "a" creates the file, keeps what it holds and writes at its end.
    for text in [&b"1\n"[..], b"2\n"] {
        let file = opened(&mut guest, "a.txt", "ab");
        write(&mut guest, file, text);
        close(&mut guest, file);
    }
    assert_eq!(lines(&mut guest, "a.txt", "rb"), [b"1\n", b"2\n"]);

    // "r+" keeps the contents and writes from the start.
    store(&mut guest, "plus.txt", b"abcdef\n");
    let file = opened(&mut guest, "plus.txt", "r+b");
    write(&mut guest, file, b"XY");
    // Reading continues where the write left off.
    assert_eq!(line(&mut guest, file, 96).as_deref(), Some(&b"cdef\n"[..]));
    close(&mut guest, file);
    assert_eq!(lines(&mut guest, "plus.txt", "rb"), [b"XYcdef\n"]);

    // "w+" may be read; right after a write it is at the end of the file. A
    // "w" stream may not be read at all.
    let file = opened(&mut guest, "wplus.txt", "w+b");
    write(&mut guest, file, b"data\n");
    assert_eq!(line(&mut guest, file, 96), None);
    assert_eq!(guest.errno(), 0);
    close(&mut guest, file);
    let file = opened(&mut guest, "wplus.txt", "w");
    assert_eq!(line(&mut guest, file, 96), None);
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    close(&mut guest, file);

    // "a+" reads from the start (Xenora's choice; ISO C leaves the initial
    // position to the implementation) and still writes at the end.
    store(&mut guest, "aplus.txt", b"one\ntwo\n");
    let file = opened(&mut guest, "aplus.txt", "a+b");
    assert_eq!(line(&mut guest, file, 96).as_deref(), Some(&b"one\n"[..]));
    write(&mut guest, file, b"three\n");
    close(&mut guest, file);
    assert_eq!(
        lines(&mut guest, "aplus.txt", "rb"),
        [&b"one\n"[..], b"two\n", b"three\n"]
    );

    // One file by any spelling the drive accepts: either slash, any case,
    // with or without the drive.
    store(&mut guest, "Name.TXT", b"same\n");
    for name in ["name.txt", "NAME.txt", "C:\\name.txt", "c:/Name.Txt"] {
        assert_eq!(lines(&mut guest, name, "r"), [b"same\n"], "{name}");
    }

    // Null and empty names and modes, modes that are not modes, a name the
    // drive rejects, and a name that is too long.
    guest.set_errno(0);
    let name = place(&mut guest, NAME, b"w.txt");
    let mode = place(&mut guest, MODE, b"r");
    for args in [[0, mode], [name, 0]] {
        assert_eq!(guest.call("fopen", &args), 0, "{args:x?}");
        assert_eq!(guest.errno(), STDIO_EINVAL, "{args:x?}");
        guest.set_errno(0);
    }
    let long = "x".repeat(261);
    for (name, mode) in [
        ("", "r"),
        ("w.txt", ""),
        ("w.txt", "tr"),
        ("w.txt", "br"),
        ("w.txt", "rw"),
        ("w.txt", "rbt"),
        ("w.txt", "r++"),
        ("w.txt", "wx"),
        ("w.txt", "r,ccs=UTF-8"),
        ("w.txt", "R"),
        ("bad*name", "w"),
        ("con", "w"),
        (long.as_str(), "w"),
    ] {
        assert_eq!(open(&mut guest, name, mode), 0, "{name:?} {mode:?}");
        assert_eq!(guest.errno(), STDIO_EINVAL, "{name:?} {mode:?}");
        guest.set_errno(0);
    }
    // `a\..\b` is no invalid name: the dot components resolve lexically
    // ahead of validation, so the path is exactly `b` whether or not `a`
    // ever existed, and the open creates it.
    assert_ne!(open(&mut guest, "a\\..\\b", "w"), 0);
    assert!(lines(&mut guest, "b", "rb").is_empty());
    // A refused "w" destroyed nothing.
    assert_eq!(lines(&mut guest, "plus.txt", "rb"), [b"XYcdef\n"]);
    // A directory that does not exist.
    for mode in ["w", "a", "r"] {
        assert_eq!(open(&mut guest, "nodir\\file.txt", mode), 0, "{mode}");
        assert_eq!(guest.errno(), ENOENT, "{mode}");
        guest.set_errno(0);
    }
}

/// "LF characters are translated to CR-LF combinations on output", "CR-LF
/// combinations are translated into single line feeds on input", and "CTRL+Z
/// is interpreted as an end-of-file character on input" in text mode; binary
/// mode suppresses the translations. Without `t` or `b` the mode is text,
/// the initial `_fmode` (Microsoft Learn, fopen).
#[test]
fn text_and_binary_streams_translate_as_documented() {
    let (mut guest, _) = stdio_guest();
    for mode in ["w", "wt"] {
        let file = opened(&mut guest, "text.txt", mode);
        write(&mut guest, file, b"a\nb\n");
        // fwrite's result did not count the carriage returns.
        close(&mut guest, file);
        // Read back untranslated, the file holds CR-LF pairs.
        assert_eq!(
            lines(&mut guest, "text.txt", "rb"),
            [b"a\r\n", b"b\r\n"],
            "{mode}"
        );
        for read in ["r", "rt"] {
            assert_eq!(lines(&mut guest, "text.txt", read), [b"a\n", b"b\n"]);
        }
    }
    // Formatted output and fputs are translated like fwrite.
    let file = opened(&mut guest, "text.txt", "w");
    assert_eq!(print(&mut guest, file, b"%d\n", &[7]), 2);
    let text = place(&mut guest, STRINGS, b"s\n");
    assert_eq!(guest.call("fputs", &[text, file]) & 0xFFFF_FFFF, 0);
    close(&mut guest, file);
    assert_eq!(lines(&mut guest, "text.txt", "rb"), [b"7\r\n", b"s\r\n"]);

    // Binary output is stored as written.
    store(&mut guest, "binary.bin", b"x\ny");
    assert_eq!(lines(&mut guest, "binary.bin", "rb"), [&b"x\n"[..], b"y"]);

    // CTRL+Z ends a text stream and is data to a binary one. A carriage
    // return that no line feed follows is kept.
    store(&mut guest, "ctrlz.bin", b"one\r\ntw\ro\x1Athree\n");
    assert_eq!(
        lines(&mut guest, "ctrlz.bin", "r"),
        [&b"one\n"[..], b"tw\ro"]
    );
    assert_eq!(
        lines(&mut guest, "ctrlz.bin", "rb"),
        [&b"one\r\n"[..], b"tw\ro\x1Athree\n"]
    );
    // A text stream that begins with CTRL+Z has nothing to read.
    store(&mut guest, "empty.bin", b"\x1Arest");
    assert!(lines(&mut guest, "empty.bin", "r").is_empty());
}

/// `fgets` stores at most `numChars - 1` characters and a terminator, and
/// "if str or stream is a null pointer, or numChars is less than or equal to
/// zero", sets `errno` to `EINVAL` and returns null (Microsoft Learn).
#[test]
fn fgets_reads_lines_within_its_count() {
    let (mut guest, [input, out, _]) = stdio_guest();
    store(&mut guest, "lines.bin", b"abcdefgh\nxy");
    let file = opened(&mut guest, "lines.bin", "rb");
    assert_eq!(line(&mut guest, file, 4).as_deref(), Some(&b"abc"[..]));
    assert_eq!(line(&mut guest, file, 4).as_deref(), Some(&b"def"[..]));
    assert_eq!(line(&mut guest, file, 2).as_deref(), Some(&b"g"[..]));
    // A count of 1 has room for the terminator only and reads nothing.
    assert_eq!(line(&mut guest, file, 1).as_deref(), Some(&b""[..]));
    // The newline is kept, and reading stops after it. The count is an int.
    let count = 0xFFFF_FFFF_0000_0060;
    assert_eq!(
        line(&mut guest, file, count & 0xFFFF_FFFF).as_deref(),
        Some(&b"h\n"[..])
    );
    guest.memory.write_bytes(LINE, &[UNTOUCHED; 8]).unwrap();
    assert_eq!(guest.call("fgets", &[LINE, count, file]), LINE);
    assert_eq!(
        guest.memory.read_u32(LINE).unwrap(),
        u32::from_le_bytes(*b"xy\0\xEE")
    );
    // At the end of the file every count returns null.
    for count in [96, 2, 1] {
        assert_eq!(line(&mut guest, file, count), None, "{count}");
    }
    assert_eq!(guest.errno(), 0);

    guest.set_errno(0);
    for args in [
        [0, 96, file],
        [LINE, 96, 0],
        [LINE, 0, file],
        [LINE, 0xFFFF_FFFF, file],
        [LINE, 0x8000_0000, file],
    ] {
        assert_eq!(guest.call("fgets", &args), 0, "{args:x?}");
        assert_eq!(guest.errno(), STDIO_EINVAL, "{args:x?}");
        guest.set_errno(0);
    }
    close(&mut guest, file);

    // A stream that was not opened for reading, and standard output.
    let writer = opened(&mut guest, "lines.bin", "ab");
    for stream in [writer, out] {
        assert_eq!(guest.call("fgets", &[LINE, 96, stream]), 0);
        assert_eq!(guest.errno(), EBADF);
        guest.set_errno(0);
    }
    close(&mut guest, writer);
    // A closed stream and a pointer that never was one. Standard input is
    // served since #467: with no input supplied the read is end of file.
    assert_eq!(guest.call("fgets", &[LINE, 96, input]), 0);
    for stream in [writer, TEXT] {
        assert_eq!(
            guest.run("fgets", &[LINE, 96, stream]).1,
            LIMIT,
            "{stream:#x}"
        );
    }
    // A buffer that cannot be written is a fault.
    let file = opened(&mut guest, "lines.bin", "rb");
    let exit = guest.run("fgets", &[0x9_0000_0000, 96, file]).1;
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
}

/// Output to a stream that was opened only for reading fails with the error
/// result of each function, and so does output the drive has no room for.
/// The `errno` values are Xenora's choice: `EBADF` and `ENOSPC`.
#[test]
fn file_output_that_cannot_be_written_fails_and_writes_nothing() {
    let (mut guest, _) = stdio_guest();
    store(&mut guest, "fixed.bin", b"keep\n");
    let file = opened(&mut guest, "fixed.bin", "rb");
    guest.set_errno(0);
    let (count, exit) = print_with(&mut guest, MINGW_OPTIONS, file, b"%d", &[1]);
    assert_eq!((count, exit), (STDIO_MINUS_ONE, ExitReason::Halt));
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    let text = place(&mut guest, STRINGS, b"text");
    assert_eq!(guest.call("fwrite", &[text, 1, 4, file]), 0);
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    assert_eq!(
        guest.call("fputs", &[text, file]) & 0xFFFF_FFFF,
        STDIO_MINUS_ONE
    );
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    close(&mut guest, file);
    assert_eq!(lines(&mut guest, "fixed.bin", "rb"), [b"keep\n"]);

    // The drive holds 16 MiB in all. Fifteen whole megabytes and most of the
    // sixteenth fit beside the five bytes above.
    const CHUNK: u64 = 1 << 20;
    guest
        .memory
        .write_bytes(TEXT, &vec![b'x'; CHUNK as usize])
        .unwrap();
    let file = opened(&mut guest, "big.bin", "wb");
    for _ in 0..15 {
        assert_eq!(guest.call("fwrite", &[TEXT, 1, CHUNK, file]), CHUNK);
    }
    assert_eq!(guest.call("fwrite", &[TEXT, 1, CHUNK - 5, file]), CHUNK - 5);
    assert_eq!(guest.errno(), 0);
    // Not one more byte, through any of the three.
    assert_eq!(guest.call("fwrite", &[TEXT, 1, 1, file]), 0);
    assert_eq!(guest.errno(), ENOSPC);
    guest.set_errno(0);
    let (count, _) = print_with(&mut guest, MINGW_OPTIONS, file, b"y", &[]);
    assert_eq!(count, STDIO_MINUS_ONE);
    assert_eq!(guest.errno(), ENOSPC);
    guest.set_errno(0);
    close(&mut guest, file);
    // Emptying the big file makes room again.
    let file = opened(&mut guest, "big.bin", "wb");
    assert_eq!(guest.call("fwrite", &[TEXT, 1, 1, file]), 1);
    close(&mut guest, file);
}

/// `fclose` "returns 0 if the stream is successfully closed" and, for a null
/// stream, sets `errno` to `EINVAL` and returns `EOF` (Microsoft Learn). At
/// most 64 streams are open at once (Xenora's bound), and the 65th `fopen`
/// fails with `EMFILE`.
#[test]
fn open_streams_are_bounded_and_fclose_releases_them() {
    let (mut guest, [input, out, err]) = stdio_guest();
    store(&mut guest, "shared.bin", b"x\n");
    let mut open_streams: Vec<u64> = (0..64)
        .map(|_| opened(&mut guest, "shared.bin", "rb"))
        .collect();
    let mut distinct = open_streams.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 64, "each stream has its own FILE object");
    guest.set_errno(0);
    for mode in ["rb", "wb", "ab"] {
        assert_eq!(open(&mut guest, "shared.bin", mode), 0, "{mode}");
        assert_eq!(guest.errno(), EMFILE, "{mode}");
        guest.set_errno(0);
    }
    // The refused "wb" destroyed nothing, and each stream has its own
    // position.
    assert_eq!(
        line(&mut guest, open_streams[0], 96).as_deref(),
        Some(&b"x\n"[..])
    );
    assert_eq!(line(&mut guest, open_streams[0], 96), None);
    assert_eq!(
        line(&mut guest, open_streams[1], 96).as_deref(),
        Some(&b"x\n"[..])
    );

    // Closing one makes room for one.
    let last = open_streams.pop().unwrap();
    close(&mut guest, last);
    let again = opened(&mut guest, "shared.bin", "rb");
    assert_eq!(open(&mut guest, "shared.bin", "rb"), 0);
    assert_eq!(guest.errno(), EMFILE);
    guest.set_errno(0);

    // fflush and setvbuf accept an open file stream.
    assert_eq!(guest.call("fflush", &[again]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("setvbuf", &[again, 0, 4, 0]) & 0xFFFF_FFFF, 0);

    assert_eq!(guest.call("fclose", &[0]) & 0xFFFF_FFFF, STDIO_MINUS_ONE);
    assert_eq!(guest.errno(), STDIO_EINVAL);
    guest.set_errno(0);
    // A closed stream is no stream to any function, and closing a standard
    // stream is not modelled.
    close(&mut guest, again);
    for symbol in ["fclose", "fflush"] {
        assert_eq!(guest.run(symbol, &[again]).1, LIMIT, "{symbol}");
    }
    let (_, exit) = print_with(&mut guest, MINGW_OPTIONS, again, b"x", &[]);
    assert_eq!(exit, LIMIT);
    // Closing a standard stream is legal: the CRT does not reserve them on
    // Windows. awk closes its input when stdin reaches EOF before exit, and
    // the close marks the descriptor exactly as `_close` of it does (#1273).
    for stream in [input, out, err] {
        assert_eq!(
            guest.call("fclose", &[stream]) & 0xFFFF_FFFF,
            0,
            "{stream:#x}"
        );
    }
    // A second close has nothing to close, and no stream at all stays no
    // stream.
    for stream in [input, out, err] {
        assert_eq!(
            guest.call("fclose", &[stream]) & 0xFFFF_FFFF,
            STDIO_MINUS_ONE,
            "{stream:#x}"
        );
    }
    assert_eq!(guest.run("fclose", &[TEXT]).1, LIMIT);
    guest.set_errno(0);
    for stream in open_streams {
        close(&mut guest, stream);
    }
    assert_eq!(guest.errno(), 0);
}

/// `perror` "prints an error message to stderr": the message "followed by a
/// colon, then by the system error message for the last library call that
/// produced the error, and finally by a newline character"; "if message is a
/// null pointer or a pointer to a null string, perror prints only the system
/// error message". The page's example prints "No such file or directory"
/// for a missing file; the other texts are Xenora's.
#[test]
fn perror_writes_the_message_and_the_error_text_to_stderr() {
    let (mut guest, _) = stdio_guest();
    guest.set_errno(0);
    // The failure the Gate A2 program would report.
    assert_eq!(open(&mut guest, "nosuchf.ile", "r"), 0);
    let message = place(&mut guest, STRINGS, b"perror says open failed");
    guest.call("perror", &[message]);
    assert_eq!(
        guest.state.standard_error(),
        b"perror says open failed: No such file or directory\r\n"
    );
    // perror does not change errno.
    assert_eq!(guest.errno(), ENOENT);
    assert!(guest.state.standard_output().is_empty());

    let empty = place(&mut guest, STRINGS + 0x80, b"");
    let mut expected = guest.state.standard_error();
    for (errno, message, text) in [
        (ENOENT, 0, &b"No such file or directory\r\n"[..]),
        (ENOENT, empty, b"No such file or directory\r\n"),
        (0, message, b"perror says open failed: No error\r\n"),
        (STDIO_EINVAL, 0, b"Invalid argument\r\n"),
        (EBADF, 0, b"Bad file descriptor\r\n"),
        (EMFILE, 0, b"Too many open files\r\n"),
        (ENOSPC, 0, b"No space left on device\r\n"),
        (13, 0, b"Permission denied\r\n"),
        (12, 0, b"Not enough space\r\n"),
        (999, 0, b"Unknown error\r\n"),
    ] {
        guest.set_errno(errno);
        guest.call("perror", &[message]);
        expected.extend_from_slice(text);
        assert_eq!(guest.state.standard_error(), expected, "errno {errno}");
        assert_eq!(guest.errno(), errno);
    }
    // An unreadable message is a fault and prints nothing.
    let exit = guest.run("perror", &[0x9_0000_0000]).1;
    assert!(matches!(exit, ExitReason::MemoryFault(_)), "{exit:?}");
    assert_eq!(guest.state.standard_error(), expected);
}

/// The module and symbol pairs a program built with mingw-w64 14.0.0 (UCRT)
/// imports the four file services by.
#[test]
fn file_services_resolve_as_mingw_w64_imports_them() {
    let (registry, _) = standard(0);
    let named = |name: &str| ImportName::Name(name.to_owned());
    const STDIO: &str = "api-ms-win-crt-stdio-l1-1-0.dll";
    const RUNTIME: &str = "api-ms-win-crt-runtime-l1-1-0.dll";
    for (module, symbol) in [
        (STDIO, "fopen"),
        (STDIO, "fclose"),
        (STDIO, "fgets"),
        (RUNTIME, "perror"),
    ] {
        let service = registry
            .resolve(module, &named(symbol))
            .unwrap_or_else(|| panic!("{module}!{symbol}"));
        let target = registry.resolve("ucrtbase.dll", &named(symbol)).unwrap();
        assert!(std::ptr::eq(service, target), "{symbol}");
        assert_eq!(service.status, ServiceStatus::Partial, "{symbol}");
    }
    assert!(registry.resolve(RUNTIME, &named("fopen")).is_none());
    assert!(registry.resolve(STDIO, &named("perror")).is_none());
}

/// The module and symbol pairs a program built with mingw-w64 14.0.0 (UCRT)
/// imports these six services by, read from such a program's import table.
#[test]
fn standard_stream_services_resolve_as_mingw_w64_imports_them() {
    let (registry, _) = standard(0);
    let named = |name: &str| ImportName::Name(name.to_owned());
    const STDIO: &str = "api-ms-win-crt-stdio-l1-1-0.dll";
    for symbol in [
        "__acrt_iob_func",
        "__stdio_common_vfprintf",
        "fwrite",
        "fputs",
        "fflush",
        "setvbuf",
    ] {
        let service = registry
            .resolve(STDIO, &named(symbol))
            .unwrap_or_else(|| panic!("{symbol}"));
        let target = registry.resolve("ucrtbase.dll", &named(symbol)).unwrap();
        assert!(std::ptr::eq(service, target), "{symbol}");
        assert_eq!(service.status, ServiceStatus::Partial, "{symbol}");
        // Not through the runtime API set, which lists other symbols.
        assert!(
            registry
                .resolve("api-ms-win-crt-runtime-l1-1-0.dll", &named(symbol))
                .is_none(),
            "{symbol}"
        );
    }
}

#[test]
fn last_error_is_set_by_failures_and_by_the_guest() {
    let mut guest = Guest::new();
    assert_eq!(guest.last_error(), 0);
    guest.call("SetLastError", &[0xFFFF_FFFF_8000_0001]);
    assert_eq!(guest.last_error(), 0x8000_0001);
    assert_eq!(guest.call("GetCurrentProcess", &[]), PROCESS);
    assert_eq!(
        guest.last_error(),
        0x8000_0001,
        "success leaves it unchanged"
    );
    guest.call("CloseHandle", &[0x1234]);
    assert_eq!(guest.last_error(), 6);
}

/// What a guest sees in `__argc` and `__argv`: the count, each argument's
/// bytes up to its terminator, and the pointer after the last argument.
fn guest_arguments(guest: &mut Guest) -> (u32, Vec<Vec<u8>>, u64) {
    let argc = guest.call("__p___argc", &[]);
    let argv = guest.call("__p___argv", &[]);
    let count = guest.memory.read_u32(argc).unwrap();
    let table = guest.memory.read_u64(argv).unwrap();
    let mut arguments = Vec::new();
    for index in 0..u64::from(count) {
        let mut at = guest.memory.read_u64(table + 8 * index).unwrap();
        let mut bytes = Vec::new();
        loop {
            match guest.memory.read_u8(at).unwrap() {
                0 => break,
                byte => bytes.push(byte),
            }
            at += 1;
        }
        arguments.push(bytes);
    }
    let after = guest.memory.read_u64(table + 8 * u64::from(count)).unwrap();
    (count, arguments, after)
}

/// The arguments a host supplies are what the guest finds in `__argc` and
/// `__argv` after `_configure_narrow_argv`, the way the mingw-w64 startup code
/// reads them before `main`. `__argc` and `__argv` are documented globals; ISO
/// C (5.1.2.2.1) puts a null pointer after the last argument, lets the program
/// modify the strings, and makes `argv[0]` the empty string when no program
/// name is available. Expected values are the strings this test supplied.
#[test]
fn program_arguments_reach_the_guest_as_argc_and_argv() {
    let mut guest = Guest::new();
    let supplied = ["gate-a2.exe", "one", "two words", "", "caf\u{e9} \u{2713}"];
    guest.state.set_program_arguments(&supplied).unwrap();

    // Before the runtime configures them there are no arguments.
    let argc = guest.call("__p___argc", &[]);
    let argv = guest.call("__p___argv", &[]);
    assert!(argc != 0 && argv != 0 && argc.abs_diff(argv) >= 8);
    assert_eq!(guest.memory.read_u32(argc).unwrap(), 0);
    assert_eq!(guest.memory.read_u64(argv).unwrap(), 0);
    // A mode other than 0, 1 or 2 is refused with EINVAL; mode 0 asks for no
    // arguments. Neither builds anything. The mode is an int.
    for (mode, result) in [(3, 22), (0xFFFF_FFFF, 22), (0x8000_0001, 22), (0, 0)] {
        let returned = guest.call("_configure_narrow_argv", &[JUNK_HIGH | mode]);
        assert_eq!(returned & 0xFFFF_FFFF, result, "mode {mode:#x}");
        assert_eq!(guest.memory.read_u32(argc).unwrap(), 0, "mode {mode:#x}");
        assert_eq!(guest.memory.read_u64(argv).unwrap(), 0, "mode {mode:#x}");
    }

    // _crt_argv_unexpanded_arguments is 1.
    assert_eq!(
        guest.call("_configure_narrow_argv", &[JUNK_HIGH | 1]) & 0xFFFF_FFFF,
        0
    );
    let (count, arguments, after) = guest_arguments(&mut guest);
    assert_eq!(count, 5);
    let wanted: Vec<Vec<u8>> = supplied
        .iter()
        .map(|text| text.as_bytes().to_vec())
        .collect();
    assert_eq!(arguments, wanted);
    assert_eq!(after, 0, "argv[argc] is a null pointer");
    // The variables did not move, and each argument has its own storage.
    assert_eq!(guest.call("__p___argc", &[]), argc);
    assert_eq!(guest.call("__p___argv", &[]), argv);
    let table = guest.memory.read_u64(argv).unwrap();
    let mut starts: Vec<u64> = (0..5)
        .map(|index| guest.memory.read_u64(table + 8 * index).unwrap())
        .collect();
    for (start, argument) in starts.iter().zip(&wanted) {
        assert!(*start >= table + 8 * 6, "a string inside the pointer table");
        // The terminator is the byte after the argument.
        assert_eq!(
            guest.memory.read_u8(start + argument.len() as u64).unwrap(),
            0
        );
    }
    starts.sort_unstable();
    for (pair, argument) in starts.windows(2).zip(&wanted) {
        assert!(pair[1] - pair[0] > argument.len() as u64, "strings overlap");
    }

    // The program may modify its arguments; a second configuration, in either
    // mode, does not rebuild them.
    let first = guest.memory.read_u64(table).unwrap();
    guest.memory.write_u8(first, b'G').unwrap();
    for mode in [1, 2, 0, 3] {
        guest.call("_configure_narrow_argv", &[mode]);
        assert_eq!(guest.memory.read_u64(argv).unwrap(), table, "mode {mode}");
        assert_eq!(guest.memory.read_u8(first).unwrap(), b'G', "mode {mode}");
        assert_eq!(guest.memory.read_u32(argc).unwrap(), 5, "mode {mode}");
    }
    // Once built, the host can no longer change them.
    assert_eq!(
        guest.state.set_program_arguments(&["late"]),
        Err(ProgramArgumentsError::AlreadyConfigured)
    );
    assert_eq!(guest_arguments(&mut guest).0, 5);
}

/// What a guest gets when the host supplies nothing, supplies no arguments at
/// all, or uses `_crt_argv_expanded_arguments` (2), and what a host may not
/// supply.
#[test]
fn program_arguments_have_defaults_and_limits() {
    // No host input: the program name is not available, so ISO C makes
    // argv[0] the empty string.
    let mut guest = Guest::new();
    assert_eq!(guest.call("_configure_narrow_argv", &[1]), 0);
    assert_eq!(guest_arguments(&mut guest), (1, vec![Vec::new()], 0));

    // An empty list is zero arguments: argv is one null pointer.
    let mut guest = Guest::new();
    guest.state.set_program_arguments(&[]).unwrap();
    assert_eq!(guest.call("_configure_narrow_argv", &[1]), 0);
    assert_eq!(guest_arguments(&mut guest), (0, Vec::new(), 0));
    let argv = guest.call("__p___argv", &[]);
    assert_ne!(guest.memory.read_u64(argv).unwrap(), 0);

    // Mode 2 asks for wildcard expansion, which is not performed: a pattern
    // arrives as it was supplied. The last list supplied before configuration
    // is the one used, and configuring first and asking for the pointers
    // afterwards works too.
    let mut guest = Guest::new();
    guest.state.set_program_arguments(&["first"]).unwrap();
    guest
        .state
        .set_program_arguments(&["prog", "*.txt", "a?c"])
        .unwrap();
    assert_eq!(guest.call("_configure_narrow_argv", &[2]), 0);
    let wanted = vec![b"prog".to_vec(), b"*.txt".to_vec(), b"a?c".to_vec()];
    assert_eq!(guest_arguments(&mut guest), (3, wanted, 0));

    // A NUL byte would end the argument early in the guest.
    let guest = Guest::new();
    let state = &guest.state;
    assert_eq!(
        state.set_program_arguments(&["ok", "a\0b"]),
        Err(ProgramArgumentsError::ContainsNul)
    );
    // The bound counts each argument with its terminator, and is inclusive.
    assert_eq!(MAX_PROGRAM_ARGUMENT_BYTES, 32_767);
    let longest = "x".repeat(MAX_PROGRAM_ARGUMENT_BYTES - 1);
    assert_eq!(state.set_program_arguments(&[&longest]), Ok(()));
    let too_long = "x".repeat(MAX_PROGRAM_ARGUMENT_BYTES);
    assert_eq!(
        state.set_program_arguments(&[&too_long]),
        Err(ProgramArgumentsError::TooLong)
    );
    // Two arguments of 16,383 and 16,382 bytes take 32,767 with their
    // terminators; one more empty argument is one byte too many.
    let (half, rest) = ("y".repeat(16_383), "z".repeat(16_382));
    assert_eq!(state.set_program_arguments(&[&half, &rest]), Ok(()));
    assert_eq!(
        state.set_program_arguments(&[&half, &rest, ""]),
        Err(ProgramArgumentsError::TooLong)
    );
    // A refused list replaces nothing: the last accepted one is still used.
    let mut guest = guest;
    assert_eq!(guest.call("_configure_narrow_argv", &[1]), 0);
    let (count, arguments, after) = guest_arguments(&mut guest);
    assert_eq!((count, after), (2, 0));
    assert_eq!(arguments, [half.as_bytes(), rest.as_bytes()]);
}

/// `_environ` is a documented global: a pointer to the array of environment
/// strings. Xenora's environment is empty, so after
/// `_initialize_narrow_environment` the table is one null pointer, the usual
/// end of such a table. Before that call `_environ` is null.
#[test]
fn the_environment_table_is_empty_and_ends_with_a_null_pointer() {
    let mut guest = Guest::new();
    let environ = guest.call("__p__environ", &[]);
    assert_ne!(environ, 0);
    assert_eq!(guest.memory.read_u64(environ).unwrap(), 0);
    assert_eq!(guest.call("_initialize_narrow_environment", &[]), 0);
    let table = guest.memory.read_u64(environ).unwrap();
    assert_ne!(table, 0);
    assert_eq!(guest.memory.read_u64(table).unwrap(), 0);
    // A second call keeps the table, and the pointer does not move.
    assert_eq!(guest.call("_initialize_narrow_environment", &[]), 0);
    assert_eq!(guest.call("__p__environ", &[]), environ);
    assert_eq!(guest.memory.read_u64(environ).unwrap(), table);

    // The three variables are separate, and neither initialization touches
    // the other's: the order the mingw-w64 startup uses is environment first.
    let argc = guest.call("__p___argc", &[]);
    let argv = guest.call("__p___argv", &[]);
    let mut cells = [argc, argv, environ];
    cells.sort_unstable();
    assert!(cells[1] - cells[0] >= 8 && cells[2] - cells[1] >= 8);
    assert_eq!(guest.memory.read_u32(argc).unwrap(), 0);
    assert_eq!(guest.memory.read_u64(argv).unwrap(), 0);
    assert_eq!(guest.call("_configure_narrow_argv", &[1]), 0);
    assert_eq!(guest.memory.read_u64(environ).unwrap(), table);
    assert_eq!(guest.memory.read_u64(table).unwrap(), 0);
    assert_eq!(guest_arguments(&mut guest).0, 1);

    // Arguments first, environment second, on a fresh guest.
    let mut other = Guest::new();
    assert_eq!(other.call("_configure_narrow_argv", &[1]), 0);
    let environ = other.call("__p__environ", &[]);
    assert_eq!(other.memory.read_u64(environ).unwrap(), 0);
    assert_eq!(other.call("_initialize_narrow_environment", &[]), 0);
    let table = other.memory.read_u64(environ).unwrap();
    assert_eq!(other.memory.read_u64(table).unwrap(), 0);
    assert_eq!(guest_arguments(&mut other), (1, vec![Vec::new()], 0));
}

/// The module and symbol pairs a program built with mingw-w64 14.0.0 (UCRT)
/// imports these five services by, read from such a program's import table.
#[test]
fn program_argument_services_resolve_as_mingw_w64_imports_them() {
    let (registry, _) = standard(0);
    let named = |name: &str| ImportName::Name(name.to_owned());
    const RUNTIME: &str = "api-ms-win-crt-runtime-l1-1-0.dll";
    const ENVIRONMENT: &str = "api-ms-win-crt-environment-l1-1-0.dll";
    for (module, symbol) in [
        (RUNTIME, "__p___argc"),
        (RUNTIME, "__p___argv"),
        (ENVIRONMENT, "__p__environ"),
        (RUNTIME, "_configure_narrow_argv"),
        (RUNTIME, "_initialize_narrow_environment"),
    ] {
        let service = registry
            .resolve(module, &named(symbol))
            .unwrap_or_else(|| panic!("{module}!{symbol}"));
        let target = registry.resolve("ucrtbase.dll", &named(symbol)).unwrap();
        assert!(std::ptr::eq(service, target), "{module}!{symbol}");
        assert_eq!(service.status, ServiceStatus::Partial, "{symbol}");
    }
    // An API set forwards only the symbols listed for it.
    assert!(
        registry
            .resolve(ENVIRONMENT, &named("__p___argc"))
            .is_none()
    );
    assert!(registry.resolve(RUNTIME, &named("__p__environ")).is_none());
}

#[test]
fn virtual_memory_is_mapped_released_and_bounded() {
    let mut guest = Guest::new();
    const COMMIT_RESERVE: u64 = 0x3000;
    const RELEASE: u64 = 0x8000;
    let address = guest.call("VirtualAlloc", &[0, 5000, COMMIT_RESERVE, 0x04]);
    assert!(address != 0 && address.is_multiple_of(0x1_0000));
    assert_eq!(
        guest.memory.read_u64(address + 8184).unwrap(),
        0,
        "zeroed, whole pages"
    );
    assert!(guest.memory.read_u8(address + 8192).is_err());
    guest.memory.write_u64(address, 7).unwrap();
    for (args, error) in [
        ([0, 0, COMMIT_RESERVE, 0x04], 87),
        ([0, 4096, 0x1000, 0x04], 50),
        ([0, 4096, COMMIT_RESERVE, 0x40], 87),
        ([address, 4096, COMMIT_RESERVE, 0x04], 487),
        ([0, u64::MAX, COMMIT_RESERVE, 0x04], 87),
        ([0, 1 << 40, COMMIT_RESERVE, 0x04], 8),
    ] {
        assert_eq!(guest.call("VirtualAlloc", &args), 0, "{args:x?}");
        assert_eq!(guest.last_error(), error, "{args:x?}");
    }
    for (args, error) in [
        ([address, 4096, RELEASE], 87),
        ([address, 0, 0x4000], 50),
        ([address + 4096, 0, RELEASE], 487),
    ] {
        assert_eq!(guest.call("VirtualFree", &args), 0, "{args:x?}");
        assert_eq!(guest.last_error(), error, "{args:x?}");
    }
    assert_eq!(guest.call("VirtualFree", &[address, 0, RELEASE]), 1);
    assert!(guest.memory.read_u8(address).is_err());
    assert_eq!(guest.call("VirtualFree", &[address, 0, RELEASE]), 0);
}

/// Query a committed allocation, change its protection at page granularity,
/// and verify that the memory model enforces the result. Expected values are
/// the public MEMORY_BASIC_INFORMATION layout and memory protection constants.
#[test]
fn virtual_memory_query_and_protect_committed_pages() {
    let mut guest = Guest::new();
    const COMMIT_RESERVE: u64 = 0x3000;
    const NO_ACCESS: u64 = 0x01;
    const READ_ONLY: u64 = 0x02;
    const READ_WRITE: u64 = 0x04;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_PRIVATE: u32 = 0x2_0000;

    let address = guest.call("VirtualAlloc", &[0, 0x2000, COMMIT_RESERVE, READ_WRITE]);
    assert_ne!(address, 0);
    guest.memory.write_u8(address, 0x11).unwrap();
    guest.memory.write_u8(address + 0x1000, 0x22).unwrap();

    assert_eq!(
        guest.call("VirtualQuery", &[address + 0x123, SCRATCH, 48]),
        48
    );
    assert_eq!(guest.memory.read_u64(SCRATCH).unwrap(), address);
    assert_eq!(guest.memory.read_u64(SCRATCH + 8).unwrap(), address);
    assert_eq!(
        guest.memory.read_u32(SCRATCH + 16).unwrap(),
        READ_WRITE as u32
    );
    assert_eq!(guest.memory.read_u64(SCRATCH + 24).unwrap(), 0x2000);
    assert_eq!(guest.memory.read_u32(SCRATCH + 32).unwrap(), MEM_COMMIT);
    assert_eq!(
        guest.memory.read_u32(SCRATCH + 36).unwrap(),
        READ_WRITE as u32
    );
    assert_eq!(guest.memory.read_u32(SCRATCH + 40).unwrap(), MEM_PRIVATE);

    // A short output buffer receives only the requested prefix and returns
    // the number of bytes actually copied.
    guest.memory.write_bytes(SCRATCH, &[0xA5; 48]).unwrap();
    assert_eq!(guest.call("VirtualQuery", &[address, SCRATCH, 20]), 20);
    assert_eq!(guest.memory.read_u64(SCRATCH).unwrap(), address);
    assert_eq!(
        guest.memory.read_u32(SCRATCH + 16).unwrap(),
        READ_WRITE as u32
    );

    // A range ending one byte into the second page covers both pages.
    assert_eq!(
        guest.call(
            "VirtualProtect",
            &[address + 0xfff, 2, NO_ACCESS, SCRATCH + 0x40],
        ),
        1
    );
    assert_eq!(
        guest.memory.read_u32(SCRATCH + 0x40).unwrap(),
        READ_WRITE as u32
    );
    assert!(guest.memory.read_u8(address).is_err());
    assert!(guest.memory.write_u8(address + 0x1000, 0x33).is_err());

    // Committed no-access memory is still queryable.
    assert_eq!(guest.call("VirtualQuery", &[address, SCRATCH, 48]), 48);
    assert_eq!(
        guest.memory.read_u32(SCRATCH + 36).unwrap(),
        NO_ACCESS as u32
    );

    // Restore read-write through the same service, then split the allocation
    // into a read-only first page and a read-write second page.
    assert_eq!(
        guest.call(
            "VirtualProtect",
            &[address, 0x2000, READ_WRITE, SCRATCH + 0x40],
        ),
        1
    );
    assert_eq!(
        guest.call(
            "VirtualProtect",
            &[address, 0x1000, READ_ONLY, SCRATCH + 0x40],
        ),
        1
    );
    assert!(guest.memory.write_u8(address, 0x44).is_err());
    assert_eq!(guest.memory.read_u8(address).unwrap(), 0x11);
    guest.memory.write_u8(address + 0x1000, 0x55).unwrap();
    assert_eq!(guest.call("VirtualQuery", &[address, SCRATCH, 48]), 48);
    assert_eq!(
        guest.memory.read_u32(SCRATCH + 36).unwrap(),
        READ_ONLY as u32
    );
    assert_eq!(
        guest.call("VirtualQuery", &[address + 0x1000, SCRATCH, 48]),
        48
    );
    assert_eq!(
        guest.memory.read_u32(SCRATCH + 36).unwrap(),
        READ_WRITE as u32
    );

    // Releasing the original base removes every split piece of the virtual
    // allocation, not only the piece that still starts at that base.
    assert_eq!(guest.call("VirtualFree", &[address, 0, 0x8000]), 1);
    assert!(guest.memory.read_u8(address).is_err());
    assert!(guest.memory.read_u8(address + 0x1000).is_err());
}

/// Invalid protection changes neither write the old-protection output nor
/// partially change the committed pages they overlap.
#[test]
fn virtual_memory_protect_failures_leave_memory_unchanged() {
    let mut guest = Guest::new();
    const COMMIT_RESERVE: u64 = 0x3000;
    const NO_ACCESS: u64 = 0x01;
    const READ_WRITE: u64 = 0x04;
    const EXECUTE_READWRITE: u64 = 0x40;
    let address = guest.call("VirtualAlloc", &[0, 0x2000, COMMIT_RESERVE, READ_WRITE]);
    assert_ne!(address, 0);
    guest.memory.write_u8(address, 0x77).unwrap();

    for (args, error) in [
        // Zero size and a null output pointer are invalid parameters.
        ([address, 0, READ_WRITE, SCRATCH + 0x40], 87),
        ([address, 0x1000, READ_WRITE, 0], 87),
        // Executable translations need cache invalidation and are explicitly
        // outside this non-executable protection slice.
        ([address, 0x1000, EXECUTE_READWRITE, SCRATCH + 0x40], 50),
        ([address, 0x1000, 0xffff, SCRATCH + 0x40], 87),
        // The second page is committed but the third page is a hole, so this
        // range is not completely committed.
        ([address + 0x1000, 0x1001, NO_ACCESS, SCRATCH + 0x40], 487),
        // The old-protection output itself must be writable.
        ([address, 0x1000, READ_WRITE, 0x9000_0000], 487),
    ] {
        guest.memory.write_u32(SCRATCH + 0x40, 0xA5A5_A5A5).unwrap();
        assert_eq!(guest.call("VirtualProtect", &args), 0, "{args:x?}");
        assert_eq!(guest.last_error(), error, "{args:x?}");
        assert_eq!(
            guest.memory.read_u32(SCRATCH + 0x40).unwrap(),
            0xA5A5_A5A5,
            "{args:x?}"
        );
        assert_eq!(guest.memory.read_u8(address).unwrap(), 0x77, "{args:x?}");
        guest.memory.write_u8(address + 0x1000, 0x66).unwrap();
    }

    assert_eq!(
        guest.call("VirtualQuery", &[address + 0x2000, SCRATCH, 48]),
        0
    );
    assert_eq!(guest.last_error(), 487);
    assert_eq!(guest.call("VirtualQuery", &[address, SCRATCH, 0]), 0);
    assert_eq!(guest.last_error(), 87);
}

/// Static image-style memory is committed guest memory too. It can be queried
/// and protected when the page-rounded range is completely backed.
#[test]
fn virtual_memory_services_cover_static_committed_regions() {
    let mut guest = Guest::new();
    const STATIC: u64 = 0x70000;
    const NO_ACCESS: u64 = 0x01;
    guest
        .memory
        .map_region(STATIC, 0x2000, MemoryPermissions::READ_WRITE)
        .unwrap();
    assert_eq!(guest.call("VirtualQuery", &[STATIC + 1, SCRATCH, 48]), 48);
    assert_eq!(guest.memory.read_u64(SCRATCH).unwrap(), STATIC);
    assert_eq!(guest.memory.read_u32(SCRATCH + 40).unwrap(), 0x2_0000);
    assert_eq!(
        guest.call(
            "VirtualProtect",
            &[STATIC, 0x1000, NO_ACCESS, SCRATCH + 0x40]
        ),
        1
    );
    assert!(guest.memory.read_u8(STATIC).is_err());
    guest.memory.write_u8(STATIC + 0x1000, 1).unwrap();
}

/// `__C_specific_handler` (a partial service) resolves by the module and
/// symbol pairs a program built with mingw-w64 14.0.0 (UCRT) imports it by.
#[test]
fn memory_and_exception_services_bind_and_are_declared() {
    let (registry, _) = standard(0);
    let named = |name: &str| ImportName::Name(name.to_owned());
    for (module, symbol, canonical) in [
        ("KERNEL32.dll", "VirtualProtect", "kernel32.dll"),
        ("KERNEL32.dll", "VirtualQuery", "kernel32.dll"),
        (
            "api-ms-win-core-memory-l1-1-0.dll",
            "VirtualProtect",
            "kernel32.dll",
        ),
        (
            "api-ms-win-core-memory-l1-1-0.dll",
            "VirtualQuery",
            "kernel32.dll",
        ),
    ] {
        let service = registry
            .resolve(module, &named(symbol))
            .unwrap_or_else(|| panic!("{module}!{symbol}"));
        let target = registry.resolve(canonical, &named(symbol)).unwrap();
        assert!(std::ptr::eq(service, target), "{module}!{symbol}");
        assert_eq!(service.status, ServiceStatus::Partial, "{symbol}");
    }
    let handler = registry
        .resolve(
            "api-ms-win-crt-private-l1-1-0.dll",
            &named("__C_specific_handler"),
        )
        .expect("api-ms-win-crt-private-l1-1-0.dll!__C_specific_handler");
    let canonical = registry
        .resolve("ucrtbase.dll", &named("__C_specific_handler"))
        .unwrap();
    assert!(std::ptr::eq(handler, canonical));
    assert_eq!(handler.status, ServiceStatus::Partial);
    for (module, symbol) in [
        ("api-ms-win-crt-private-l1-1-0.dll", "VirtualProtect"),
        ("api-ms-win-core-memory-l1-1-0.dll", "__C_specific_handler"),
        ("kernel32.dll", "__C_specific_handler"),
    ] {
        assert!(
            registry.resolve(module, &named(symbol)).is_none(),
            "{module}!{symbol}"
        );
    }
    assert!(
        SERVICES
            .iter()
            .all(|service| service.status != ServiceStatus::Stub),
        "no generated service remains a declared stop-the-guest stub"
    );
}

#[test]
fn floating_arguments_and_results_use_xmm_registers() {
    let mut guest = Guest::new();
    let mut float = |symbol: &str, bits: u64| {
        // Only the low lane is the argument, and RCX must be ignored.
        guest.xmm[0] = 0xFFFF_FFFF_FFFF_FFFF << 64 | u128::from(bits);
        let (cpu, exit) = guest.run(symbol, &[0x4022_0000_0000_0000]);
        assert_eq!(exit, ExitReason::Halt);
        cpu.xmm[0]
    };
    assert_eq!(
        float("sqrt", 0x4030_0000_0000_0000) as u64,
        0x4010_0000_0000_0000
    ); // 16 -> 4
    assert_eq!(
        float("sqrt", 0x4000_0000_0000_0000) as u64,
        0x3FF6_A09E_667F_3BCD
    ); // sqrt 2
    assert_eq!(
        float("sqrt", 0x8000_0000_0000_0000) as u64,
        0x8000_0000_0000_0000
    ); // -0
    assert_eq!(
        float("sqrt", 0x7FF0_0000_0000_0000) as u64,
        0x7FF0_0000_0000_0000
    );
    let nan = float("sqrt", 0xBFF0_0000_0000_0000) as u64;
    assert!(f64::from_bits(nan).is_nan());
    assert_eq!(
        float("fabs", 0xC004_0000_0000_0000) as u64,
        0x4004_0000_0000_0000
    ); // -2.5
    assert_eq!(float("fabs", 0x8000_0000_0000_0000) as u64, 0);
    let garbage = 0xDEAD_BEEF_0000_0000;
    assert_eq!(float("sqrtf", garbage | 0x4110_0000) as u32, 0x4040_0000); // 9 -> 3
    assert_eq!(float("fabsf", garbage | 0xBF80_0000) as u32, 0x3F80_0000); // -1
}

// The rest of math.h (#468). Expected values are not computed by the code
// under test: the exact functions' by hand from IEC 60559 (cross-checked with
// Python's `fractions`), the host functions' with mpmath 1.4.1 at 200 bits and
// rounded once to the nearest double or float.

/// Calls a math service with up to two float arguments and returns XMM0.
fn math_call(guest: &mut Guest, symbol: &str, arguments: &[u64], integers: &[u64]) -> u128 {
    let junk = 0xDEAD_BEEF_0BAD_F00D_u128 << 64;
    for (lane, bits) in guest.xmm.iter_mut().zip(arguments) {
        *lane = junk | u128::from(*bits);
    }
    let (cpu, exit) = guest.run(symbol, integers);
    assert_eq!(exit, ExitReason::Halt, "{symbol}");
    cpu.xmm[0]
}

fn math64(guest: &mut Guest, symbol: &str, arguments: &[f64]) -> u64 {
    let bits: Vec<u64> = arguments.iter().map(|x| x.to_bits()).collect();
    math_call(guest, symbol, &bits, &[0x4022_0000_0000_0000]) as u64
}

fn math32(guest: &mut Guest, symbol: &str, arguments: &[f32]) -> u32 {
    let bits: Vec<u64> = arguments
        .iter()
        .map(|x| u64::from(x.to_bits()) | 0xDEAD_0000_0000)
        .collect();
    math_call(guest, symbol, &bits, &[]) as u32
}

/// Distance in units in the last place between two doubles of the same sign.
fn ulps64(a: u64, b: u64) -> u64 {
    assert_eq!(a >> 63, b >> 63, "{a:#018X} {b:#018X}");
    a.abs_diff(b)
}

fn ulps32(a: u32, b: u32) -> u32 {
    assert_eq!(a >> 31, b >> 31, "{a:#010X} {b:#010X}");
    a.abs_diff(b)
}

#[test]
fn crt_math_exact_functions_match_hand_derived_values() {
    let mut guest = Guest::new();
    let neg_zero = (-0.0f64).to_bits();
    let cases: &[(&str, &[f64], u64)] = &[
        ("ceil", &[-0.5], neg_zero),
        ("ceil", &[1.000_000_000_000_000_2], 2.0f64.to_bits()),
        ("floor", &[-0.5], (-1.0f64).to_bits()),
        (
            "floor",
            &[4_503_599_627_370_495.5],
            4_503_599_627_370_495.0f64.to_bits(),
        ),
        ("trunc", &[-1.9], (-1.0f64).to_bits()),
        ("trunc", &[-0.3], neg_zero),
        // Ties away from zero, and the largest double below 0.5.
        ("round", &[0.5], 1.0f64.to_bits()),
        ("round", &[-2.5], (-3.0f64).to_bits()),
        ("round", &[0.499_999_999_999_999_94], 0),
        (
            "round",
            &[4_503_599_627_370_497.0],
            4_503_599_627_370_497.0f64.to_bits(),
        ),
        // Ties to even.
        ("rint", &[2.5], 2.0f64.to_bits()),
        ("rint", &[3.5], 4.0f64.to_bits()),
        ("rint", &[-0.5], neg_zero),
        ("nearbyint", &[0.5], 0),
        ("nearbyint", &[-1.5], (-2.0f64).to_bits()),
        ("copysign", &[3.0, -0.0], (-3.0f64).to_bits()),
        ("copysign", &[-3.0, 0.0], 3.0f64.to_bits()),
        ("fmod", &[5.5, 2.0], 1.5f64.to_bits()),
        ("fmod", &[-5.5, 2.0], (-1.5f64).to_bits()),
        ("fmod", &[-4.0, 2.0], neg_zero),
        ("fmod", &[0.1, 1e-300], 0x0177_350D_4134_AEC0),
        ("fmod", &[1e308, 1e-308], 0x0002_8401_CF53_D610),
        ("remainder", &[5.0, 2.0], 1.0f64.to_bits()),
        ("remainder", &[7.0, 2.0], (-1.0f64).to_bits()),
        ("remainder", &[-7.0, 2.0], 1.0f64.to_bits()),
        ("remainder", &[6.5, 1.0], 0.5f64.to_bits()),
        ("remainder", &[7.5, 1.0], (-0.5f64).to_bits()),
        ("remainder", &[-4.0, 2.0], neg_zero),
        ("remainder", &[1e300, 7e-300], 0x81AC_E4A3_2878_D880),
        // MAX = 2^1024 - 2^971 is nearer 2 * 2^1023 than 1 * 2^1023.
        (
            "remainder",
            &[f64::MAX, 2f64.powi(1023)],
            (-(2f64.powi(971))).to_bits(),
        ),
        ("fdim", &[3.0, 1.0], 2.0f64.to_bits()),
        ("fdim", &[1.0, 3.0], 0),
        ("fdim", &[f64::MAX, -f64::MAX], f64::INFINITY.to_bits()),
        ("fmax", &[-0.0, 0.0], 0),
        ("fmax", &[0.0, -0.0], 0),
        ("fmax", &[-1.0, 2.0], 2.0f64.to_bits()),
        ("fmin", &[0.0, -0.0], neg_zero),
        ("fmin", &[-0.0, 0.0], neg_zero),
        ("fmin", &[-1.0, 2.0], (-1.0f64).to_bits()),
    ];
    for (symbol, arguments, expected) in cases {
        let actual = math64(&mut guest, symbol, arguments);
        assert_eq!(actual, *expected, "{symbol}{arguments:?}: {actual:#018X}");
    }
    let cases32: &[(&str, &[f32], u32)] = &[
        ("ceilf", &[1.5], 2.0f32.to_bits()),
        ("ceilf", &[-0.5], (-0.0f32).to_bits()),
        ("floorf", &[-1.5], (-2.0f32).to_bits()),
        ("roundf", &[-0.5], (-1.0f32).to_bits()),
        ("roundf", &[0.499_999_97], 0),
        ("fmodf", &[5.5, 2.0], 1.5f32.to_bits()),
        ("fmodf", &[-7.0, 0.75], (-0.25f32).to_bits()),
    ];
    for (symbol, arguments, expected) in cases32 {
        let actual = math32(&mut guest, symbol, arguments);
        assert_eq!(actual, *expected, "{symbol}{arguments:?}: {actual:#010X}");
    }
}

#[test]
fn crt_math_special_values_follow_annex_f() {
    let mut guest = Guest::new();
    let (inf, nan) = (f64::INFINITY, f64::NAN);
    let half_pi = std::f64::consts::FRAC_PI_2;
    let pi = std::f64::consts::PI;
    // ISO C Annex F (F.10) special cases, as values.
    let cases: &[(&str, &[f64], f64)] = &[
        ("acos", &[1.0], 0.0),
        ("asin", &[-0.0], -0.0),
        ("atan", &[-0.0], -0.0),
        ("atan", &[-inf], -half_pi),
        ("atan2", &[0.0, -0.0], pi),
        ("atan2", &[-0.0, -0.0], -pi),
        ("atan2", &[-0.0, 0.0], -0.0),
        ("atan2", &[1.0, -inf], pi),
        ("atan2", &[-1.0, inf], -0.0),
        ("atan2", &[inf, 5.0], half_pi),
        ("atan2", &[inf, inf], std::f64::consts::FRAC_PI_4),
        ("cos", &[-0.0], 1.0),
        ("sin", &[-0.0], -0.0),
        ("tan", &[-0.0], -0.0),
        ("cosh", &[-0.0], 1.0),
        ("cosh", &[-inf], inf),
        ("sinh", &[-0.0], -0.0),
        ("sinh", &[-inf], -inf),
        ("tanh", &[-0.0], -0.0),
        ("tanh", &[-inf], -1.0),
        ("cbrt", &[-0.0], -0.0),
        ("cbrt", &[-inf], -inf),
        ("exp", &[-0.0], 1.0),
        ("exp", &[-inf], 0.0),
        ("exp", &[inf], inf),
        ("exp", &[710.0], inf),
        ("exp2", &[-inf], 0.0),
        ("exp2", &[1024.0], inf),
        ("exp2", &[-1074.0], f64::from_bits(1)),
        ("expm1", &[-0.0], -0.0),
        ("expm1", &[-inf], -1.0),
        ("log", &[-0.0], -inf),
        ("log", &[1.0], 0.0),
        ("log", &[inf], inf),
        ("log10", &[0.0], -inf),
        ("log10", &[1000.0], 3.0),
        ("log2", &[-0.0], -inf),
        ("log2", &[f64::from_bits(1)], -1074.0),
        ("log1p", &[-0.0], -0.0),
        ("log1p", &[-1.0], -inf),
        ("log1p", &[inf], inf),
        ("erf", &[-0.0], -0.0),
        ("erf", &[-inf], -1.0),
        ("tgamma", &[0.0], inf),
        ("tgamma", &[-0.0], -inf),
        ("tgamma", &[inf], inf),
        ("tgamma", &[5.0], 24.0),
        ("tgamma", &[172.0], inf),
        ("hypot", &[-0.0, -0.0], 0.0),
        ("hypot", &[-inf, nan], inf),
        ("hypot", &[nan, inf], inf),
        ("hypot", &[-5.0, 0.0], 5.0),
        ("pow", &[nan, -0.0], 1.0),
        ("pow", &[1.0, nan], 1.0),
        ("pow", &[-1.0, -inf], 1.0),
        ("pow", &[-0.0, -3.0], -inf),
        ("pow", &[0.0, -2.0], inf),
        ("pow", &[-0.0, 3.0], -0.0),
        ("pow", &[-2.0, 3.0], -8.0),
        ("pow", &[0.5, -inf], inf),
        ("pow", &[-inf, -3.0], -0.0),
        ("pow", &[inf, -1.0], 0.0),
        ("ceil", &[-inf], -inf),
        ("floor", &[-0.0], -0.0),
        ("trunc", &[inf], inf),
        ("round", &[-0.0], -0.0),
        ("rint", &[-inf], -inf),
        ("nearbyint", &[-0.0], -0.0),
        ("fmod", &[-0.0, 3.0], -0.0),
        ("fmod", &[2.5, -inf], 2.5),
        ("remainder", &[-0.0, 3.0], -0.0),
        ("remainder", &[2.5, inf], 2.5),
        ("fmax", &[nan, -1.0], -1.0),
        ("fmin", &[-1.0, nan], -1.0),
        ("fdim", &[inf, inf], 0.0),
        ("copysign", &[inf, -0.0], -inf),
    ];
    for (symbol, arguments, expected) in cases {
        let actual = math64(&mut guest, symbol, arguments);
        assert_eq!(
            actual,
            expected.to_bits(),
            "{symbol}{arguments:?}: {actual:#018X}"
        );
    }
    // Domain errors return the x86 default NaN.
    let default_nan = 0xFFF8_0000_0000_0000;
    let domain: &[(&str, &[f64])] = &[
        ("acos", &[1.5]),
        ("asin", &[-inf]),
        ("cos", &[inf]),
        ("sin", &[-inf]),
        ("tan", &[inf]),
        ("log", &[-1.0]),
        ("log10", &[-inf]),
        ("log2", &[-0.5]),
        ("log1p", &[-2.0]),
        ("tgamma", &[-1.0]),
        ("tgamma", &[-inf]),
        ("pow", &[-8.0, 1.0 / 3.0]),
        ("fmod", &[inf, 1.0]),
        ("fmod", &[1.0, 0.0]),
        ("remainder", &[1.0, 0.0]),
        ("remainder", &[-inf, 1.0]),
    ];
    for (symbol, arguments) in domain {
        let actual = math64(&mut guest, symbol, arguments);
        assert_eq!(actual, default_nan, "{symbol}{arguments:?}: {actual:#018X}");
    }
    // A NaN argument comes back quieted, payload and sign kept.
    let signaling = 0x7FF0_0000_0000_0123;
    for symbol in [
        "exp", "sin", "log", "floor", "rint", "erf", "tgamma", "atan",
    ] {
        let actual = math_call(&mut guest, symbol, &[signaling], &[]) as u64;
        assert_eq!(actual, 0x7FF8_0000_0000_0123, "{symbol}");
    }
    let quiet_negative = 0xFFF8_0000_0000_0456;
    for symbol in ["pow", "atan2", "fmod", "remainder", "hypot", "fdim", "fmax"] {
        let actual = math_call(&mut guest, symbol, &[quiet_negative, quiet_negative], &[]) as u64;
        assert_eq!(actual, quiet_negative, "{symbol}");
    }
    // copysign does not quiet: it only moves a bit.
    let actual = math_call(
        &mut guest,
        "copysign",
        &[signaling, (-1.0f64).to_bits()],
        &[],
    ) as u64;
    assert_eq!(actual, signaling | 1 << 63);
    // The float forms.
    let cases32: &[(&str, &[f32], f32)] = &[
        ("cosf", &[-0.0], 1.0),
        ("sinf", &[-0.0], -0.0),
        ("tanf", &[-0.0], -0.0),
        ("expf", &[-f32::INFINITY], 0.0),
        ("expf", &[89.0], f32::INFINITY),
        ("logf", &[0.0], -f32::INFINITY),
        ("logf", &[1.0], 0.0),
        ("powf", &[f32::NAN, 0.0], 1.0),
        ("powf", &[-2.0, 3.0], -8.0),
        ("ceilf", &[-0.0], -0.0),
        ("floorf", &[f32::INFINITY], f32::INFINITY),
        ("roundf", &[-0.0], -0.0),
        ("fmodf", &[-0.0, 1.0], -0.0),
    ];
    for (symbol, arguments, expected) in cases32 {
        let actual = math32(&mut guest, symbol, arguments);
        assert_eq!(
            actual,
            expected.to_bits(),
            "{symbol}{arguments:?}: {actual:#010X}"
        );
    }
    // Annex F gives atan2f(-0, -0) = -pi. The macOS host library returns the
    // float just inside the range, 0xC0490FDA, one ulp from the nearest one.
    let actual = math32(&mut guest, "atan2f", &[-0.0, -0.0]);
    assert!(
        ulps32(actual, (-std::f32::consts::PI).to_bits()) <= 1,
        "{actual:#010X}"
    );
    for (symbol, arguments) in [
        ("logf", &[-1.0f32][..]),
        ("fmodf", &[1.0, 0.0]),
        ("sinf", &[f32::INFINITY]),
    ] {
        assert_eq!(
            math32(&mut guest, symbol, arguments),
            0xFFC0_0000,
            "{symbol}"
        );
    }
}

#[test]
fn crt_math_host_functions_are_within_one_ulp_of_reference() {
    const HOST64: &[(&str, u64, u64, u64)] = &[
        (
            "acos",
            0x3FD3333333333333,
            0x0000000000000000,
            0x3FF441F5ECBEEF59,
        ), // acos(0.3)
        (
            "acos",
            0xBFE6666666666666,
            0x0000000000000000,
            0x4002C501446CD5F1,
        ), // acos(-0.7)
        (
            "acos",
            0x3FEFAE147AE147AE,
            0x0000000000000000,
            0x3FC21DF72882BFD8,
        ), // acos(0.99)
        (
            "asin",
            0x3FD3333333333333,
            0x0000000000000000,
            0x3FD380159E14F6FF,
        ), // asin(0.3)
        (
            "asin",
            0xBFE0000000000000,
            0x0000000000000000,
            0xBFE0C152382D7366,
        ), // asin(-0.5)
        (
            "asin",
            0x3DDB7CDFD9D7BDBB,
            0x0000000000000000,
            0x3DDB7CDFD9D7BDBB,
        ), // asin(1e-10)
        (
            "atan",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FDDAC670561BB4F,
        ), // atan(0.5)
        (
            "atan",
            0xC008000000000000,
            0x0000000000000000,
            0xBFF3FC176B7A8560,
        ), // atan(-3.0)
        (
            "atan",
            0x412E848000000000,
            0x0000000000000000,
            0x3FF921FA47D4B30D,
        ), // atan(1000000.0)
        (
            "cbrt",
            0x4000000000000000,
            0x0000000000000000,
            0x3FF428A2F98D728B,
        ), // cbrt(2.0)
        (
            "cbrt",
            0xC03B800000000000,
            0x0000000000000000,
            0xC00825B1B6BAC03B,
        ), // cbrt(-27.5)
        (
            "cbrt",
            0x01A56E1FC2F8F359,
            0x0000000000000000,
            0x2B2BFF2EE48E0530,
        ), // cbrt(1e-300)
        (
            "cos",
            0x3FF0000000000000,
            0x0000000000000000,
            0x3FE14A280FB5068C,
        ), // cos(1.0)
        (
            "cos",
            0x4059000000000000,
            0x0000000000000000,
            0x3FEB981DBF665FDF,
        ), // cos(100.0)
        (
            "cos",
            0x4480F0CF064DD592,
            0x0000000000000000,
            0x3FE0BE2CEF01C8F4,
        ), // cos(1e+22)
        (
            "cosh",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FF20AC1862AE8D0,
        ), // cosh(0.5)
        (
            "cosh",
            0xC008000000000000,
            0x0000000000000000,
            0x402422A497D6185E,
        ), // cosh(-3.0)
        (
            "cosh",
            0x4085E00000000000,
            0x0000000000000000,
            0x7EFD945DF4F8EC8E,
        ), // cosh(700.0)
        (
            "erf",
            0x3FB999999999999A,
            0x0000000000000000,
            0x3FBCCA5EA24FB334,
        ), // erf(0.1)
        (
            "erf",
            0xBFF8000000000000,
            0x0000000000000000,
            0xBFEEEA5557137AE0,
        ), // erf(-1.5)
        (
            "erf",
            0x4008000000000000,
            0x0000000000000000,
            0x3FEFFFD1AC4135F9,
        ), // erf(3.0)
        (
            "exp",
            0x3FF0000000000000,
            0x0000000000000000,
            0x4005BF0A8B145769,
        ), // exp(1.0)
        (
            "exp",
            0xC024000000000000,
            0x0000000000000000,
            0x3F07CD79B5647C9B,
        ), // exp(-10.0)
        (
            "exp",
            0x4085E00000000000,
            0x0000000000000000,
            0x7F0D945DF4F8EC8E,
        ), // exp(700.0)
        (
            "exp2",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FF6A09E667F3BCD,
        ), // exp2(0.5)
        (
            "exp2",
            0xC090BA0000000000,
            0x0000000000000000,
            0x000000000000000B,
        ), // exp2(-1070.5)
        (
            "exp2",
            0x402499999999999A,
            0x0000000000000000,
            0x4093B2C47BFF832C,
        ), // exp2(10.3)
        (
            "expm1",
            0x3DDB7CDFD9D7BDBB,
            0x0000000000000000,
            0x3DDB7CDFD9DDA4E3,
        ), // expm1(1e-10)
        (
            "expm1",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FE4C2531C3C0D38,
        ), // expm1(0.5)
        (
            "expm1",
            0xC000000000000000,
            0x0000000000000000,
            0xBFEBAB5557101F8D,
        ), // expm1(-2.0)
        (
            "log",
            0x4000000000000000,
            0x0000000000000000,
            0x3FE62E42FEFA39EF,
        ), // log(2.0)
        (
            "log",
            0x01A56E1FC2F8F359,
            0x0000000000000000,
            0xC085963447F87FB5,
        ), // log(1e-300)
        (
            "log",
            0x3FEFF7CED916872B,
            0x0000000000000000,
            0xBF5064670D979B73,
        ), // log(0.999)
        (
            "log10",
            0x4000000000000000,
            0x0000000000000000,
            0x3FD34413509F79FF,
        ), // log10(2.0)
        (
            "log10",
            0x3F12599ED7C6FBD2,
            0x0000000000000000,
            0xC0109E9E9E90E678,
        ), // log10(7e-05)
        (
            "log10",
            0x4480F0CF064DD592,
            0x0000000000000000,
            0x4036000000000000,
        ), // log10(1e+22)
        (
            "log1p",
            0x3CD203AF9EE75616,
            0x0000000000000000,
            0x3CD203AF9EE75613,
        ), // log1p(1e-15)
        (
            "log1p",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FD9F323ECBF984C,
        ), // log1p(0.5)
        (
            "log1p",
            0xBFE0000000000000,
            0x0000000000000000,
            0xBFE62E42FEFA39EF,
        ), // log1p(-0.5)
        (
            "log2",
            0x4008000000000000,
            0x0000000000000000,
            0x3FF95C01A39FBD68,
        ), // log2(3.0)
        (
            "log2",
            0x54B249AD2594C37D,
            0x0000000000000000,
            0x4074C315BF6707B1,
        ), // log2(1e+100)
        (
            "log2",
            0x3FB999999999999A,
            0x0000000000000000,
            0xC00A934F0979A371,
        ), // log2(0.1)
        (
            "sin",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FDEAEE8744B05F0,
        ), // sin(0.5)
        (
            "sin",
            0x400921FB54442D18,
            0x0000000000000000,
            0x3CA1A62633145C07,
        ), // sin(3.141592653589793)
        (
            "sin",
            0x4480F0CF064DD592,
            0x0000000000000000,
            0xBFEB453AB76BF397,
        ), // sin(1e+22)
        (
            "sinh",
            0x3EE4F8B588E368F1,
            0x0000000000000000,
            0x3EE4F8B588E4E940,
        ), // sinh(1e-05)
        (
            "sinh",
            0x4000000000000000,
            0x0000000000000000,
            0x400D03CF63B6E19F,
        ), // sinh(2.0)
        (
            "sinh",
            0xC085E00000000000,
            0x0000000000000000,
            0xFEFD945DF4F8EC8E,
        ), // sinh(-700.0)
        (
            "tan",
            0x3FF0000000000000,
            0x0000000000000000,
            0x3FF8EB245CBEE3A6,
        ), // tan(1.0)
        (
            "tan",
            0x3FF921FB54442D18,
            0x0000000000000000,
            0x434D02967C31CDB5,
        ), // tan(1.5707963267948966)
        (
            "tan",
            0xBFE0000000000000,
            0x0000000000000000,
            0xBFE17B4F5BF3474A,
        ), // tan(-0.5)
        (
            "tanh",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FDD9353D7568AF3,
        ), // tanh(0.5)
        (
            "tanh",
            0xC000000000000000,
            0x0000000000000000,
            0xBFEED9505E1BC3D4,
        ), // tanh(-2.0)
        (
            "tanh",
            0x3E45798EE2308C3A,
            0x0000000000000000,
            0x3E45798EE2308C3A,
        ), // tanh(1e-08)
        (
            "tgamma",
            0x3FE0000000000000,
            0x0000000000000000,
            0x3FFC5BF891B4EF6B,
        ), // tgamma(0.5)
        (
            "tgamma",
            0x4016000000000000,
            0x0000000000000000,
            0x404A2BE0247739F2,
        ), // tgamma(5.5)
        (
            "tgamma",
            0xC004000000000000,
            0x0000000000000000,
            0xBFEE3FF812E32183,
        ), // tgamma(-2.5)
        (
            "tgamma",
            0x4065500000000000,
            0x0000000000000000,
            0x7F69589F849167A8,
        ), // tgamma(170.5)
        (
            "atan2",
            0x3FF0000000000000,
            0x4000000000000000,
            0x3FDDAC670561BB4F,
        ), // atan2(1.0, 2.0)
        (
            "atan2",
            0xBFF0000000000000,
            0xC000000000000000,
            0xC0056C6E7397F5AE,
        ), // atan2(-1.0, -2.0)
        (
            "atan2",
            0x3FE0000000000000,
            0xBF1A36E2EB1C432D,
            0x3FF922CD0B5B5711,
        ), // atan2(0.5, -0.0001)
        (
            "hypot",
            0x4008000000000000,
            0x4010000000000000,
            0x4014000000000000,
        ), // hypot(3.0, 4.0)
        (
            "hypot",
            0x7E37E43C8800759C,
            0x7E37E43C8800759C,
            0x7E40E4D50F99B211,
        ), // hypot(1e+300, 1e+300)
        (
            "hypot",
            0x000012688B70E62B,
            0x000024D116E1CC56,
            0x0000292991FDAE04,
        ), // hypot(1e-310, 2e-310)
        (
            "pow",
            0x4000000000000000,
            0x3FE0000000000000,
            0x3FF6A09E667F3BCD,
        ), // pow(2.0, 0.5)
        (
            "pow",
            0x3FF8000000000000,
            0x4059000000000000,
            0x43969194F299CDDA,
        ), // pow(1.5, 100.0)
        (
            "pow",
            0x3FECCCCCCCCCCCCD,
            0xC08F400000000000,
            0x497008CAC83EB741,
        ), // pow(0.9, -1000.0)
    ];
    const HOST32: &[(&str, u32, u32, u32)] = &[
        ("cosf", 0x3F000000, 0x00000000, 0x3F60A940), // cosf(0.5f)
        ("cosf", 0x42C80000, 0x00000000, 0x3F5CC0EE), // cosf(100.0f)
        ("expf", 0x3F800000, 0x00000000, 0x402DF854), // expf(1.0f)
        ("expf", 0xC1A00000, 0x00000000, 0x310DA433), // expf(-20.0f)
        ("logf", 0x40000000, 0x00000000, 0x3F317218), // logf(2.0f)
        ("logf", 0x0DA24260, 0x00000000, 0xC28A27B5), // logf(1.0000000031710769e-30f)
        ("sinf", 0x3F000000, 0x00000000, 0x3EF57744), // sinf(0.5f)
        ("sinf", 0x501502F9, 0x00000000, 0xBEF99A64), // sinf(10000000000.0f)
        ("tanf", 0x3F800000, 0x00000000, 0x3FC75923), // tanf(1.0f)
        ("tanf", 0xBE800000, 0x00000000, 0xBE82BC2D), // tanf(-0.25f)
        ("atan2f", 0x3F800000, 0x40000000, 0x3EED6338), // atan2f(1.0f, 2.0f)
        ("atan2f", 0xC0400000, 0x3F000000, 0xBFB3EC43), // atan2f(-3.0f, 0.5f)
        ("powf", 0x40000000, 0x3F000000, 0x3FB504F3), // powf(2.0f, 0.5f)
        ("powf", 0x3F8CCCCD, 0x42480000, 0x42EAC82F), // powf(1.100000023841858f, 50.0f)
    ];
    let mut guest = Guest::new();
    for (symbol, x, y, reference) in HOST64 {
        let actual = math_call(&mut guest, symbol, &[*x, *y], &[]) as u64;
        let distance = ulps64(actual, *reference);
        assert!(
            distance <= 1,
            "{symbol}({x:#018X}, {y:#018X}) = {actual:#018X}, reference {reference:#018X}"
        );
    }
    for (symbol, x, y, reference) in HOST32 {
        let actual = math_call(&mut guest, symbol, &[u64::from(*x), u64::from(*y)], &[]) as u32;
        let distance = ulps32(actual, *reference);
        assert!(
            distance <= 1,
            "{symbol}({x:#010X}, {y:#010X}) = {actual:#010X}, reference {reference:#010X}"
        );
    }
}

#[test]
fn crt_math_frexp_and_modf_store_through_guest_pointers() {
    let mut guest = Guest::new();
    let split = |guest: &mut Guest, symbol: &str, x: f64| {
        guest.memory.write_bytes(SCRATCH, &[0xAB; 8]).unwrap();
        let result = math_call(guest, symbol, &[x.to_bits()], &[JUNK_HIGH, SCRATCH]) as u64;
        let mut stored = [0; 8];
        guest.memory.read_bytes(SCRATCH, &mut stored).unwrap();
        (result, stored)
    };
    for (x, fraction, exponent) in [
        (8.0, 0.5, 4),
        (-0.75, -0.75, 0),
        (f64::MAX, 1.0 - f64::EPSILON / 2.0, 1024),
        (f64::from_bits(1), 0.5, -1073),
        (
            -f64::from_bits(0x000F_FFFF_FFFF_FFFF),
            -(1.0 - f64::EPSILON),
            -1022,
        ),
        (-0.0, -0.0, 0),
        (f64::INFINITY, f64::INFINITY, 0),
    ] {
        let (result, stored) = split(&mut guest, "frexp", x);
        assert_eq!(result, f64::to_bits(fraction), "frexp({x})");
        assert_eq!(stored[..4], i32::to_le_bytes(exponent), "frexp({x})");
        assert_eq!(stored[4..], [0xAB; 4], "frexp({x}) wrote past the int");
    }
    let (result, stored) = split(&mut guest, "frexp", f64::NAN);
    assert!(f64::from_bits(result).is_nan());
    assert_eq!(stored[..4], [0; 4]);
    for (x, fraction, integral) in [
        (-3.75, -0.75, -3.0),
        (-3.0, -0.0, -3.0),
        (0.25, 0.25, 0.0),
        (-0.25, -0.25, -0.0),
        (1e300, 0.0, 1e300),
        (-f64::INFINITY, -0.0, -f64::INFINITY),
        (4_503_599_627_370_495.5, 0.5, 4_503_599_627_370_495.0),
    ] {
        let (result, stored) = split(&mut guest, "modf", x);
        assert_eq!(result, f64::to_bits(fraction), "modf({x})");
        assert_eq!(
            u64::from_le_bytes(stored),
            f64::to_bits(integral),
            "modf({x})"
        );
    }
    let (result, stored) = split(&mut guest, "modf", f64::NAN);
    assert!(f64::from_bits(result).is_nan());
    assert!(f64::from_bits(u64::from_le_bytes(stored)).is_nan());
    // An unwritable pointer is an access violation, not a silent skip.
    for symbol in ["frexp", "modf"] {
        guest.xmm[0] = u128::from(2.0f64.to_bits());
        let (_, exit) = guest.run(symbol, &[0, 0x10]);
        assert!(
            matches!(exit, ExitReason::MemoryFault(_)),
            "{symbol}: {exit:?}"
        );
    }
}

#[test]
fn crt_math_integer_rounding_covers_the_range_edges() {
    let mut guest = Guest::new();
    let integer = |guest: &mut Guest, symbol: &str, x: f64| {
        guest.xmm[0] = 0xDEAD_BEEF_u128 << 64 | u128::from(x.to_bits());
        guest.call(symbol, &[JUNK_HIGH])
    };
    let long_min = 0x8000_0000;
    for (x, expected) in [
        (2.5, 3),
        (-2.5, (-3i32) as u32),
        (-0.4, 0),
        (2_147_483_647.4, 0x7FFF_FFFF),
        (-2_147_483_648.4, long_min),
        // Out of range, NaN and infinities: LONG_MIN, as x86 conversion.
        (2_147_483_647.5, long_min),
        (-2_147_483_648.5, long_min),
        (f64::NAN, long_min),
        (f64::INFINITY, long_min),
    ] {
        // A 32-bit `long` comes back in EAX with the upper half clear.
        assert_eq!(
            integer(&mut guest, "lround", x),
            u64::from(expected),
            "lround({x})"
        );
    }
    let llong_min = 1 << 63;
    for (x, expected) in [
        (-0.5, u64::MAX),
        (4_503_599_627_370_495.5, 4_503_599_627_370_496),
        (9_223_372_036_854_774_784.0, 9_223_372_036_854_774_784),
        (-9_223_372_036_854_775_808.0, llong_min),
        (9_223_372_036_854_775_808.0, llong_min),
        (-f64::INFINITY, llong_min),
        (f64::NAN, llong_min),
    ] {
        assert_eq!(integer(&mut guest, "llround", x), expected, "llround({x})");
    }
}

const CRT_MATH_API_SET: &str = "api-ms-win-crt-math-l1-1-0.dll";

fn crt_math_binary32_cpu(x: f32, y: f32, second_integer: u64) -> CpuState {
    let mut cpu = CpuState::new(BASE + u64::from(CODE_RVA), STACK_TOP);
    cpu.set(Register::Rax, u64::MAX);
    cpu.set(Register::Rcx, JUNK_HIGH | u64::from(42.0_f32.to_bits()));
    cpu.set(Register::Rdx, second_integer);
    // Poison the rest of each lane to expose an accidental binary64 argument.
    let junk = 0xAAAA_BBBB_CCCC_DDDD_7FF8_0000_0000_0000_u128;
    cpu.xmm[0] = junk | u128::from(x.to_bits());
    cpu.xmm[1] = junk | u128::from(y.to_bits());
    cpu
}

#[test]
fn crt_math_binary32_lroundf_returns_a_win64_long() {
    let (mut engine, mut memory) = aliased_guest(CRT_MATH_API_SET, "lroundf");
    for (x, expected) in [
        (2.5, 3),
        (-2.5, -3),
        (f32::from_bits(0x3EFF_FFFF), 0), // immediately below 0.5
        (-f32::from_bits(0x3EFF_FFFF), 0),
        (-0.0, 0),
        (f32::from_bits(0x4EFF_FFFF), 2_147_483_520), // 2^31 - 128
        (f32::from_bits(0xCEFF_FFFF), -2_147_483_520),
        (f32::from_bits(0xCF00_0000), i32::MIN), // -2^31, still in range
        // Xenora's existing lround policy uses LONG_MIN for invalid conversions.
        (f32::from_bits(0x4F00_0000), i32::MIN),
        (f32::from_bits(0xCF00_0001), i32::MIN),
        (f32::INFINITY, i32::MIN),
        (f32::NEG_INFINITY, i32::MIN),
        (f32::NAN, i32::MIN),
    ] {
        let mut cpu = crt_math_binary32_cpu(x, f32::NAN, JUNK_HIGH);
        assert_eq!(
            engine.run(&mut cpu, &mut memory, 8).exit_reason,
            ExitReason::Halt
        );
        assert_eq!(
            cpu.get(Register::Rax),
            u64::from(expected as u32),
            "lroundf({x})"
        );
    }
}

#[test]
fn crt_math_binary32_modff_stores_one_float_through_rdx() {
    let (mut engine, mut memory) = aliased_guest(CRT_MATH_API_SET, "modff");
    let smallest = f32::from_bits(1);
    let output = SCRATCH + 4;
    for (x, fraction, integral) in [
        (3.75_f32, 0.75_f32, 3.0_f32),
        (-3.75, -0.75, -3.0),
        (-3.0, -0.0, -3.0),
        (-smallest, -smallest, -0.0),
        (0.25, 0.25, 0.0),
        (-0.0, -0.0, -0.0),
        (8_388_607.5, 0.5, 8_388_607.0),
        (f32::NEG_INFINITY, -0.0, f32::NEG_INFINITY),
        (f32::NAN, f32::NAN, f32::NAN),
    ] {
        memory.write_bytes(SCRATCH, &[0xAB; 12]).unwrap();
        let mut cpu = crt_math_binary32_cpu(x, f32::NAN, output);
        assert_eq!(
            engine.run(&mut cpu, &mut memory, 8).exit_reason,
            ExitReason::Halt
        );
        let mut stored = [0; 12];
        memory.read_bytes(SCRATCH, &mut stored).unwrap();
        assert_eq!(stored[..4], [0xAB; 4], "modff({x})");
        assert_eq!(stored[8..], [0xAB; 4], "modff({x})");
        let result = cpu.xmm[0] as u32;
        if x.is_nan() {
            assert!(f32::from_bits(result).is_nan());
            assert!(f32::from_le_bytes(stored[4..8].try_into().unwrap()).is_nan());
        } else {
            assert_eq!(result, fraction.to_bits(), "modff({x})");
            assert_eq!(stored[4..8], integral.to_le_bytes(), "modff({x})");
        }
    }
    for address in [0, 0x10] {
        let mut cpu = crt_math_binary32_cpu(3.75, f32::NAN, address);
        let exit = engine.run(&mut cpu, &mut memory, 8).exit_reason;
        assert!(
            matches!(exit, ExitReason::MemoryFault(_)),
            "modff({address:#x}): {exit:?}"
        );
    }
}

#[test]
fn crt_math_binary32_nextafterf_steps_to_adjacent_values() {
    let (mut engine, mut memory) = aliased_guest(CRT_MATH_API_SET, "nextafterf");
    let smallest = f32::from_bits(1);
    for (x, y, expected) in [
        (0.0, -0.0, 0x8000_0000),
        (-0.0, 0.0, 0),
        (0.0, -1.0, 0x8000_0001),
        (-0.0, 1.0, 1),
        (-smallest, 1.0, 0x8000_0000),
        (smallest, -1.0, 0),
        (f32::MIN_POSITIVE, 0.0, 0x007F_FFFF),
        (f32::from_bits(0x007F_FFFF), 1.0, 0x0080_0000),
        (1.0, 2.0, 0x3F80_0001),
        (1.0, 0.0, 0x3F7F_FFFF),
        (-1.0, -2.0, 0xBF80_0001),
        (-1.0, 0.0, 0xBF7F_FFFF),
        (f32::MAX, f32::INFINITY, 0x7F80_0000),
        (f32::NEG_INFINITY, 0.0, 0xFF7F_FFFF),
        (f32::INFINITY, f32::INFINITY, 0x7F80_0000),
    ] {
        let mut cpu = crt_math_binary32_cpu(x, y, JUNK_HIGH);
        assert_eq!(
            engine.run(&mut cpu, &mut memory, 8).exit_reason,
            ExitReason::Halt
        );
        assert_eq!(cpu.xmm[0] as u32, expected, "nextafterf({x}, {y})");
    }
}

#[test]
fn crt_math_binary32_remainderf_rounds_quotient_ties_to_even() {
    let (mut engine, mut memory) = aliased_guest(CRT_MATH_API_SET, "remainderf");
    for (x, y, expected) in [
        (5.0, 2.0, 1.0_f32), // 5 - 2*2
        (7.0, 2.0, -1.0),    // 7 - 4*2
        (7.0, -2.0, -1.0),
        (-7.0, 2.0, 1.0),
        (4.0, -2.0, 0.0),
        (-4.0, 2.0, -0.0),
        (-0.0, 2.0, -0.0),
        (1.5, f32::NEG_INFINITY, 1.5),
        // In units of the smallest subnormal, 2^249 leaves 2 modulo 3.
        (
            f32::from_bits(0x7180_0000),
            f32::from_bits(3),
            -f32::from_bits(1),
        ),
        (1.0, -0.0, f32::NAN),
        (f32::INFINITY, 2.0, f32::NAN),
        (f32::NAN, 2.0, f32::NAN),
        (2.0, f32::NAN, f32::NAN),
    ] {
        let mut cpu = crt_math_binary32_cpu(x, y, JUNK_HIGH);
        assert_eq!(
            engine.run(&mut cpu, &mut memory, 8).exit_reason,
            ExitReason::Halt
        );
        let result = cpu.xmm[0] as u32;
        if expected.is_nan() {
            assert!(f32::from_bits(result).is_nan(), "remainderf({x}, {y})");
        } else {
            assert_eq!(result, expected.to_bits(), "remainderf({x}, {y})");
        }
    }
}

#[test]
fn guest_call_through_dbt_preserves_win64_abi_state() {
    use Register::{R8, R9, R12, R13, R14, R15, Rax, Rbp, Rbx, Rcx, Rdi, Rdx, Rsi, Rsp};
    let observed = Arc::new(Mutex::new(None::<(u64, u64, [u64; 4])>));
    let seen = observed.clone();
    let mut registry = ImportRegistry::new();
    registry.register("t.dll", "F", move |_args, cpu, mem| {
        let rsp = cpu.get(Rsp);
        let shadow = [
            mem.read_u64(rsp + 8).unwrap(),
            mem.read_u64(rsp + 16).unwrap(),
            mem.read_u64(rsp + 24).unwrap(),
            mem.read_u64(rsp + 32).unwrap(),
        ];
        *seen.lock().unwrap() = Some((rsp, cpu.rip, shadow));
        cpu.set(Rcx, 0x11);
        cpu.set(Rdx, 0x22);
        cpu.set(R8, 0x33);
        cpu.set(R9, 0x44);
        for (reg, lane) in cpu.xmm[..6].iter_mut().enumerate() {
            *lane = u128::from(0x55_u64 + reg as u64);
        }
        Ok(0x99AA_BBCC_DDEE_F001)
    });
    let image = build(&[("t.dll", Symbol::Name("F"))]);
    let pe = ParsedPe::parse(&image.bytes).unwrap();
    let mut memory = pe.load_into_memory(&image.bytes).unwrap().memory;
    memory
        .map_region(STACK, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    registry
        .bind_imports(&pe, &image.bytes, BASE, &mut memory)
        .unwrap();
    let mut engine = DbtEngine::new(256 * 1024).unwrap();
    engine.set_import_registry(registry);
    // Before CALL RSP is 16-byte aligned; CALL pushes return address so the
    // callee sees RSP % 16 == 8. Shadow space is [entry_rsp+8, entry_rsp+40).
    let initial_rsp = STACK_TOP;
    assert_eq!(initial_rsp % 16, 0);
    let entry_rsp_expected = initial_rsp - 8;
    for slot in 0..4u64 {
        memory
            .write_u64(entry_rsp_expected + 8 + slot * 8, 0x7000 + slot)
            .unwrap();
    }
    let mut cpu = CpuState::new(BASE + u64::from(CODE_RVA), initial_rsp);
    let nonvolatile_gpr = [Rbx, Rbp, Rdi, Rsi, R12, R13, R14, R15];
    for (index, register) in nonvolatile_gpr.into_iter().enumerate() {
        cpu.set(register, 0x6100 + index as u64);
    }
    for (offset, lane) in cpu.xmm[6..16].iter_mut().enumerate() {
        *lane = u128::from(0x6200_u64 + (offset + 6) as u64);
    }
    let result = engine.run(&mut cpu, &mut memory, 1000);
    assert_eq!(result.exit_reason, ExitReason::Halt);
    let (entry_rsp, _, shadow) = observed.lock().unwrap().expect("service ran");
    assert_eq!(entry_rsp, entry_rsp_expected);
    assert_eq!(entry_rsp % 16, 8);
    assert_eq!(shadow, [0x7000, 0x7001, 0x7002, 0x7003]);
    assert_eq!(cpu.get(Rax), 0x99AA_BBCC_DDEE_F001);
    assert_eq!(cpu.get(Rsp), initial_rsp);
    for (index, register) in nonvolatile_gpr.into_iter().enumerate() {
        assert_eq!(cpu.get(register), 0x6100 + index as u64, "{register:?}");
    }
    for (offset, lane) in cpu.xmm[6..16].iter().enumerate() {
        let index = offset + 6;
        assert_eq!(*lane, u128::from(0x6200_u64 + index as u64), "xmm{index}");
    }
}

#[test]
fn arguments_are_assigned_by_position_and_read_the_stack_after_the_fourth() {
    let mut memory = GuestMemory::new();
    memory
        .map_region(STACK, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    // [RSP] return address, 32 bytes of shadow space, then arguments 4 and 5.
    memory
        .write_u64(STACK_TOP + 40, 0x1122_3344_5566_7788)
        .unwrap();
    memory
        .write_u64(STACK_TOP + 48, 0x4008_0000_0000_0000)
        .unwrap();
    let mut cpu = CpuState::new(0, STACK_TOP);
    for (index, register) in [Register::Rcx, Register::Rdx, Register::R8, Register::R9]
        .into_iter()
        .enumerate()
    {
        cpu.set(register, 0xFFFF_FFFF_0000_0010 + index as u64);
        cpu.xmm[index] = (1 << 100) + 0xAAAA_AAAA_0000_0020 + index as u128;
    }
    let args = Win64Args::new(&cpu);
    let call = Call::new(&args, &cpu, &memory);
    assert_eq!(call.u32(0), Ok(0x10));
    assert_eq!(call.f64(1), Ok(Float64(0xAAAA_AAAA_0000_0021)));
    assert_eq!(call.f32(2), Ok(Float32(0x22)));
    assert_eq!(call.u64(3), Ok(0xFFFF_FFFF_0000_0013));
    assert_eq!(call.i32(4), Ok(0x5566_7788));
    assert_eq!(call.f64(5), Ok(Float64(0x4008_0000_0000_0000)));
    cpu.set(Register::Rsp, STACK + 0xFF0);
    let args = Win64Args::new(&cpu);
    let call = Call::new(&args, &cpu, &memory);
    assert!(matches!(call.u64(4), Err(ExitReason::MemoryFault(_))));
    cpu.set(Register::Rsp, u64::MAX - 8);
    let args = Win64Args::new(&cpu);
    assert!(Call::new(&args, &cpu, &memory).f64(4).is_err());
}

// --- registry ----------------------------------------------------------------

/// Bits above an `int` argument are not part of it.
/// The legacy CRT data imports the harness image carries after `_errno`,
/// in this order (#643).
const LEGACY_DATA_SYMBOLS: [&str; 7] = [
    "__argc",
    "__argv",
    "_environ",
    "__initenv",
    "_fmode",
    "_commode",
    "_timezone",
];

/// Legacy-linked binaries import these services from `msvcrt.dll`, where the
/// compatibility mapping resolves them to the same handlers as the modern
/// runtime.
const LEGACY_FUNCTION_SYMBOLS: [&str; 37] = [
    "__iob_func",
    "sscanf",
    "fprintf",
    "vfprintf",
    "strlen",
    "memcpy",
    "malloc",
    "free",
    "strcmp",
    "memchr",
    "strchr",
    "getenv",
    "sprintf",
    "_vsnprintf",
    "_vscprintf",
    "_time64",
    "_tzset",
    "_umask",
    "_getpid",
    "rand",
    "srand",
    "isalpha",
    "isdigit",
    "isalnum",
    "islower",
    "isupper",
    "isspace",
    "ispunct",
    "iscntrl",
    "isprint",
    "isgraph",
    "isxdigit",
    "isblank",
    "tolower",
    "toupper",
    "atoi",
    "atof",
];

const JUNK: u64 = 0xFFFF_FFFF_0000_0000;
/// The low 32 bits of an `int` result of -1.
const MINUS_ONE: u64 = 0xFFFF_FFFF;
const EINVAL: u32 = 22;

/// `_set_new_mode` (new.h) and `_configthreadlocale` (locale.h), from their
/// Microsoft Learn pages: each returns the setting before the call, and -1 for
/// an argument outside its documented set, with `errno` set to `EINVAL`.
#[test]
fn crt_startup_modes_return_the_previous_setting() {
    let mut guest = Guest::new();
    let result = |value: u64| value & 0xFFFF_FFFF;
    // malloc does not call the new handler by default, so the first mode is 0.
    assert_eq!(result(guest.call("_set_new_mode", &[1])), 0);
    assert_eq!(result(guest.call("_set_new_mode", &[1])), 1);
    assert_eq!(result(guest.call("_set_new_mode", &[JUNK])), 1);
    assert_eq!(result(guest.call("_set_new_mode", &[JUNK | 1])), 0);
    guest.set_errno(0);
    for invalid in [2, 3, MINUS_ONE, 0x8000_0000] {
        assert_eq!(result(guest.call("_set_new_mode", &[invalid])), MINUS_ONE);
        assert_eq!(guest.errno(), EINVAL, "{invalid:#x}");
        guest.set_errno(0);
    }
    // A refused mode changes nothing, and a valid call leaves errno alone.
    assert_eq!(result(guest.call("_set_new_mode", &[0])), 1);
    assert_eq!(guest.errno(), 0);

    // _ENABLE_PER_THREAD_LOCALE is 1, _DISABLE_PER_THREAD_LOCALE is 2, and 0
    // only asks. A program starts with the global locale.
    let locale =
        |guest: &mut Guest, request: u64| result(guest.call("_configthreadlocale", &[request]));
    assert_eq!(locale(&mut guest, 0), 2);
    assert_eq!(locale(&mut guest, 0), 2);
    assert_eq!(locale(&mut guest, 1), 2);
    assert_eq!(locale(&mut guest, 0), 1);
    assert_eq!(locale(&mut guest, JUNK | 2), 1);
    assert_eq!(locale(&mut guest, JUNK), 2);
    assert_eq!(locale(&mut guest, 1), 2);
    assert_eq!(guest.errno(), 0);
    for invalid in [3, 4, MINUS_ONE, 0x8000_0001] {
        assert_eq!(locale(&mut guest, invalid), MINUS_ONE, "{invalid:#x}");
        assert_eq!(guest.errno(), EINVAL, "{invalid:#x}");
        guest.set_errno(0);
    }
    // A refused request changes nothing, and a valid one leaves errno alone.
    assert_eq!(locale(&mut guest, 0), 1);
    assert_eq!(guest.errno(), 0);
    // The two settings are separate.
    assert_eq!(result(guest.call("_set_new_mode", &[0])), 0);
}

/// `_set_invalid_parameter_handler` (stdlib.h), `SetUnhandledExceptionFilter`
/// (errhandlingapi.h) and `signal` (signal.h), from their Microsoft Learn
/// pages: each returns the handler it replaces. The first two start with none,
/// which is a null pointer; a signal starts at `SIG_DFL`, which is zero.
/// `signal` returns `SIG_ERR`, which is -1 as a pointer, and sets `errno` to
/// `EINVAL` for a signal that is not one of the six its page lists.
#[test]
fn crt_startup_handlers_return_the_previous_handler() {
    let mut guest = Guest::new();
    const A: u64 = 0x1_4000_1230;
    const B: u64 = 0x7FFF_FFFF_FFFF_FFF0;
    for symbol in [
        "_set_invalid_parameter_handler",
        "SetUnhandledExceptionFilter",
    ] {
        assert_eq!(guest.call(symbol, &[A]), 0, "{symbol}");
        assert_eq!(guest.call(symbol, &[B]), A, "{symbol}");
        assert_eq!(guest.call(symbol, &[0]), B, "{symbol}");
        assert_eq!(guest.call(symbol, &[0]), 0, "{symbol}");
    }
    // One does not see the other's handler.
    assert_eq!(guest.call("_set_invalid_parameter_handler", &[A]), 0);
    assert_eq!(guest.call("SetUnhandledExceptionFilter", &[B]), 0);
    assert_eq!(guest.call("_set_invalid_parameter_handler", &[0]), A);
    assert_eq!(guest.call("SetUnhandledExceptionFilter", &[0]), B);

    // SIGINT 2, SIGILL 4, SIGFPE 8, SIGSEGV 11, SIGTERM 15, SIGABRT 22.
    const SIGNALS: [u64; 6] = [2, 4, 8, 11, 15, 22];
    guest.set_errno(0);
    for signal in SIGNALS {
        assert_eq!(guest.call("signal", &[signal, A + signal]), 0, "{signal}");
    }
    // Each signal has its own handler, and the number is an int.
    for signal in SIGNALS {
        assert_eq!(
            guest.call("signal", &[JUNK | signal, B]),
            A + signal,
            "{signal}"
        );
    }
    // SIG_DFL is 0 and SIG_IGN is 1; either is stored like a function.
    assert_eq!(guest.call("signal", &[2, 1]), B);
    assert_eq!(guest.call("signal", &[2, 0]), 1);
    assert_eq!(guest.call("signal", &[2, A]), 0);
    assert_eq!(guest.errno(), 0);
    for unlisted in [
        0,
        1,
        3,
        5,
        7,
        9,
        10,
        12,
        14,
        16,
        23,
        64,
        MINUS_ONE,
        0x8000_0002,
    ] {
        assert_eq!(
            guest.call("signal", &[unlisted, B]),
            u64::MAX,
            "{unlisted:#x}"
        );
        assert_eq!(guest.errno(), EINVAL, "{unlisted:#x}");
        guest.set_errno(0);
    }
    // A refused call changed no handler.
    assert_eq!(guest.call("signal", &[2, 0]), A);
    for signal in &SIGNALS[1..] {
        assert_eq!(guest.call("signal", &[*signal, 0]), B, "{signal}");
    }
}

/// `__p__fmode` and `__p__commode`, from their Microsoft Learn pages: each
/// returns a pointer to a global `int`, `_fmode` and `_commode`. The `_fmode`
/// page gives its default as `_O_TEXT`, which fcntl.h defines as 0x4000. No
/// page gives `_commode` an initial value; zero, "no commit", is Xenora's.
#[test]
fn crt_file_mode_variables_are_guest_memory() {
    let mut guest = Guest::new();
    let fmode = guest.call("__p__fmode", &[]);
    let commode = guest.call("__p__commode", &[]);
    assert_ne!(fmode, 0);
    assert_ne!(commode, 0);
    // Two ints that do not overlap.
    assert!(fmode.abs_diff(commode) >= 4);
    assert_eq!(guest.memory.read_u32(fmode).unwrap(), 0x4000);
    assert_eq!(guest.memory.read_u32(commode).unwrap(), 0);
    // The program assigns through the pointers: _O_BINARY is 0x8000 and
    // _IOCOMMIT is 0x4000.
    guest.memory.write_u32(fmode, 0x8000).unwrap();
    assert_eq!(guest.memory.read_u32(commode).unwrap(), 0);
    guest.memory.write_u32(commode, 0x4000).unwrap();
    // The variables stay where they are and keep what was stored.
    assert_eq!(guest.call("__p__fmode", &[]), fmode);
    assert_eq!(guest.call("__p__commode", &[]), commode);
    assert_eq!(guest.memory.read_u32(fmode).unwrap(), 0x8000);
    assert_eq!(guest.memory.read_u32(commode).unwrap(), 0x4000);

    // The order of the first calls does not matter.
    let mut other = Guest::new();
    let commode = other.call("__p__commode", &[]);
    assert_eq!(other.memory.read_u32(commode).unwrap(), 0);
    let fmode = other.call("__p__fmode", &[]);
    assert_eq!(other.memory.read_u32(fmode).unwrap(), 0x4000);
    assert!(fmode.abs_diff(commode) >= 4);
}

/// `_set_app_type` and `__setusermatherr` (corecrt_startup.h) return nothing.
/// What they were given is visible to the host only.
#[test]
fn crt_app_type_and_math_error_handler_are_recorded() {
    let mut guest = Guest::new();
    assert_eq!(guest.state.crt_app_type(), 0); // _crt_unknown_app
    assert_eq!(guest.state.crt_user_math_error(), 0);
    guest.call("_set_app_type", &[JUNK | 1]); // _crt_console_app
    assert_eq!(guest.state.crt_app_type(), 1);
    assert_eq!(guest.state.crt_user_math_error(), 0);
    guest.call("__setusermatherr", &[0x1_4000_2340]);
    assert_eq!(guest.state.crt_user_math_error(), 0x1_4000_2340);
    assert_eq!(guest.state.crt_app_type(), 1);
    guest.call("_set_app_type", &[2]); // _crt_gui_app
    guest.call("__setusermatherr", &[0]);
    assert_eq!(guest.state.crt_app_type(), 2);
    assert_eq!(guest.state.crt_user_math_error(), 0);
    // Neither touched errno or the last error.
    assert_eq!(guest.errno(), 0);
    assert_eq!(guest.last_error(), 0);
}

#[test]
fn legacy_startup_records_the_app_type() {
    let mut guest = Guest::new();
    assert_eq!(guest.state.crt_app_type(), 0);
    guest.call("__set_app_type", &[JUNK | 1]);
    assert_eq!(guest.state.crt_app_type(), 1);
    // The legacy entry and the modern one record in the same place.
    guest.call("_set_app_type", &[2]);
    assert_eq!(guest.state.crt_app_type(), 2);
    assert_eq!(guest.errno(), 0);
}

#[test]
fn legacy_startup_builds_the_main_arguments() {
    let mut guest = Guest::new();
    let supplied = ["gate-a2.exe", "one", "two words"];
    guest.state.set_program_arguments(&supplied).unwrap();
    // Null output pointers are refused with EINVAL.
    for args in [
        [0, SCRATCH, SCRATCH + 16, 0, 0],
        [SCRATCH, 0, SCRATCH + 16, 0, 0],
        [SCRATCH, SCRATCH + 16, 0, 0, 0],
    ] {
        guest.memory.write_u64(SCRATCH, 0xDEAD).unwrap();
        assert_eq!(
            guest.call("__getmainargs", &args) & 0xFFFF_FFFF,
            u64::from(u32::MAX)
        );
        assert_eq!(guest.memory.read_u64(SCRATCH).unwrap(), 0xDEAD, "untouched");
        assert_eq!(guest.errno(), 22);
    }
    guest.memory.write_u64(SCRATCH, 0).unwrap();
    guest.memory.write_u64(SCRATCH + 8, 0).unwrap();
    guest.memory.write_u64(SCRATCH + 16, 0).unwrap();
    assert_eq!(
        guest.call(
            "__getmainargs",
            &[SCRATCH, SCRATCH + 8, SCRATCH + 16, 0, 0xBAD]
        ) & 0xFFFF_FFFF,
        0
    );
    assert_eq!(guest.memory.read_u32(SCRATCH).unwrap(), 3);
    let table = guest.memory.read_u64(SCRATCH + 8).unwrap();
    assert!(table != 0);
    // The same table the modern accessors reach.
    let modern = guest.call("__p___argv", &[]);
    assert_eq!(guest.memory.read_u64(modern).unwrap(), table);
    let mut first = guest.memory.read_u64(table).unwrap();
    let mut bytes = Vec::new();
    loop {
        match guest.memory.read_u8(first).unwrap() {
            0 => break,
            byte => bytes.push(byte),
        }
        first += 1;
    }
    assert_eq!(bytes, b"gate-a2.exe");
    // The environment is the empty table `_initialize_narrow_environment` builds.
    let environ = guest.memory.read_u64(SCRATCH + 16).unwrap();
    assert_eq!(guest.memory.read_u64(environ).unwrap(), 0);
    // A second call returns the same table: the arguments configure once.
    assert_eq!(
        guest.call("__getmainargs", &[SCRATCH, SCRATCH + 8, SCRATCH + 16, 1, 0]) & 0xFFFF_FFFF,
        0
    );
    assert_eq!(guest.memory.read_u64(SCRATCH + 8).unwrap(), table);
}

#[test]
fn legacy_mb_cur_max_is_one_byte() {
    let mut guest = Guest::new();
    assert_eq!(guest.call("___mb_cur_max_func", &[]) & 0xFFFF_FFFF, 1);
    assert_eq!(guest.errno(), 0);
}

#[test]
fn legacy_amsg_exit_ends_the_process() {
    let mut guest = Guest::new();
    let (_, exit) = guest.run("_amsg_exit", &[JUNK | 7]);
    assert_eq!(exit, ExitReason::ProcessExit(7));
    let (_, again) = guest.run("_amsg_exit", &[3]);
    assert_eq!(
        again,
        ExitReason::ProcessExit(7),
        "the first exit status wins"
    );
}

#[test]
fn environment_variables_round_trip_and_miss_the_undefined_ones() {
    let mut guest = Guest::new();

    // A fresh environment answers every query with the documented miss.
    guest.memory.write_bytes(SCRATCH, b"PATH\0").unwrap();
    for symbol in ["GetEnvironmentVariableA", "GetEnvironmentVariableW"] {
        assert_eq!(
            guest.call(symbol, &[SCRATCH, SCRATCH + 0x40, 32]) & 0xFFFF_FFFF,
            0
        );
        assert_eq!(guest.last_error(), 203, "{symbol} ERROR_ENVVAR_NOT_FOUND");
    }

    // A defined variable round-trips through both widths, case-insensitively.
    guest
        .state
        .set_environment_variable("XenoraProbe", Some("answer-42"));
    guest.memory.write_bytes(SCRATCH, b"xenoraprobe\0").unwrap();
    let got = guest.call("GetEnvironmentVariableA", &[SCRATCH, SCRATCH + 0x20, 32]) & 0xFFFF_FFFF;
    assert_eq!(got, 9, "the length without the terminator");
    let mut bytes = [0u8; 10];
    guest.memory.read_bytes(SCRATCH + 0x20, &mut bytes).unwrap();
    assert_eq!(&bytes, b"answer-42\0");

    let wide_name: Vec<u16> = "XENORAPROBE".encode_utf16().collect();
    for (index, unit) in wide_name.iter().enumerate() {
        guest
            .memory
            .write_u16(SCRATCH + 2 * index as u64, *unit)
            .unwrap();
    }
    guest
        .memory
        .write_u16(SCRATCH + 2 * wide_name.len() as u64, 0)
        .unwrap();
    let got = guest.call("GetEnvironmentVariableW", &[SCRATCH, SCRATCH + 0x60, 32]) & 0xFFFF_FFFF;
    assert_eq!(got, 9);
    assert_eq!(
        guest.memory.read_u16(SCRATCH + 0x60).unwrap(),
        u16::from(b'a')
    );

    // A small buffer answers the size it needs, terminator included.
    guest.memory.write_bytes(SCRATCH, b"xenoraprobe\0").unwrap();
    assert_eq!(
        guest.call("GetEnvironmentVariableA", &[SCRATCH, SCRATCH + 0x40, 4]) & 0xFFFF_FFFF,
        10,
        "length 9 plus the terminator"
    );
    for (index, unit) in wide_name.iter().enumerate() {
        guest
            .memory
            .write_u16(SCRATCH + 2 * index as u64, *unit)
            .unwrap();
    }
    guest
        .memory
        .write_u16(SCRATCH + 2 * wide_name.len() as u64, 0)
        .unwrap();
    assert_eq!(
        guest.call("GetEnvironmentVariableW", &[SCRATCH, SCRATCH + 0x40, 4]) & 0xFFFF_FFFF,
        10
    );
    guest.memory.write_bytes(SCRATCH, b"xenoraprobe\0").unwrap();

    // A deleted variable misses again.
    guest.state.set_environment_variable("XenoraProbe", None);
    assert_eq!(
        guest.call("GetEnvironmentVariableA", &[SCRATCH, SCRATCH + 0x20, 32]) & 0xFFFF_FFFF,
        0
    );
    assert_eq!(guest.last_error(), 203);
}

#[test]
fn the_hosted_console_has_no_window_and_its_title_round_trips() {
    let mut guest = Guest::new();
    assert_eq!(guest.call("GetConsoleWindow", &[]), 0);

    // Null titles and invalid outputs are refused.
    assert_eq!(guest.call("SetConsoleTitleW", &[0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.last_error(), 87);
    assert_eq!(guest.call("GetConsoleTitleW", &[0, 32]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.call("GetConsoleTitleW", &[SCRATCH, 0]) & 0xFFFF_FFFF,
        0
    );

    // The title starts empty: length zero, just the terminator written.
    assert_eq!(
        guest.call("GetConsoleTitleW", &[SCRATCH, 32]) & 0xFFFF_FFFF,
        0
    );
    assert_eq!(guest.memory.read_u16(SCRATCH).unwrap(), 0);

    // A wide round trip. "titre é" is 7 characters.
    let wide: Vec<u16> = "titre é".encode_utf16().collect();
    for (index, unit) in wide.iter().enumerate() {
        guest
            .memory
            .write_u16(SCRATCH + 2 * index as u64, *unit)
            .unwrap();
    }
    guest
        .memory
        .write_u16(SCRATCH + 2 * wide.len() as u64, 0)
        .unwrap();
    assert_eq!(guest.call("SetConsoleTitleW", &[SCRATCH]) & 0xFFFF_FFFF, 1);
    guest.memory.write_bytes(SCRATCH, &[0xCC; 0x40]).unwrap();
    assert_eq!(
        guest.call("GetConsoleTitleW", &[SCRATCH, 32]) & 0xFFFF_FFFF,
        7
    );
    for (index, unit) in wide.iter().enumerate() {
        assert_eq!(
            guest.memory.read_u16(SCRATCH + 2 * index as u64).unwrap(),
            *unit
        );
    }
    assert_eq!(
        guest.memory.read_u16(SCRATCH + 14).unwrap(),
        0,
        "terminated"
    );

    // A short buffer holds less, yet the answer is the full length.
    assert_eq!(
        guest.call("GetConsoleTitleW", &[SCRATCH, 4]) & 0xFFFF_FFFF,
        7
    );
    assert_eq!(
        guest.memory.read_u16(SCRATCH + 6).unwrap(),
        0,
        "terminated at size - 1"
    );

    // The narrow form converts with the UTF-8 console code page.
    assert_eq!(
        guest.call("GetConsoleTitleA", &[SCRATCH, 32]) & 0xFFFF_FFFF,
        8,
        "é is two bytes"
    );
    assert_eq!(guest.memory.read_u8(SCRATCH + 6).unwrap(), 0xC3);
    assert_eq!(guest.memory.read_u8(SCRATCH + 7).unwrap(), 0xA9);
    // A narrow round trip too.
    guest
        .memory
        .write_bytes(SCRATCH, "café".as_bytes())
        .unwrap();
    guest.memory.write_u8(SCRATCH + 5, 0).unwrap();
    assert_eq!(guest.call("SetConsoleTitleA", &[SCRATCH]) & 0xFFFF_FFFF, 1);
    assert_eq!(
        guest.call("GetConsoleTitleW", &[SCRATCH, 32]) & 0xFFFF_FFFF,
        4,
        "café is 4 wide characters"
    );
    assert_eq!(
        guest.last_error(),
        87,
        "successes leave the last error alone"
    );
}

#[test]
fn legacy_data_imports_bind_the_crt_variable_cells() {
    let mut guest = Guest::new();
    let supplied = ["prog.exe", "alpha", "beta"];
    guest.state.set_program_arguments(&supplied).unwrap();
    // The slot of each data import, in the order of LEGACY_DATA_SYMBOLS.
    let base = SERVICES.len() + 1;
    let cell = |guest: &Guest, position: usize| {
        guest
            .memory
            .read_u64(BASE + u64::from(guest.slots[base + position]))
            .unwrap()
    };
    let argc = cell(&guest, 0);
    let argv = cell(&guest, 1);
    let environ = cell(&guest, 2);
    let initenv = cell(&guest, 3);
    let fmode = cell(&guest, 4);
    let commode = cell(&guest, 5);
    let timezone = cell(&guest, 6);
    // None of them is a dispatch trampoline: a data import binds the
    // variable itself, below the trampoline range.
    for address in [argc, argv, environ, initenv, fmode, commode, timezone] {
        assert!(address != 0, "bound");
        assert!(
            address < IMPORT_TRAMPOLINE_BASE_VA,
            "{address:#x} is no trampoline"
        );
    }
    // `_fmode` starts as _O_TEXT, `_commode` and `_timezone` as zero.
    assert_eq!(guest.memory.read_u32(fmode).unwrap(), 0x4000);
    assert_eq!(guest.memory.read_u32(commode).unwrap(), 0);
    assert_eq!(guest.memory.read_u32(timezone).unwrap(), 0);
    // `_fmode` and `_commode` are adjacent ints, `_commode` after `_fmode`.
    assert_eq!(commode, fmode + 4);
    // Before the runtime configures the arguments the cells are zero.
    assert_eq!(guest.memory.read_u32(argc).unwrap(), 0);
    assert_eq!(guest.memory.read_u64(argv).unwrap(), 0);

    // The modern configuration fills the same cells the data imports bound.
    assert_eq!(guest.call("_configure_narrow_argv", &[1]) & 0xFFFF_FFFF, 0);
    let modern_argv = guest.call("__p___argv", &[]);
    let modern_argc = guest.call("__p___argc", &[]);
    assert_eq!(argv, modern_argv, "the data import is the modern cell");
    assert_eq!(argc, modern_argc);
    let table = guest.memory.read_u64(argv).unwrap();
    assert_ne!(table, 0);
    assert_eq!(guest.memory.read_u32(argc).unwrap(), 3);
    // The modern accessor and the data cell read one table.
    assert_eq!(guest.memory.read_u64(modern_argv).unwrap(), table);
    // `_environ` and `__initenv` bind one cell, the one `_initialize_narrow_environment` fills.
    assert_eq!(environ, initenv);
    assert_eq!(environ, guest.call("__p__environ", &[]));
}

/// The module and symbol pairs a program built with mingw-w64 14.0.0 (UCRT)
/// imports these services by, read from such a program's import table.
#[test]
fn crt_startup_services_resolve_as_mingw_w64_imports_them() {
    let (registry, _) = standard(0);
    for (module, symbol, canonical) in [
        (
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "_set_app_type",
            "ucrtbase.dll",
        ),
        (
            "api-ms-win-crt-heap-l1-1-0.dll",
            "_set_new_mode",
            "ucrtbase.dll",
        ),
        (
            "api-ms-win-crt-locale-l1-1-0.dll",
            "_configthreadlocale",
            "ucrtbase.dll",
        ),
        (
            "api-ms-win-crt-math-l1-1-0.dll",
            "__setusermatherr",
            "ucrtbase.dll",
        ),
        (
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "_set_invalid_parameter_handler",
            "ucrtbase.dll",
        ),
        (
            "api-ms-win-crt-stdio-l1-1-0.dll",
            "__p__fmode",
            "ucrtbase.dll",
        ),
        (
            "api-ms-win-crt-stdio-l1-1-0.dll",
            "__p__commode",
            "ucrtbase.dll",
        ),
        (
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "signal",
            "ucrtbase.dll",
        ),
        (
            "KERNEL32.dll",
            "SetUnhandledExceptionFilter",
            "kernel32.dll",
        ),
        (
            "api-ms-win-crt-private-l1-1-0.dll",
            "memcpy",
            "ucrtbase.dll",
        ),
    ] {
        let service = registry
            .resolve(module, &named(symbol))
            .unwrap_or_else(|| panic!("{module}!{symbol}"));
        let target = registry.resolve(canonical, &named(symbol)).unwrap();
        assert!(std::ptr::eq(service, target), "{module}!{symbol}");
        assert_eq!(service.status, ServiceStatus::Partial, "{symbol}");
    }
    // An API set forwards only the symbols listed for it.
    for (module, symbol) in [
        ("api-ms-win-crt-heap-l1-1-0.dll", "_set_app_type"),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "_set_new_mode"),
        ("api-ms-win-crt-stdio-l1-1-0.dll", "signal"),
        ("api-ms-win-crt-private-l1-1-0.dll", "_set_app_type"),
    ] {
        assert!(
            registry.resolve(module, &named(symbol)).is_none(),
            "{module}!{symbol}"
        );
    }
}

fn named(name: &str) -> ImportName {
    ImportName::Name(name.to_owned())
}

#[test]
fn generated_metadata_matches_the_live_registry() {
    let (registry, _) = standard(0);
    for service in &SERVICES {
        let descriptor = registry
            .resolve(service.library, &named(service.symbol))
            .unwrap();
        assert_eq!(descriptor.status, service.status, "{}", service.symbol);
        assert!(!service.tests.is_empty());
        for alias in service.aliases {
            let upper = alias.to_ascii_uppercase();
            let aliased = registry.resolve(&upper, &named(service.symbol)).unwrap();
            assert!(
                std::ptr::eq(aliased, descriptor),
                "{alias}!{}",
                service.symbol
            );
        }
        // Symbol names are exact, and unlisted API sets do not resolve.
        assert!(
            registry
                .resolve(
                    service.library,
                    &named(&service.symbol.to_ascii_uppercase())
                )
                .is_none()
                || service.symbol == service.symbol.to_ascii_uppercase()
        );
        assert!(
            registry
                .resolve("api-ms-win-core-file-l2-1-0.dll", &named(service.symbol))
                .is_none()
        );
    }
}

#[test]
fn conflicting_or_invalid_registrations_are_refused() {
    let handler = || Box::new(|_: &Win64Args, _: &mut CpuState, _: &mut GuestMemory| Ok(0));
    let mut registry = ImportRegistry::new();
    let mut add = |module: &str, name: ImportName| {
        registry.try_register(module, name, ServiceStatus::Stub, handler())
    };
    assert_eq!(add("a.dll", named("F")), Ok(()));
    assert_eq!(
        add("a.dll", named("f")),
        Ok(()),
        "symbols are case-sensitive"
    );
    assert_eq!(add("b.dll", named("F")), Ok(()));
    assert!(matches!(
        add("A.DLL", named("F")),
        Err(RegistryError::Duplicate { .. })
    ));
    assert_eq!(add("a.dll", ImportName::Ordinal(7)), Ok(()));
    assert!(matches!(
        add("a.dll", ImportName::Ordinal(7)),
        Err(RegistryError::Duplicate { .. })
    ));
    assert_eq!(
        add("a.dll", named("Ordinal#7")),
        Ok(()),
        "a name is never an ordinal"
    );
    for (module, symbol) in [("", "F"), ("a.dll", ""), ("a b.dll", "F"), ("a.dll", "F\n")] {
        assert!(matches!(
            add(module, named(symbol)),
            Err(RegistryError::InvalidName { .. })
        ));
    }
    assert_eq!(registry.try_alias("set.dll", "a.dll", "F"), Ok(()));
    assert_eq!(
        registry.try_alias("set.dll", "a.dll", "F"),
        Ok(()),
        "repeating is harmless"
    );
    assert!(matches!(
        registry.try_alias("set.dll", "b.dll", "F"),
        Err(RegistryError::Duplicate { .. })
    ));
    assert!(matches!(
        registry.try_alias("b.dll", "a.dll", "F"),
        Err(RegistryError::Duplicate { .. })
    ));
    assert!(matches!(
        registry.try_alias("x.dll", "a.dll", "G"),
        Err(RegistryError::UnknownTarget { .. })
    ));
}

#[test]
#[should_panic(expected = "kernel32.dll!CloseHandle is already registered")]
fn a_host_module_cannot_replace_a_standard_service() {
    let (mut registry, _) = standard(0);
    registry.register("KERNEL32.dll", "CloseHandle", |_, _, _| Ok(1));
}

fn bind(registry: &mut ImportRegistry, image: &Image) -> (Result<usize, ImportError>, GuestMemory) {
    let pe = ParsedPe::parse(&image.bytes).unwrap();
    let mut memory = pe.load_into_memory(&image.bytes).unwrap().memory;
    let result = registry.bind_imports(&pe, &image.bytes, BASE, &mut memory);
    (result, memory)
}

#[test]
fn an_unresolved_import_leaves_every_slot_unbound() {
    let image = build(&[
        ("kernel32.dll", Symbol::Name("GetLastError")),
        ("kernel32.dll", Symbol::Name("NoSuchFunction")),
    ]);
    let (mut registry, _) = standard(0);
    let (result, memory) = bind(&mut registry, &image);
    let expected = ImportError::UnresolvedImport {
        module: "kernel32.dll".into(),
        symbol: "NoSuchFunction".into(),
    };
    assert_eq!(result, Err(expected));
    for slot in &image.slots {
        let file = IDATA_RAW + (slot - IDATA_RVA) as usize;
        let original = u64::from_le_bytes(image.bytes[file..file + 8].try_into().unwrap());
        assert_eq!(memory.read_u64(BASE + u64::from(*slot)).unwrap(), original);
    }
}

#[test]
fn aliases_share_a_trampoline_and_ordinals_bind_only_ordinals() {
    let (mut registry, _) = standard(0);
    registry
        .try_register(
            "o.dll",
            ImportName::Ordinal(7),
            ServiceStatus::Partial,
            Box::new(|_, _, _| Ok(77)),
        )
        .unwrap();
    let image = build(&[
        ("KERNEL32.dll", Symbol::Name("GetLastError")),
        (
            "API-MS-Win-Core-ErrorHandling-L1-1-0.dll",
            Symbol::Name("GetLastError"),
        ),
        ("O.DLL", Symbol::Ordinal(7)),
    ]);
    let (result, memory) = bind(&mut registry, &image);
    assert_eq!(result, Ok(3));
    let slot = |index: usize| {
        memory
            .read_u64(BASE + u64::from(image.slots[index]))
            .unwrap()
    };
    assert_eq!(slot(0), slot(1));
    assert_ne!(slot(0), slot(2));
    for symbol in [Symbol::Name("Ordinal#7"), Symbol::Ordinal(8)] {
        let (result, _) = bind(&mut registry, &build(&[("o.dll", symbol)]));
        assert!(
            matches!(result, Err(ImportError::UnresolvedImport { .. })),
            "{result:?}"
        );
    }
}

/// Run the generated guest stub for import `slot` with one integer argument.
fn call_bound_slot(
    engine: &mut DbtEngine,
    memory: &mut GuestMemory,
    slot: usize,
    value: u64,
) -> u64 {
    let mut cpu = CpuState::new(BASE + u64::from(CODE_RVA) + 16 * slot as u64, STACK_TOP);
    cpu.set(Register::Rcx, value);
    let result = engine.run(&mut cpu, memory, 1000);
    assert_eq!(result.exit_reason, ExitReason::Halt, "slot {slot}");
    cpu.get(Register::Rax)
}

#[test]
fn pointer_encoding_services_round_trip_through_bound_imports() {
    let image = build(&[
        ("kernel32.dll", Symbol::Name("EncodePointer")),
        ("kernel32.dll", Symbol::Name("DecodePointer")),
    ]);
    let (mut registry, _, _state) = standard_with_state(0);
    let (result, mut memory) = bind(&mut registry, &image);
    assert_eq!(result, Ok(2));
    memory
        .map_region(STACK, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    // The service dispatcher reads the caller-owned 32-byte home area.
    for slot in 0..4 {
        memory
            .write_u64(STACK_TOP + slot * 8, 0x7000 + slot)
            .unwrap();
    }
    let mut engine = DbtEngine::new(256 * 1024).unwrap();
    engine.set_import_registry(registry);

    let pointer = 0x1_4000_1234;
    let encoded = call_bound_slot(&mut engine, &mut memory, 0, pointer);
    assert_ne!(encoded, pointer, "the cookie must transform the pointer");
    assert_eq!(
        call_bound_slot(&mut engine, &mut memory, 1, encoded),
        pointer
    );
}

/// A registry with one service bound, and its trampoline address.
fn bound_service<F>(handler: F) -> (ImportRegistry, GuestMemory, u64)
where
    F: Fn(&Win64Args, &mut CpuState, &mut GuestMemory) -> Result<u64, ExitReason>
        + Send
        + Sync
        + 'static,
{
    let mut registry = ImportRegistry::new();
    registry.register("t.dll", "F", handler);
    let image = build(&[("t.dll", Symbol::Name("F"))]);
    let (result, mut memory) = bind(&mut registry, &image);
    assert_eq!(result, Ok(1));
    memory
        .map_region(STACK, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    memory.write_u64(STACK_TOP, 0x1234).unwrap();
    let trampoline = memory.read_u64(BASE + u64::from(image.slots[0])).unwrap();
    (registry, memory, trampoline)
}

#[test]
fn a_service_that_changes_a_nonvolatile_register_stops_the_guest() {
    use Register::{R8, R9, R10, R11, R12, R13, R14, R15, Rbp, Rbx, Rcx, Rdi, Rdx, Rsi, Rsp};
    let dispatch = |change: fn(&mut CpuState, usize), which: usize| {
        let (registry, mut memory, trampoline) = bound_service(move |_, cpu, _| {
            change(cpu, which);
            Ok(5)
        });
        let mut cpu = CpuState::new(trampoline, STACK_TOP);
        let result = registry.dispatch(trampoline, &mut cpu, &mut memory);
        (result, cpu)
    };
    for register in [Rbx, Rbp, Rdi, Rsi, Rsp, R12, R13, R14, R15] {
        let (result, _) = dispatch(|cpu, index| cpu.gpr[index] ^= 8, register as usize);
        assert_eq!(result, Err(ExitReason::ServiceAbiViolation), "{register:?}");
    }
    for register in [Rcx, Rdx, R8, R9, R10, R11] {
        let (result, cpu) = dispatch(|cpu, index| cpu.gpr[index] ^= 8, register as usize);
        assert_eq!(result, Ok(()), "{register:?}");
        assert_eq!(
            (cpu.rip, cpu.get(Rsp), cpu.get(Register::Rax)),
            (0x1234, STACK_TOP + 8, 5)
        );
    }
    for index in 0..16 {
        let (result, _) = dispatch(|cpu, index| cpu.xmm[index] ^= 1 << 127, index);
        let expected = if index < 6 {
            Ok(())
        } else {
            Err(ExitReason::ServiceAbiViolation)
        };
        assert_eq!(result, expected, "xmm{index}");
    }
}

#[test]
fn service_calls_preserve_win64_abi_state() {
    // Microsoft x64 calling convention: at entry RSP % 16 == 8 (return address
    // pushed by CALL). Callee preserves RBX,RBP,RDI,RSI,R12-R15 and XMM6-XMM15.
    // Caller owns 32-byte shadow/home space at [RSP+8, RSP+40). RAX carries the
    // return value; RCX,RDX,R8,R9,R10,R11,XMM0-XMM5 are volatile.
    use Register::{R8, R9, R10, R11, R12, R13, R14, R15, Rax, Rbp, Rbx, Rcx, Rdi, Rdx, Rsi, Rsp};
    let observed = Arc::new(Mutex::new(None::<(u64, u64, [u64; 4], u64)>));
    let seen = observed.clone();
    let (registry, mut memory, trampoline) = bound_service(move |args, cpu, mem| {
        let rsp = cpu.get(Rsp);
        let shadow = [
            mem.read_u64(rsp + 8).unwrap(),
            mem.read_u64(rsp + 16).unwrap(),
            mem.read_u64(rsp + 24).unwrap(),
            mem.read_u64(rsp + 32).unwrap(),
        ];
        *seen.lock().unwrap() = Some((rsp, cpu.rip, shadow, args.rcx));
        // Clobber volatile registers; dispatcher must still return correctly and
        // nonvolatile state must be preserved after return.
        cpu.set(Rcx, 0xA1);
        cpu.set(Rdx, 0xA2);
        cpu.set(R8, 0xA3);
        cpu.set(R9, 0xA4);
        cpu.set(R10, 0xA5);
        cpu.set(R11, 0xA6);
        for (reg, lane) in cpu.xmm[..6].iter_mut().enumerate() {
            *lane = u128::from(0xB0_u64 + reg as u64);
        }
        Ok(0x1122_3344_5566_7788)
    });
    // Win64: before CALL RSP is 16-byte aligned; CALL pushes return address,
    // so callee entry sees RSP % 16 == 8.
    let call_rsp = STACK_TOP - 8;
    assert_eq!(call_rsp % 16, 8);
    memory.write_u64(call_rsp, 0x1234).unwrap();
    for slot in 0..4u64 {
        memory
            .write_u64(call_rsp + 8 + slot * 8, 0xC000 + slot)
            .unwrap();
    }
    let mut cpu = CpuState::new(trampoline, call_rsp);
    let nonvolatile_gpr = [Rbx, Rbp, Rdi, Rsi, R12, R13, R14, R15];
    for (index, register) in nonvolatile_gpr.into_iter().enumerate() {
        cpu.set(register, 0x5AA5_0000_0001_0000 + index as u64);
    }
    for (offset, lane) in cpu.xmm[6..16].iter_mut().enumerate() {
        *lane = u128::from(0xD000_0000_0000_0000_u64 + (offset + 6) as u64);
    }
    cpu.set(Rcx, 0x1357_9BDF_2468_ACE0);
    let result = registry.dispatch(trampoline, &mut cpu, &mut memory);
    assert_eq!(result, Ok(()));
    let (entry_rsp, entry_rip, shadow, entry_rcx) = observed.lock().unwrap().expect("service ran");
    assert_eq!(entry_rip, trampoline);
    assert_eq!(
        entry_rsp, call_rsp,
        "service sees caller RSP at return address"
    );
    assert_eq!(entry_rsp % 16, 8, "Win64 entry RSP must be 8 mod 16");
    assert_eq!(entry_rcx, 0x1357_9BDF_2468_ACE0);
    // Shadow/home space is caller-owned and must be addressable by the service.
    assert_eq!(shadow, [0xC000, 0xC001, 0xC002, 0xC003]);
    for slot in 0..4u64 {
        assert_eq!(
            memory.read_u64(call_rsp + 8 + slot * 8).unwrap(),
            0xC000 + slot,
            "service call must not mutate caller shadow space"
        );
    }
    // Post-return ABI state.
    assert_eq!(cpu.get(Rax), 0x1122_3344_5566_7788);
    assert_eq!(cpu.get(Rsp), call_rsp + 8);
    assert_eq!(cpu.rip, 0x1234);
    for (index, register) in nonvolatile_gpr.into_iter().enumerate() {
        assert_eq!(
            cpu.get(register),
            0x5AA5_0000_0001_0000 + index as u64,
            "nonvolatile {register:?} must be preserved"
        );
    }
    for (offset, lane) in cpu.xmm[6..16].iter().enumerate() {
        let index = offset + 6;
        assert_eq!(
            *lane,
            u128::from(0xD000_0000_0000_0000_u64 + index as u64),
            "nonvolatile xmm{index} must be preserved"
        );
    }
}

#[test]
fn a_call_that_cannot_return_runs_no_service() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let (registry, mut memory, trampoline) = bound_service(move |_, _, _| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    });
    for rsp in [0x9000_0000, STACK + 0xFFC, u64::MAX - 7] {
        let mut cpu = CpuState::new(trampoline, rsp);
        let before = cpu.clone();
        assert!(
            registry
                .dispatch(trampoline, &mut cpu, &mut memory)
                .is_err()
        );
        assert_eq!(cpu, before);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut cpu = CpuState::new(trampoline, STACK_TOP);
    assert_eq!(registry.dispatch(trampoline, &mut cpu, &mut memory), Ok(()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// --- import table --------------------------------------------------------------

fn inspect(image: &Image) -> ProbeReport {
    probe_pe_bytes(&image.bytes, &ProbeConfig::default()).unwrap()
}

/// File offset of an RVA in the import section.
fn file(rva: u32) -> usize {
    IDATA_RAW + (rva - IDATA_RVA) as usize
}

fn u32_at(image: &Image, at: usize) -> u32 {
    u32::from_le_bytes(image.bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn malformed_import_tables_are_reported_and_never_bound() {
    let base = || {
        build(&[
            ("kernel32.dll", Symbol::Name("GetLastError")),
            ("kernel32.dll", Symbol::Name("CloseHandle")),
        ])
    };
    let end = IDATA_RVA + IDATA_LEN as u32;
    let second = IDATA_RAW + 20;
    type Damage = fn(&mut Image, usize, u32);
    type Expected = fn(&ImportTableError) -> bool;
    // (damage to the second descriptor, expected error)
    let cases: &[(&str, Damage, Expected)] = &[
        (
            "name runs off the section (issue #270)",
            |image, second, end| {
                let lookup = u32_at(image, second);
                image.bytes[file(lookup)..file(lookup) + 8]
                    .copy_from_slice(&u64::from(end - 6).to_le_bytes());
                let at = file(end - 4);
                image.bytes[at..at + 4].copy_from_slice(b"Name");
            },
            |error| matches!(error, ImportTableError::MalformedName { .. }),
        ),
        (
            "name pointer at the last byte",
            |image, second, end| {
                let lookup = u32_at(image, second);
                image.bytes[file(lookup)..file(lookup) + 8]
                    .copy_from_slice(&u64::from(end - 1).to_le_bytes());
            },
            |error| matches!(error, ImportTableError::MalformedName { .. }),
        ),
        (
            "empty name",
            |image, second, _| {
                let lookup = u32_at(image, second);
                let hint = u32_at(image, file(lookup));
                image.bytes[file(hint) + 2] = 0;
            },
            |error| matches!(error, ImportTableError::MalformedName { .. }),
        ),
        (
            "non-ASCII name",
            |image, second, _| {
                let lookup = u32_at(image, second);
                let hint = u32_at(image, file(lookup));
                image.bytes[file(hint) + 4] = 0xC3;
            },
            |error| matches!(error, ImportTableError::MalformedName { .. }),
        ),
        (
            "module name outside every section",
            |image, second, _| {
                image.bytes[second + 12..second + 16].copy_from_slice(&0x7000_0000u32.to_le_bytes())
            },
            |error| matches!(error, ImportTableError::MalformedName { .. }),
        ),
        (
            "lookup table outside every section",
            |image, second, _| {
                image.bytes[second..second + 4].copy_from_slice(&u32::MAX.to_le_bytes())
            },
            |error| matches!(error, ImportTableError::OutOfBounds { .. }),
        ),
        (
            "reserved bits in a name entry",
            |image, second, _| {
                let lookup = u32_at(image, second);
                image.bytes[file(lookup) + 5] = 1;
            },
            |error| matches!(error, ImportTableError::ReservedBits { .. }),
        ),
        (
            "bit 31 in a name entry",
            |image, second, _| {
                let lookup = u32_at(image, second);
                image.bytes[file(lookup) + 3] |= 0x80;
            },
            |error| matches!(error, ImportTableError::ReservedBits { .. }),
        ),
        (
            "name continues in bytes after the section",
            |image, second, end| {
                let lookup = u32_at(image, second);
                image.bytes[file(lookup)..file(lookup) + 8]
                    .copy_from_slice(&u64::from(end - 6).to_le_bytes());
                let at = file(end - 4);
                image.bytes[at..at + 4].copy_from_slice(b"Name");
                image.bytes.extend_from_slice(b"Tail\0");
            },
            |error| matches!(error, ImportTableError::MalformedName { .. }),
        ),
        (
            "reserved bits in an ordinal entry",
            |image, second, _| {
                let lookup = u32_at(image, second);
                image.bytes[file(lookup)..file(lookup) + 8]
                    .copy_from_slice(&(1u64 << 63 | 0x1_0000).to_le_bytes());
            },
            |error| matches!(error, ImportTableError::ReservedBits { .. }),
        ),
    ];
    for (what, damage, expected) in cases {
        let mut image = base();
        damage(&mut image, second, end);
        let (mut registry, _) = standard(0);
        let (result, _) = bind(&mut registry, &image);
        match &result {
            Err(ImportError::Table(error)) => assert!(expected(error), "{what}: {error:?}"),
            other => panic!("{what}: {other:?}"),
        }
        let report = inspect(&image);
        assert_eq!(
            report.import_error.map(ImportError::Table),
            result.err(),
            "{what}"
        );
        assert_eq!(
            report.imports.len(),
            1,
            "{what}: the first import is still listed"
        );
        assert_eq!(report.imports[0].symbol, "GetLastError");
    }
}

#[test]
fn endless_tables_are_bounded() {
    // A descriptor at 0, a module name at 0x40, a hint and name at 0x60 and a
    // lookup entry at 0x80. The mapping repeats one structure without end.
    let mut bytes = vec![0u8; 0x88];
    bytes[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x40..0x46].copy_from_slice(b"m.dll\0");
    bytes[0x62..0x64].copy_from_slice(b"F\0");
    bytes[0x80] = 0x60;

    // Lookup entries repeat from 0x80 on.
    let (entries, error) = parse_imports(&bytes, 0, 20, |rva| {
        let rva = rva as usize;
        Some(if rva < 0x80 { rva } else { 0x80 + rva % 8 })
    });
    assert_eq!(error, Some(ImportTableError::TooManyImports));
    assert_eq!(entries.len(), MAX_IMPORTS);

    // Descriptors repeat from 0x1000 on; each has one symbol.
    bytes.extend([0; 8]);
    let (entries, error) = parse_imports(&bytes, 0x1000, 0x10000, |rva| {
        let rva = rva as usize;
        Some(if rva < 0x1000 {
            rva
        } else {
            (rva - 0x1000) % 20
        })
    });
    assert_eq!(error, Some(ImportTableError::TooManyDescriptors));
    assert_eq!(entries.len(), 1024);
}

#[test]
fn inspection_and_binding_agree_on_damaged_tables() {
    let base = build(&[
        ("kernel32.dll", Symbol::Name("GetLastError")),
        (
            "api-ms-win-core-handle-l1-1-0.dll",
            Symbol::Name("CloseHandle"),
        ),
        ("ucrtbase.dll", Symbol::Name("sqrt")),
        ("o.dll", Symbol::Ordinal(3)),
    ]);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    };
    let (mut bound, mut malformed, mut unresolved) = (0, 0, 0);
    for _ in 0..6000 {
        let mut image = Image {
            bytes: base.bytes.clone(),
            slots: base.slots.clone(),
        };
        for _ in 0..1 + next() % 3 {
            let at = IDATA_RAW + (next() % 0x220) as usize;
            image.bytes[at] = match next() % 4 {
                0 => 0,
                1 => 0xFF,
                _ => next() as u8,
            };
        }
        let (mut registry, _) = standard(0);
        registry
            .try_register(
                "o.dll",
                ImportName::Ordinal(3),
                ServiceStatus::Stub,
                Box::new(|_, _, _| Ok(0)),
            )
            .unwrap();
        let pe = ParsedPe::parse(&image.bytes).unwrap();
        let mut memory = pe.load_into_memory(&image.bytes).unwrap().memory;
        let result = registry.bind_imports(&pe, &image.bytes, BASE, &mut memory);
        let report = inspect(&image);
        match result {
            Ok(count) => {
                bound += 1;
                assert_eq!(report.import_error, None);
                assert_eq!(report.imports.len(), count);
            }
            Err(ImportError::Table(error)) => {
                malformed += 1;
                assert_eq!(report.import_error, Some(error));
            }
            Err(ImportError::UnresolvedImport { module, symbol }) => {
                unresolved += 1;
                assert_eq!(report.import_error, None);
                assert!(
                    report
                        .imports
                        .iter()
                        .any(|import| import.dll == module && import.symbol == symbol)
                );
            }
            Err(ImportError::Memory(_)) => {}
        }
    }
    assert!(
        bound > 100 && malformed > 100 && unresolved > 100,
        "{bound} {malformed} {unresolved}"
    );
}

#[test]
fn inspection_reports_exactly_what_binding_resolves() {
    let image = build(&[
        ("KERNEL32.dll", Symbol::Name("GetLastError")),
        ("kernel32.dll", Symbol::Name("getlasterror")),
        (
            "api-ms-win-core-errorhandling-l1-1-0.dll",
            Symbol::Name("SetLastError"),
        ),
        (
            "api-ms-win-core-errorhandling-l1-1-3.dll",
            Symbol::Name("SetLastError"),
        ),
        ("kernel32.dll", Symbol::Ordinal(1)),
    ]);
    let report = inspect(&image);
    let supported: Vec<bool> = report
        .imports
        .iter()
        .map(|import| import.is_supported)
        .collect();
    assert_eq!(supported, [true, false, true, false, false]);
    assert_eq!(
        report.imports[2].canonical_module.as_deref(),
        Some("kernel32.dll")
    );
    assert_eq!(report.imports[4].symbol, "Ordinal#1");
}

/// The NUL-terminated string at `address` in guest memory.
fn guest_string(memory: &GuestMemory, address: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut at = address;
    loop {
        match memory.read_u8(at).unwrap() {
            0 => break,
            byte => bytes.push(byte),
        }
        at += 1;
    }
    bytes
}

/// A guest that imports one symbol from one module, so that the import table
/// a program built with mingw-w64 has can be bound and run.
fn aliased_guest(module: &'static str, symbol: &'static str) -> (DbtEngine, GuestMemory) {
    let image = build(&[(module, Symbol::Name(symbol))]);
    let pe = ParsedPe::parse(&image.bytes).unwrap();
    let mut memory = pe.load_into_memory(&image.bytes).unwrap().memory;
    memory
        .map_region(SCRATCH, 0x100, MemoryPermissions::READ_WRITE)
        .unwrap();
    memory
        .map_region(STACK, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    let (mut registry, _, _) = standard_with_state(0x01DA_0000_1234_5678);
    let bound = registry
        .bind_imports(&pe, &image.bytes, BASE, &mut memory)
        .unwrap();
    assert_eq!(bound, 1, "{module}!{symbol}");
    let mut engine = DbtEngine::new(256 * 1024).unwrap();
    engine.set_import_registry(registry);
    (engine, memory)
}

/// `fputc` "writes the character converted to unsigned char to the stream and
/// returns it", and returns `EOF` with `errno` set on an error (Microsoft
/// Learn, fputc). The standard streams are text-mode streams, where "each
/// line feed is replaced with a carriage return-line feed pair".
#[test]
fn fputc_writes_one_character_to_a_stream() {
    let (mut guest, [input, out, err]) = stdio_guest();
    assert_eq!(guest.call("fputc", &[u64::from(b'A'), out]), 65);
    assert_eq!(guest.state.standard_output(), b"A");
    // A line feed becomes a carriage return and a line feed.
    assert_eq!(guest.call("fputc", &[u64::from(b'\n'), out]), 10);
    assert_eq!(guest.state.standard_output(), b"A\r\n");
    // stderr keeps its own buffer.
    assert_eq!(guest.call("fputc", &[u64::from(b'!'), err]), 33);
    assert_eq!(guest.state.standard_error(), b"!");
    // The character is converted to unsigned char.
    assert_eq!(guest.call("fputc", &[u64::from(u32::MAX), out]), 255);
    assert_eq!(guest.state.standard_output()[3..], [0xFF]);

    // A null stream is an error.
    guest.set_errno(0);
    assert_eq!(
        guest.call("fputc", &[u64::from(b'A'), 0]) & 0xFFFF_FFFF,
        STDIO_MINUS_ONE
    );
    assert_eq!(guest.errno(), STDIO_EINVAL);
    guest.set_errno(0);
    // stdin cannot be written to, and a pointer that is no stream is not
    // modelled.
    for stream in [input, TEXT, out + 4, 16] {
        assert_eq!(
            guest.run("fputc", &[u64::from(b'A'), stream]).1,
            LIMIT,
            "{stream:#x}"
        );
    }
    assert_eq!(guest.state.standard_output().len(), 4);
    assert_eq!(guest.errno(), 0);
}

/// `strerror` "returns a pointer to the message that describes the error
/// number" (Microsoft Learn, strerror). The message stays valid until the
/// next call. The runtime names the error numbers it uses the way `perror`
/// names them.
#[test]
fn strerror_names_the_error_numbers_the_runtime_uses() {
    let mut guest = Guest::new();
    for (code, text) in [
        (2i32, &b"No such file or directory"[..]),
        (5, &b"Input/output error"[..]),
        (9, &b"Bad file descriptor"[..]),
        (12, &b"Not enough space"[..]),
        (13, &b"Permission denied"[..]),
        (22, &b"Invalid argument"[..]),
        (28, &b"No space left on device"[..]),
        (999, &b"Unknown error"[..]),
        (-1, &b"Unknown error"[..]),
    ] {
        let address = guest.call("strerror", &[code as u64]);
        assert_ne!(address, 0, "code {code}");
        assert_eq!(guest_string(&guest.memory, address), text, "code {code}");
    }
}

/// `localeconv` "gets detailed information about numeric formatting for the
/// current locale" (Microsoft Learn, localeconv). Only the C locale is
/// modelled: its decimal point is ".", its thousands separator and its
/// grouping are empty, and the C locale has no monetary formatting, so every
/// numeric member is `CHAR_MAX`, the value of a member the current locale
/// does not provide.
#[test]
fn localeconv_returns_the_c_locale() {
    let mut guest = Guest::new();
    let address = guest.call("localeconv", &[]);
    assert_ne!(address, 0);
    let pointer = |index: u64| guest.memory.read_u64(address + 8 * index).unwrap();
    let text = |at: u64| guest_string(&guest.memory, at);
    assert_eq!(text(pointer(0)), b".");
    for index in 1..10 {
        assert_eq!(text(pointer(index)), b"", "member {index}");
    }
    for index in 0..8 {
        assert_eq!(
            guest.memory.read_u8(address + 80 + index).unwrap(),
            127,
            "member {index}"
        );
    }
}

/// The C locale is single-byte, so one byte is one character. `mbrtowc`
/// "returns the number of bytes in the multibyte character", or `(size_t)-1`
/// if it is not a valid multibyte character (Microsoft Learn, mbrtowc);
/// `wcrtomb` "returns the number of bytes written", or `(size_t)-1` if the
/// wide character cannot be represented (Microsoft Learn, wcrtomb). The
/// `mbstate_t` is not used in the C locale.
#[test]
fn mbrtowc_and_wcrtomb_convert_the_characters_of_the_c_locale() {
    let mut guest = Guest::new();
    guest
        .memory
        .map_region(TEXT, TEXT_LEN, MemoryPermissions::READ_WRITE)
        .unwrap();
    let wide = TEXT;
    let narrow = TEXT + 0x100;
    let state = TEXT + 0x200;
    let untouched = 0x1234_5678_9ABC_DEF0;
    guest.memory.write_u64(state, untouched).unwrap();

    // A byte of the basic character set is one wide character.
    assert_eq!(guest.call("mbrtowc", &[wide, 1, u64::from(b'A'), 0]), 1);
    assert_eq!(guest.memory.read_u32(wide).unwrap(), u32::from(b'A'));
    // A byte above the basic character set is not a character of the C locale.
    assert_eq!(guest.call("mbrtowc", &[wide, 1, 0x80, 0]), u64::MAX);
    // The null character is a character of no bytes.
    assert_eq!(guest.call("mbrtowc", &[wide, 1, 0, 0]), 0);
    assert_eq!(guest.memory.read_u32(wide).unwrap(), 0);
    // Nothing to convert.
    assert_eq!(guest.call("mbrtowc", &[wide, 0, u64::from(b'A'), 0]), 0);
    // The conversion happens without a place to put it.
    assert_eq!(guest.call("mbrtowc", &[0, 1, u64::from(b'A'), 0]), 1);
    // The state is left alone.
    assert_eq!(guest.call("mbrtowc", &[wide, 1, u64::from(b'A'), state]), 1);
    assert_eq!(guest.memory.read_u64(state).unwrap(), untouched);

    // A wide character of the basic character set is one byte.
    assert_eq!(guest.call("wcrtomb", &[narrow, u64::from(b'A'), 0]), 1);
    assert_eq!(guest.memory.read_u8(narrow).unwrap(), b'A');
    // A wide character the C locale cannot represent.
    assert_eq!(guest.call("wcrtomb", &[narrow, 0x100, 0]), u64::MAX);
    // The conversion happens without a place to put it.
    assert_eq!(guest.call("wcrtomb", &[0, u64::from(b'A'), 0]), 1);
    // The state is left alone.
    assert_eq!(guest.call("wcrtomb", &[narrow, u64::from(b'A'), state]), 1);
    assert_eq!(guest.memory.read_u64(state).unwrap(), untouched);
}

/// `_lock_file` "returns 0 if the file is locked successfully" and -1 with
/// `errno` set to `EBADF` for an invalid file (Microsoft Learn, _lock_file).
/// The lock itself does nothing: Xenora's guest scheduler runs one guest
/// thread at a time, so two guest threads can never hold the same stream at
/// once.
#[test]
fn locking_a_stream_succeeds_and_a_null_stream_fails() {
    let (mut guest, [input, out, _]) = stdio_guest();
    // The mode of the lock does not change the result.
    for mode in [0u64, 1, 2] {
        assert_eq!(guest.call("_lock_file", &[out, mode]) & 0xFFFF_FFFF, 0);
        assert_eq!(guest.call("_unlock_file", &[out]) & 0xFFFF_FFFF, 0);
    }
    // A stream that cannot be written to can still be locked.
    assert_eq!(guest.call("_lock_file", &[input, 0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_unlock_file", &[input]) & 0xFFFF_FFFF, 0);

    // A null stream is an invalid file.
    guest.set_errno(0);
    assert_eq!(
        guest.call("_lock_file", &[0, 0]) & 0xFFFF_FFFF,
        STDIO_MINUS_ONE
    );
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    assert_eq!(
        guest.call("_unlock_file", &[0]) & 0xFFFF_FFFF,
        STDIO_MINUS_ONE
    );
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    // A pointer that is no stream is not modelled.
    for stream in [TEXT, out + 4, 16] {
        assert_eq!(
            guest.run("_lock_file", &[stream, 0]).1,
            LIMIT,
            "{stream:#x}"
        );
        assert_eq!(guest.run("_unlock_file", &[stream]).1, LIMIT, "{stream:#x}");
    }
    assert_eq!(guest.errno(), 0);
}

/// The API set a program built with mingw-w64 imports `memmove` from
/// forwards it to `ucrtbase.dll`, so a guest that imports it that way binds
/// and runs.
#[test]
fn memmove_binds_through_the_private_api_set() {
    const PRIVATE: &str = "api-ms-win-crt-private-l1-1-0.dll";
    let (mut engine, mut memory) = aliased_guest(PRIVATE, "memmove");
    let source = SCRATCH;
    let destination = SCRATCH + 0x40;
    memory.write_bytes(source, b"moved").unwrap();
    let mut cpu = CpuState::new(BASE + u64::from(CODE_RVA), STACK_TOP);
    cpu.set(Register::Rcx, destination);
    cpu.set(Register::Rdx, source);
    cpu.set(Register::R8, 5);
    let result = engine.run(&mut cpu, &mut memory, 8);
    assert_eq!(result.exit_reason, ExitReason::Halt);
    let moved: Vec<u8> = (0..5)
        .map(|index| memory.read_u8(destination + index).unwrap())
        .collect();
    assert_eq!(moved, b"moved");
}

#[test]
fn crt_getpid_matches_the_process_identity() {
    let mut guest = Guest::new();
    let win32 = guest.call("GetCurrentProcessId", &[]);
    assert_eq!(guest.call("_getpid", &[]), win32);
}

/// Regression checks for three descriptor edge cases: a read past the end
/// keeps the seeked position, a zero-byte write does not extend the file,
/// and a full descriptor table refuses before creating or truncating.
#[test]
fn descriptor_edges_past_the_end_and_a_full_table() {
    let (mut guest, _streams) = stdio_guest();
    store(&mut guest, "edge.bin", b"abc");
    guest.memory.write_bytes(NAME, b"edge.bin\0").unwrap();
    let fd = guest.call("_open", &[NAME, 2 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!(fd >= 3, "{fd:x}");
    // Seek past the end, read: nothing read, position stays at 8.
    assert_eq!(guest.call("_lseek", &[fd, 8, 0]) & 0xFFFF_FFFF, 8);
    assert_eq!(guest.call("_read", &[fd, SCRATCH, 1]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_lseek", &[fd, 0, 1]) & 0xFFFF_FFFF, 8);
    // A zero-byte write there does not extend the file: a second descriptor
    // still sees the end at offset 3.
    assert_eq!(guest.call("_write", &[fd, SCRATCH, 0]) & 0xFFFF_FFFF, 0);
    let probe = guest.call("_open", &[NAME, 0x8000, 0]) & 0xFFFF_FFFF;
    assert_eq!(guest.call("_lseek", &[probe, 0, 2]) & 0xFFFF_FFFF, 3);
    assert_eq!(guest.call("_close", &[probe]) & 0xFFFF_FFFF, 0);
    // A real write lands at 8 and does extend, with the gap zeroed.
    guest.memory.write_bytes(SCRATCH, b"Z").unwrap();
    assert_eq!(guest.call("_write", &[fd, SCRATCH, 1]) & 0xFFFF_FFFF, 1);
    let probe = guest.call("_open", &[NAME, 0x8000, 0]) & 0xFFFF_FFFF;
    assert_eq!(guest.call("_lseek", &[probe, 0, 2]) & 0xFFFF_FFFF, 9);
    assert_eq!(guest.call("_close", &[probe]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
}

/// `fputws`/`fgetws`/`putwchar`/`getwchar` in the C locale: every byte is
/// its wide character, the C orientation is enforced, and a wide character
/// above 255 fails the write.
#[test]
fn wide_stream_io_writes_and_reads_in_the_c_locale() {
    let (mut guest, [_stdin, stdout, _error]) = stdio_guest();
    let wide: Vec<u8> = b"wide line\n"
        .iter()
        .flat_map(|byte| [*byte, 0])
        .chain([0, 0])
        .collect();
    guest.memory.write_bytes(STRINGS, &wide).unwrap();
    let file = opened(&mut guest, "wide-a.txt", "w+b");
    // fputws returns a non-negative value on success, never WEOF.
    assert!(guest.call("fputws", &[STRINGS, file]) < 0xFFFF);
    close(&mut guest, file);
    assert!(guest.state.standard_output().is_empty());

    let file = opened(&mut guest, "wide-a.txt", "r");
    guest.memory.write_bytes(SCRATCH, &[0xEE; 64]).unwrap();
    assert_eq!(guest.call("fgetws", &[SCRATCH, 32, file]), SCRATCH);
    let mut back = Vec::new();
    for at in 0..11u64 {
        back.push(guest.memory.read_u16(SCRATCH + at * 2).unwrap() as u8);
    }
    assert_eq!(&back[..10], b"wide line\n");
    assert_eq!(back[10], 0);
    close(&mut guest, file);

    // putwchar writes the byte of the character in the C locale.
    assert_eq!(guest.call("putwchar", &[u64::from(b'A')]), u64::from(b'A'));
    assert_eq!(guest.state.standard_output(), b"A");
    // stdout is wide-oriented now: a byte write on it fails, as the CRT
    // fails the conflict.
    let byte = place(&mut guest, STRINGS + 0x40, b"B");
    assert_eq!(
        guest.call("fputs", &[byte, stdout]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    // A wide character above 255 cannot convert in the C locale.
    assert_eq!(guest.call("putwchar", &[0x100]), 0xFFFF);

    // getwchar reads one byte as its wide character.
    let (mut guest, _streams) = stdio_guest();
    guest.state.set_standard_input(b"Hi there");
    assert_eq!(guest.call("getwchar", &[]), u64::from(b'H'));
    assert_eq!(guest.call("getwchar", &[]), u64::from(b'i'));
    // stdin is wide-oriented now: getchar answers EOF for the conflict.
    assert_eq!(guest.call("getchar", &[]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
}

/// Write the wide units of a string and return their address.
fn place_wide(guest: &mut Guest, at: u64, text: &str) -> u64 {
    let mut bytes = Vec::new();
    for unit in text.encode_utf16().chain([0]) {
        bytes.extend(unit.to_le_bytes());
    }
    guest.memory.write_bytes(at, &bytes).unwrap();
    at
}

/// `__stdio_common_vswprintf` in the C locale: the syntax is printf's, the
/// counting is in wide units, `%s` is the wide string and `%S` the narrow
/// one, and truncation follows the same option bits as the narrow forms.
#[test]
fn wide_buffer_formatting_counts_in_wide_units() {
    let (mut guest, _streams) = stdio_guest();
    let wide_print = |guest: &mut Guest, format_addr: u64, count: u64, slots: &[u64]| -> u64 {
        for (index, slot) in slots.iter().enumerate() {
            guest
                .memory
                .write_u64(VA_LIST + 8 * index as u64, *slot)
                .unwrap();
        }
        guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
        guest.memory.write_u64(STACK_TOP + 40, VA_LIST).unwrap();
        let (cpu, exit) = guest.run(
            "__stdio_common_vswprintf",
            &[STANDARD, SCRATCH, count, format_addr],
        );
        assert_eq!(exit, ExitReason::Halt);
        cpu.get(Register::Rax) & 0xFFFF_FFFF
    };
    let read_wide = |guest: &Guest, at: u64, len: usize| -> String {
        let mut units = Vec::new();
        for index in 0..len as u64 {
            let unit = guest.memory.read_u16(at + index * 2).unwrap();
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16(&units).unwrap()
    };

    // Integers, a wide string, a narrow one, both characters, padding.
    let wide_arg = place_wide(&mut guest, STRINGS, "wide");
    let narrow_arg = place(&mut guest, STRINGS + 0x40, b"narrow");
    let format = place_wide(&mut guest, TEXT, "n=%d w=%s s=%S c=%c%C pad=%5u!");
    let result = wide_print(
        &mut guest,
        format,
        64,
        &[
            42,
            wide_arg,
            narrow_arg,
            u64::from(b'W'),
            u64::from(b'n'),
            7,
        ],
    );
    assert_eq!(
        read_wide(&guest, SCRATCH, 64),
        "n=42 w=wide s=narrow c=Wn pad=    7!"
    );
    assert_eq!(
        result as usize,
        "n=42 w=wide s=narrow c=Wn pad=    7!".len()
    );

    // The terminator is one wide zero, and truncation counts in units.
    let format = place_wide(&mut guest, TEXT, "abcdef");
    guest.memory.write_bytes(SCRATCH, &[0xEE; 32]).unwrap();
    assert_eq!(wide_print(&mut guest, format, 4, &[]), 6);
    // "abc" and the wide terminator, then the untouched sentinel bytes.
    assert_eq!(read_wide(&guest, SCRATCH, 4), "abc");
    assert_eq!(guest.memory.read_u16(SCRATCH + 6).unwrap(), 0);
    assert_eq!(guest.memory.read_u8(SCRATCH + 8).unwrap(), 0xEE);

    // The size query: null buffer, zero count, the would-be length.
    let format = place_wide(&mut guest, TEXT, "%d%d%d");
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    guest.memory.write_u64(STACK_TOP + 40, VA_LIST).unwrap();
    for (index, slot) in [1u64, 22, 333].iter().enumerate() {
        guest
            .memory
            .write_u64(VA_LIST + 8 * index as u64, *slot)
            .unwrap();
    }
    let (cpu, exit) = guest.run("__stdio_common_vswprintf", &[STANDARD, 0, 0, format]);
    assert_eq!(exit, ExitReason::Halt);
    assert_eq!(cpu.get(Register::Rax) & 0xFFFF_FFFF, 6);

    // A width or precision from the arguments, as the narrow forms read it.
    let wide_arg2 = place_wide(&mut guest, STRINGS + 0x60, "xy");
    let format = place_wide(&mut guest, TEXT, "%*s");
    assert_eq!(wide_print(&mut guest, format, 16, &[6, wide_arg2]), 6);
    assert_eq!(read_wide(&guest, SCRATCH, 8), "    xy");

    // %n is invalid here as it is there.
    let format = place_wide(&mut guest, TEXT, "%n");
    assert_eq!(wide_print(&mut guest, format, 16, &[]), u32::MAX as u64);
}

/// Call a service whose arguments past the fourth ride the guest stack
/// above the shadow space, as compiled code passes them.
fn call6(guest: &mut Guest, symbol: &str, args: &[u64]) -> u64 {
    for (index, arg) in args.iter().enumerate().skip(4) {
        guest
            .memory
            .write_u64(STACK_TOP + 32 + 8 * (index - 4) as u64, *arg)
            .unwrap();
    }
    let registers = args.len().min(4);
    guest.call(symbol, &args[..registers])
}

#[test]
fn multibyte_to_wide_converts_utf8_and_the_ansi_page() {
    let mut guest = Guest::new();
    guest
        .memory
        .map_region(CPBUF, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    // UTF-8 "h\u{e9}\u{20ac}": three characters, five bytes plus terminator.
    let text = place(&mut guest, CPBUF, "h\u{e9}\u{20ac}".as_bytes());
    let asked = call6(
        &mut guest,
        "MultiByteToWideChar",
        &[65001, 0, text, u64::MAX, 0, 0],
    );
    assert_eq!(asked, 4, "the terminator counts under a -1 byte count");
    let out = SCRATCH;
    let wrote = call6(
        &mut guest,
        "MultiByteToWideChar",
        &[65001, 0, text, u64::MAX, out, asked],
    );
    assert_eq!(wrote, 4);
    assert_eq!(guest.memory.read_u16(out).unwrap(), u16::from(b'h'));
    assert_eq!(guest.memory.read_u16(out + 2).unwrap(), 0xE9);
    assert_eq!(guest.memory.read_u16(out + 4).unwrap(), 0x20AC);
    assert_eq!(guest.memory.read_u16(out + 6).unwrap(), 0);
    // A positive byte count converts exactly that many bytes.
    let exact = call6(
        &mut guest,
        "MultiByteToWideChar",
        &[65001, 0, text, 1, out, 8],
    );
    assert_eq!(exact, 1);
    // The ANSI page: byte 0x80 is the euro sign, 0x81 is undefined.
    place(&mut guest, CPBUF + 0x40, &[0x80, 0x81]);
    let ansi = call6(
        &mut guest,
        "MultiByteToWideChar",
        &[1252, 0, CPBUF + 0x40, 2, out, 8],
    );
    assert_eq!(ansi, 2);
    assert_eq!(guest.memory.read_u16(out).unwrap(), 0x20AC);
    assert_eq!(
        guest.memory.read_u16(out + 2).unwrap(),
        0xFFFD,
        "a byte the page leaves undefined is replaced"
    );
    // CP_ACP resolves to UTF-8, the runtime's ANSI page: the ASCII byte
    // converts as itself.
    let pseudo = call6(&mut guest, "MultiByteToWideChar", &[0, 0, CPBUF, 1, out, 8]);
    assert_eq!(pseudo, 1);
    assert_eq!(guest.memory.read_u16(out).unwrap(), u16::from(b'h'));
    // A malformed sequence fails under MB_ERR_INVALID_CHARS and is replaced
    // without it.
    place(&mut guest, CPBUF + 0x80, &[0xFF]);
    let strict = call6(
        &mut guest,
        "MultiByteToWideChar",
        &[65001, 8, CPBUF + 0x80, 1, out, 8],
    );
    assert_eq!(strict, 0);
    assert_eq!(guest.last_error(), 1113, "ERROR_NO_UNICODE_TRANSLATION");
    let lenient = call6(
        &mut guest,
        "MultiByteToWideChar",
        &[65001, 0, CPBUF + 0x80, 1, out, 8],
    );
    assert_eq!(lenient, 1);
    assert_eq!(guest.memory.read_u16(out).unwrap(), 0xFFFD);
    // The failures: an unknown page, a zero byte count, flags past the one
    // documented, and a small output buffer.
    assert_eq!(
        call6(
            &mut guest,
            "MultiByteToWideChar",
            &[99999, 0, text, 1, out, 8]
        ),
        0
    );
    assert_eq!(guest.last_error(), 87, "ERROR_INVALID_PARAMETER");
    assert_eq!(
        call6(
            &mut guest,
            "MultiByteToWideChar",
            &[65001, 0, text, 0, out, 8]
        ),
        0
    );
    assert_eq!(guest.last_error(), 87);
    assert_eq!(
        call6(
            &mut guest,
            "MultiByteToWideChar",
            &[65001, 2, text, 1, out, 8]
        ),
        0
    );
    assert_eq!(guest.last_error(), 1004, "ERROR_INVALID_FLAGS");
    assert_eq!(
        call6(
            &mut guest,
            "MultiByteToWideChar",
            &[65001, 0, text, 4, out, 2]
        ),
        0
    );
    assert_eq!(guest.last_error(), 122, "ERROR_INSUFFICIENT_BUFFER");
}

#[test]
fn wide_char_to_multibyte_converts_utf8_and_marks_defaults() {
    let mut guest = Guest::new();
    guest
        .memory
        .map_region(CPBUF, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    // Wide "h\u{e9}" as units, then a terminator.
    for (index, unit) in [u16::from(b'h'), 0xE9, 0].iter().enumerate() {
        guest
            .memory
            .write_u16(CPBUF + index as u64 * 2, *unit)
            .unwrap();
    }
    let out = SCRATCH;
    let wrote = call6(
        &mut guest,
        "WideCharToMultiByte",
        &[65001, 0, CPBUF, u64::MAX, out, 16, 0, 0],
    );
    assert_eq!(wrote, 4, "h, two bytes for é, and the terminator");
    assert_eq!(guest.memory.read_u8(out).unwrap(), b'h');
    assert_eq!(guest.memory.read_u8(out + 1).unwrap(), 0xC3);
    assert_eq!(guest.memory.read_u8(out + 2).unwrap(), 0xA9);
    assert_eq!(guest.memory.read_u8(out + 3).unwrap(), 0);
    // A character the ANSI page cannot represent becomes the default byte
    // and sets the used-default flag.
    guest.memory.write_u16(CPBUF, 0x4E2D).unwrap();
    guest.memory.write_u16(CPBUF + 2, 0).unwrap();
    let used = SCRATCH + 0x40;
    let ansi = call6(
        &mut guest,
        "WideCharToMultiByte",
        &[1252, 0, CPBUF, u64::MAX, out, 16, 0, used],
    );
    assert_eq!(ansi, 2);
    assert_eq!(guest.memory.read_u8(out).unwrap(), b'?');
    assert_eq!(guest.memory.read_u32(used).unwrap(), 1);
    // The same input fails under WC_ERR_INVALID_CHARS.
    let strict = call6(
        &mut guest,
        "WideCharToMultiByte",
        &[1252, 0x80, CPBUF, u64::MAX, out, 16, 0, 0],
    );
    assert_eq!(strict, 0);
    assert_eq!(guest.last_error(), 1113);
    // UTF-8 refuses the default-character arguments, as documented.
    guest.memory.write_u8(CPBUF + 0x60, b'!').unwrap();
    assert_eq!(
        call6(
            &mut guest,
            "WideCharToMultiByte",
            &[65001, 0, CPBUF, u64::MAX, out, 16, CPBUF + 0x60, 0]
        ),
        0
    );
    assert_eq!(guest.last_error(), 87);
    // A size query answers the bytes needed: three for the character in
    // UTF-8, one for the terminator.
    let asked = call6(
        &mut guest,
        "WideCharToMultiByte",
        &[65001, 0, CPBUF, u64::MAX, 0, 0, 0, 0],
    );
    assert_eq!(asked, 4);
}

#[test]
fn the_codepages_answer_their_numbers() {
    let mut guest = Guest::new();
    assert_eq!(guest.call("GetACP", &[]), 65001);
    assert_eq!(guest.call("GetOEMCP", &[]), 437);
    assert_eq!(guest.call("IsValidCodePage", &[1252]), 1);
    assert_eq!(guest.call("IsValidCodePage", &[437]), 1);
    assert_eq!(guest.call("IsValidCodePage", &[65001]), 1);
    assert_eq!(guest.call("IsValidCodePage", &[0]), 0);
    assert_eq!(guest.call("IsValidCodePage", &[99999]), 0);
    let info = SCRATCH;
    assert_eq!(guest.call("GetCPInfo", &[1252, info]), 1);
    assert_eq!(guest.memory.read_u32(info).unwrap(), 1);
    assert_eq!(guest.call("GetCPInfo", &[65001, info]), 1);
    assert_eq!(guest.memory.read_u32(info).unwrap(), 4);
    assert_eq!(guest.call("GetCPInfo", &[99999, info]), 0);
    assert_eq!(guest.last_error(), 87);
}

#[test]
fn the_locale_is_en_us_and_answers_its_strings() {
    let mut guest = Guest::new();
    guest
        .memory
        .map_region(CPBUF, 0x1000, MemoryPermissions::READ_WRITE)
        .unwrap();
    assert_eq!(guest.call("GetSystemDefaultLCID", &[]), 0x0409);
    assert_eq!(guest.call("GetUserDefaultLCID", &[]), 0x0409);
    assert_eq!(guest.call("GetUserDefaultLangID", &[]), 0x0409);
    // The locale name comes as wide units, its count including the
    // terminator, and the size query agrees.
    let asked = guest.call("GetUserDefaultLocaleName", &[0, 0]);
    assert_eq!(asked, 6);
    let wrote = guest.call("GetUserDefaultLocaleName", &[CPBUF, 16]);
    assert_eq!(wrote, 6);
    assert_eq!(guest.memory.read_u16(CPBUF).unwrap(), u16::from(b'e'));
    assert_eq!(guest.memory.read_u16(CPBUF + 6).unwrap(), u16::from(b'U'));
    assert_eq!(guest.memory.read_u16(CPBUF + 10).unwrap(), 0);
    assert_eq!(guest.call("GetUserDefaultLocaleName", &[CPBUF, 4]), 0);
    assert_eq!(guest.last_error(), 122, "ERROR_INSUFFICIENT_BUFFER");
    // LOCALE_SENGLANGUAGE (0x1001) is "English" in every form.
    let wide = guest.call("GetLocaleInfoW", &[0x0409, 0x1001, CPBUF, 32]);
    assert_eq!(wide, 8, "seven letters and the terminator");
    assert_eq!(guest.memory.read_u16(CPBUF).unwrap(), u16::from(b'E'));
    let narrow = guest.call("GetLocaleInfoA", &[0x0409, 0x1001, CPBUF, 32]);
    assert_eq!(narrow, 8);
    assert_eq!(guest.memory.read_u8(CPBUF).unwrap(), b'E');
    assert_eq!(guest.memory.read_u8(CPBUF + 7).unwrap(), 0);
    // The ex form: a null name is the user default, "en-US" any case names
    // the one locale, anything else fails.
    place(&mut guest, CPBUF + 0x40, b"E\0N\0-\0u\0s\0\0\0");
    // The units above were placed as bytes; write them properly as units.
    for (index, unit) in [b'E', b'N', b'-', b'u', b's', 0u8].iter().enumerate() {
        guest
            .memory
            .write_u16(CPBUF + 0x40 + index as u64 * 2, u16::from(*unit))
            .unwrap();
    }
    let ex = guest.call("GetLocaleInfoEx", &[CPBUF + 0x40, 0x005C, CPBUF, 32]);
    assert_eq!(ex, 6, "en-US and its terminator");
    let null_name = guest.call("GetLocaleInfoEx", &[0, 0x000E, CPBUF, 32]);
    assert_eq!(null_name, 2, "the decimal point and its terminator");
    assert_eq!(guest.memory.read_u16(CPBUF).unwrap(), u16::from(b'.'));
    // The failures: another locale, an unknown type, the number form.
    assert_eq!(
        guest.call("GetLocaleInfoW", &[0x040C, 0x1001, CPBUF, 32]),
        0
    );
    assert_eq!(guest.last_error(), 87, "ERROR_INVALID_PARAMETER");
    assert_eq!(
        guest.call("GetLocaleInfoW", &[0x0409, 0x7777, CPBUF, 32]),
        0
    );
    assert_eq!(guest.last_error(), 87);
    assert_eq!(
        guest.call("GetLocaleInfoW", &[0x0409, 0x2000_000E, CPBUF, 32]),
        0
    );
    assert_eq!(guest.last_error(), 87);
    // The size query and the small buffer.
    assert_eq!(guest.call("GetLocaleInfoW", &[0x0409, 0x1001, 0, 0]), 8);
    assert_eq!(guest.call("GetLocaleInfoW", &[0x0409, 0x1001, CPBUF, 4]), 0);
    assert_eq!(guest.last_error(), 122);
}

/// Writes args 5 and 6 to the guest stack above the shadow space, then calls
/// with the first four in registers: the Microsoft x64 calling convention.

#[test]
fn the_string_comparison_services_answer_in_byte_order() {
    let mut guest = Guest::new();
    place(&mut guest, SCRATCH, b"Hello");
    place(&mut guest, SCRATCH + 0x10, b"HELLO");
    place(&mut guest, SCRATCH + 0x20, b"world");
    // Wide "AbC" at 0x30 and "aBc" at 0x40.
    for (base, text) in [(0x30u64, "AbC"), (0x40, "aBc")] {
        for (index, unit) in text.encode_utf16().chain([0]).enumerate() {
            guest
                .memory
                .write_u16(SCRATCH + base + index as u64 * 2, unit)
                .unwrap();
        }
    }

    // The lengths count without the terminator, narrow in bytes and wide in units.
    assert_eq!(guest.call("lstrlenA", &[SCRATCH]), 5);
    assert_eq!(guest.call("lstrlenW", &[SCRATCH + 0x30]), 3);

    // lstrcpy copies with the terminator and hands the destination back.
    let copied = guest.call("lstrcpyA", &[SCRATCH + 0x60, SCRATCH + 0x20]);
    assert_eq!(copied, SCRATCH + 0x60);
    assert_eq!(guest_string(&guest.memory, SCRATCH + 0x60), b"world");

    // lstrcmp is ordinal; the case-insensitive form folds ASCII letters.
    assert_eq!(guest.call("lstrcmpA", &[SCRATCH, SCRATCH]) as i32, 0);
    // Ordinal: 'e'(0x65) > 'E'(0x45), so "Hello" sorts after "HELLO".
    assert!((guest.call("lstrcmpA", &[SCRATCH, SCRATCH + 0x10]) as i32) > 0);
    assert!((guest.call("lstrcmpA", &[SCRATCH + 0x10, SCRATCH]) as i32) < 0);
    assert_eq!(
        guest.call("lstrcmpiA", &[SCRATCH, SCRATCH + 0x10]) as i32,
        0
    );
    assert!((guest.call("lstrcmpiA", &[SCRATCH, SCRATCH + 0x20]) as i32) != 0);

    // CompareString answers 1/2/3 for less/equal/greater, byte order in both
    // widths, the case fold only when asked. -1 counts the terminator.
    let args = [0x0409, 0, SCRATCH, u64::MAX, SCRATCH, u64::MAX];
    assert_eq!(call6(&mut guest, "CompareStringA", &args), 2);
    // Ordinal byte order: 'e'(0x65) sorts after 'E'(0x45), so "Hello" is greater.
    let args = [0x0409, 0, SCRATCH, u64::MAX, SCRATCH + 0x10, u64::MAX];
    assert_eq!(call6(&mut guest, "CompareStringA", &args), 3);
    let args = [0x0409, 1, SCRATCH, u64::MAX, SCRATCH + 0x10, u64::MAX];
    assert_eq!(call6(&mut guest, "CompareStringA", &args), 2);
    let args = [
        0x0409,
        0,
        SCRATCH + 0x30,
        u64::MAX,
        SCRATCH + 0x40,
        u64::MAX,
    ];
    assert_eq!(call6(&mut guest, "CompareStringW", &args), 1); // 'A'<'a' ordinal
    let args = [
        0x0409,
        1,
        SCRATCH + 0x30,
        u64::MAX,
        SCRATCH + 0x40,
        u64::MAX,
    ];
    assert_eq!(call6(&mut guest, "CompareStringW", &args), 2);

    // Failures: another locale, unsupported flags.
    let args = [0x040C, 0, SCRATCH, u64::MAX, SCRATCH, u64::MAX];
    assert_eq!(call6(&mut guest, "CompareStringA", &args), 0);
    assert_eq!(guest.last_error(), 87);
    let args = [0x0409, 4, SCRATCH, u64::MAX, SCRATCH, u64::MAX];
    assert_eq!(call6(&mut guest, "CompareStringA", &args), 0);
    assert_eq!(guest.last_error(), 87);

    // GetStringTypeW classifies ASCII for CT_CTYPE1, terminator included for -1.
    let got = guest.call(
        "GetStringTypeW",
        &[1, SCRATCH + 0x30, u64::MAX, SCRATCH + 0x80],
    );
    assert_eq!(got, 1);
    let upper_alpha = 0x1 | 0x100 | 0x80; // 'A' is upper, alpha, xdigit
    assert_eq!(guest.memory.read_u16(SCRATCH + 0x80).unwrap(), upper_alpha);
    let lower_alpha = 0x2 | 0x100 | 0x80; // 'b' is lower, alpha and a hex digit
    assert_eq!(guest.memory.read_u16(SCRATCH + 0x82).unwrap(), lower_alpha);
    let upper_c = 0x1 | 0x100 | 0x80; // 'C' is upper, alpha and a hex digit
    assert_eq!(guest.memory.read_u16(SCRATCH + 0x84).unwrap(), upper_c);
    // The terminator is classified too for -1: U+0000 is a control character.
    assert_eq!(guest.memory.read_u16(SCRATCH + 0x86).unwrap(), 0x20);
    // CT_CTYPE2 is refused.
    let got = guest.call(
        "GetStringTypeW",
        &[2, SCRATCH + 0x30, u64::MAX, SCRATCH + 0x80],
    );
    assert_eq!(got, 0);
    assert_eq!(guest.last_error(), 87);

    // LCMapStringW maps ASCII case, counts the terminator for -1, answers the
    // required size for a null destination, and fails a small buffer.
    let wrote = call6(
        &mut guest,
        "LCMapStringW",
        &[0x0409, 0x200, SCRATCH + 0x40, u64::MAX, SCRATCH + 0xA0, 8],
    );
    assert_eq!(wrote, 4);
    assert_eq!(
        guest.memory.read_u16(SCRATCH + 0xA0).unwrap(),
        u16::from(b'A')
    );
    assert_eq!(
        guest.memory.read_u16(SCRATCH + 0xA2).unwrap(),
        u16::from(b'B')
    );
    assert_eq!(guest.memory.read_u16(SCRATCH + 0xA6).unwrap(), 0);
    let asked = call6(
        &mut guest,
        "LCMapStringW",
        &[0x0409, 0x100, SCRATCH + 0x40, u64::MAX, 0, 0],
    );
    assert_eq!(asked, 4);
    let small = call6(
        &mut guest,
        "LCMapStringW",
        &[0x0409, 0x200, SCRATCH + 0x40, u64::MAX, SCRATCH + 0xA0, 2],
    );
    assert_eq!(small, 0);
    assert_eq!(guest.last_error(), 122);
    // Sort keys and friends are refused.
    let bad = call6(
        &mut guest,
        "LCMapStringW",
        &[0x0409, 0x400, SCRATCH + 0x40, u64::MAX, SCRATCH + 0xA0, 8],
    );
    assert_eq!(bad, 0);
    assert_eq!(guest.last_error(), 87);
}

#[test]
fn the_console_identity_and_standard_handles_round_trip() {
    let mut guest = Guest::new();

    // The three devices answer one fixed pseudo-handle each, distinct.
    let input = guest.call("GetStdHandle", &[0xFFFF_FFF6]);
    let output = guest.call("GetStdHandle", &[0xFFFF_FFF5]);
    let error = guest.call("GetStdHandle", &[0xFFFF_FFF4]);
    assert!(input != 0 && output != 0 && error != 0);
    assert!(input != output && output != error && input != error);
    // An unknown device fails.
    assert_eq!(guest.call("GetStdHandle", &[0xFFFF_FF00]), 0);
    assert_eq!(guest.last_error(), 87);

    // The console code pages are UTF-8, coherent with the process code page.
    assert_eq!(guest.call("GetConsoleCP", &[]), 65001);
    assert_eq!(guest.call("GetConsoleOutputCP", &[]), 65001);

    // The modes round-trip; an unknown handle fails.
    assert_eq!(guest.call("GetConsoleMode", &[output, SCRATCH]), 1);
    let default_mode = guest.memory.read_u32(SCRATCH).unwrap();
    assert_ne!(default_mode, 0);
    assert_eq!(guest.call("SetConsoleMode", &[output, 0x3]), 1);
    assert_eq!(guest.call("GetConsoleMode", &[output, SCRATCH]), 1);
    assert_eq!(guest.memory.read_u32(SCRATCH).unwrap(), 0x3);
    assert_eq!(guest.call("GetConsoleMode", &[0xDEAD, SCRATCH]), 0);
    assert_eq!(guest.last_error(), 6);

    // WriteConsoleA appends bytes to the output capture printf uses, and
    // reports the characters consumed. The fifth argument rides the stack.
    place(&mut guest, SCRATCH, b"console-out");
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    let wrote = guest.call("WriteConsoleA", &[output, SCRATCH, 11, SCRATCH + 0x40]);
    assert_eq!(wrote, 1);
    assert_eq!(guest.memory.read_u32(SCRATCH + 0x40).unwrap(), 11);

    // WriteConsoleW converts to UTF-8 in the same capture, in order after it.
    for (index, unit) in "widé".encode_utf16().enumerate() {
        guest
            .memory
            .write_u16(SCRATCH + 0x10 + index as u64 * 2, unit)
            .unwrap();
    }
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    let wrote = guest.call(
        "WriteConsoleW",
        &[output, SCRATCH + 0x10, 4, SCRATCH + 0x40],
    );
    assert_eq!(wrote, 1);
    // é is two UTF-8 bytes: the capture holds the narrow then the wide text.
    let capture = guest.state.standard_output();
    let text = String::from_utf8_lossy(&capture);
    assert!(text.contains("console-out"), "{text}");
    assert!(text.contains("widé"), "{text}");
    assert!(text.find("console-out").unwrap() < text.find("widé").unwrap());

    // WriteConsole to the error handle goes to the error capture instead.
    place(&mut guest, SCRATCH + 0x20, b"err-text");
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    assert_eq!(
        guest.call("WriteConsoleA", &[error, SCRATCH + 0x20, 8, 0]),
        1
    );
    let capture = guest.state.standard_error();
    assert!(String::from_utf8_lossy(&capture).contains("err-text"));

    // A write through the input handle or an unknown handle fails.
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    assert_eq!(guest.call("WriteConsoleA", &[input, SCRATCH, 1, 0]), 0);
    assert_eq!(guest.last_error(), 6);

    // ReadConsoleA hands one line back with CR LF restored, counting bytes.
    guest.state.set_standard_input(b"first line\nsecond");
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    let got = guest.call("ReadConsoleA", &[input, SCRATCH + 0x60, 32, SCRATCH + 0x80]);
    assert_eq!(got, 1);
    assert_eq!(guest.memory.read_u32(SCRATCH + 0x80).unwrap(), 12);
    let mut line = Vec::new();
    for at in 0..12u64 {
        line.push(guest.memory.read_u8(SCRATCH + 0x60 + at).unwrap());
    }
    assert_eq!(line, b"first line\r\n");

    // SetStdHandle stores a replacement and GetStdHandle answers it; a write
    // through the replacement then fails honestly, not silently.
    assert_eq!(guest.call("SetStdHandle", &[0xFFFF_FFF5, 0x5555]), 1);
    assert_eq!(guest.call("GetStdHandle", &[0xFFFF_FFF5]), 0x5555);
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    assert_eq!(guest.call("WriteConsoleA", &[0x5555, SCRATCH, 1, 0]), 0);
    assert_eq!(guest.last_error(), 6);
}

#[test]
fn legacy_function_imports_run_the_same_services() {
    let mut guest = Guest::new();
    // Every legacy import binds: the count assertion in `Guest::new` covers it.
    // `strlen` measures the string the narrow form receives.
    guest.memory.write_bytes(SCRATCH, b"legacy\0").unwrap();
    assert_eq!(guest.call("strlen", &[SCRATCH]), 6);
    // `memcpy` copies and answers the destination.
    assert_eq!(
        guest.call("memcpy", &[SCRATCH + 0x20, SCRATCH, 7]),
        SCRATCH + 0x20
    );
    let mut copied = [0u8; 7];
    guest
        .memory
        .read_bytes(SCRATCH + 0x20, &mut copied)
        .unwrap();
    assert_eq!(&copied, b"legacy\0");
    // `malloc` and `free` round trip.
    let allocation = guest.call("malloc", &[0x40]);
    assert_ne!(allocation, 0);
    guest.call("free", &[allocation]);
    // `strcmp` orders its operands.
    guest
        .memory
        .write_bytes(SCRATCH + 0x40, b"legacy\0")
        .unwrap();
    assert_eq!(guest.call("strcmp", &[SCRATCH, SCRATCH + 0x40]), 0);
    // `memchr` finds the byte and misses the absent one.
    assert_eq!(
        guest.call("memchr", &[SCRATCH, u64::from(b'g'), 6]),
        SCRATCH + 2
    );
    assert_eq!(guest.call("memchr", &[SCRATCH, u64::from(b'z'), 6]), 0);
    // `strchr` finds the terminator itself, as the documentation requires.
    assert_eq!(guest.call("strchr", &[SCRATCH, 0]), SCRATCH + 6);
    // `getenv` misses every name in the empty environment.
    guest.memory.write_bytes(SCRATCH + 0x60, b"PATH\0").unwrap();
    assert_eq!(guest.call("getenv", &[SCRATCH + 0x60]), 0);
}

#[test]
fn legacy_printf_forms_format_and_count() {
    let mut guest = Guest::new();
    // The work area is a heap allocation, larger than the fixture scratch.
    let work = guest.call("malloc", &[0x200]);
    assert_ne!(work, 0);
    // `sprintf` reads its variadic arguments from the calling convention and
    // terminates the text it writes.
    guest.memory.write_bytes(SCRATCH, b"%d-%s\0").unwrap();
    guest.memory.write_bytes(work + 0x40, b"fin\0").unwrap();
    let len = guest.call("sprintf", &[work + 0x80, SCRATCH, 42, work + 0x40]);
    assert_eq!(len, 6);
    let mut text = [0u8; 7];
    guest.memory.read_bytes(work + 0x80, &mut text).unwrap();
    assert_eq!(&text, b"42-fin\0");
    // `_vscprintf` counts the same text through the va_list form: the slots
    // sit contiguously in memory.
    guest.memory.write_u64(work + 0x100, 42).unwrap();
    guest.memory.write_u64(work + 0x108, work + 0x40).unwrap();
    assert_eq!(guest.call("_vscprintf", &[SCRATCH, work + 0x100]), 6);
    // `_vsnprintf` fills what fits and answers -1 when the text does not.
    assert_eq!(
        guest.call("_vsnprintf", &[work + 0x180, 4, SCRATCH, work + 0x100]),
        u64::from(u32::MAX)
    );
    let mut short = [0u8; 4];
    guest.memory.read_bytes(work + 0x180, &mut short).unwrap();
    assert_eq!(&short, b"42-f");
    // Room for the terminator: the text fits and the answer is its length.
    assert_eq!(
        guest.call("_vsnprintf", &[work + 0x180, 7, SCRATCH, work + 0x100]),
        6
    );
    let mut whole = [0u8; 7];
    guest.memory.read_bytes(work + 0x180, &mut whole).unwrap();
    assert_eq!(&whole, b"42-fin\0");
}

#[test]
fn legacy_time_pid_mask_and_random_services_run() {
    let mut guest = Guest::new();
    // `_time64` answers the injected clock: the fixture starts at
    // 0x01DA000012345678 100-nanosecond intervals past 1601 and advances a
    // few ticks an operation, so the seconds sit inside the window the two
    // readings around the call bracket.
    guest.call("GetSystemTimeAsFileTime", &[SCRATCH]);
    let before = guest.memory.read_u64(SCRATCH).unwrap();
    let seconds = guest.call("_time64", &[0]);
    guest.call("GetSystemTimeAsFileTime", &[SCRATCH]);
    let after = guest.memory.read_u64(SCRATCH).unwrap();
    let unix = |filetime: u64| (filetime - 116_444_736_000_000_000) / 10_000_000;
    assert!(unix(before) <= seconds && seconds <= unix(after));
    assert_eq!(seconds, 0x652C_E246);
    // The store form writes the same value through a non-null argument.
    let work = guest.call("malloc", &[0x40]);
    assert_eq!(guest.call("_time64", &[work]), seconds);
    assert_eq!(guest.memory.read_u64(work).unwrap(), seconds);
    // `_tzset` is void and leaves no error behind.
    guest.call("_tzset", &[]);
    // `_umask` answers the previous mask: first zero, then the one just set.
    assert_eq!(guest.call("_umask", &[0o022]), 0);
    assert_eq!(guest.call("_umask", &[0o077]), 0o022);
    // `_getpid` answers the hosted process identifier, as GetCurrentProcessId.
    assert_ne!(guest.call("_getpid", &[]), 0);
    // `rand` follows the documented recurrence from its default seed: the
    // published reference sequence of the legacy CRT is 41, 18467, 6334.
    assert_eq!(guest.call("rand", &[]), 41);
    assert_eq!(guest.call("rand", &[]), 18467);
    assert_eq!(guest.call("rand", &[]), 6334);
    // `srand` restarts the sequence: seed 1 is the default state.
    guest.call("srand", &[1]);
    assert_eq!(guest.call("rand", &[]), 41);
}

#[test]
fn legacy_descriptor_seek_and_tell_positions() {
    let (mut guest, [_stdin, _out, _err]) = stdio_guest();
    let buf = TEXT + 0x4000;
    // Open a file in binary, write eight bytes, and measure with the 64-bit
    // forms: the position after the write is 8.
    guest.memory.write_bytes(NAME, b"fd64.bin\0").unwrap();
    let fd = guest.call("_open", &[NAME, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    guest.memory.write_bytes(buf, b"abcdefgh").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf, 8]) & 0xFFFF_FFFF, 8);
    assert_eq!(guest.call("_telli64", &[fd]), 8);
    // A negative offset from the end reaches position 6, and a positive one
    // from the start reaches past the end, as seeking permits.
    assert_eq!(guest.call("_lseeki64", &[fd, (-2i64) as u64, 2]), 6);
    assert_eq!(guest.call("_telli64", &[fd]), 6);
    assert_eq!(guest.call("_lseeki64", &[fd, 20, 0]), 20);
    // A position before the start and an unknown origin are -1 with EINVAL.
    assert_eq!(guest.call("_lseeki64", &[fd, (-40i64) as u64, 0]), u64::MAX);
    assert_eq!(guest.errno(), EINVAL);
    assert_eq!(guest.call("_lseeki64", &[fd, 0, 9]), u64::MAX);
    // The standard descriptors cannot be sought.
    assert_eq!(guest.call("_lseeki64", &[0, 0, 1]), u64::MAX);
    assert_eq!(guest.errno(), EBADF);
    // `_setmode` answers the previous translation: the file opened binary.
    assert_eq!(guest.call("_setmode", &[fd, 0x4000]), 0x8000);
    assert_eq!(guest.call("_setmode", &[fd, 0x8000]), 0x4000);
    // A bad descriptor and a bad mode are -1 with their errnos.
    assert_eq!(
        guest.call("_setmode", &[77, 0x4000]) & 0xFFFF_FFFF,
        MINUS_ONE
    );
    assert_eq!(guest.errno(), EBADF);
    assert_eq!(
        guest.call("_setmode", &[fd, 0x2000]) & 0xFFFF_FFFF,
        MINUS_ONE
    );
    assert_eq!(guest.errno(), EINVAL);
}

#[test]
fn legacy_descriptor_duplication_shares_the_position() {
    let (mut guest, [_stdin, _out, _err]) = stdio_guest();
    let buf = TEXT + 0x4000;
    guest.memory.write_bytes(NAME, b"dup.bin\0").unwrap();
    let fd = guest.call("_open", &[NAME, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    // `_dup` answers the lowest free descriptor, and a seek through the
    // original moves the position the duplication reads at.
    let copy = guest.call("_dup", &[fd]) & 0xFFFF_FFFF;
    assert_eq!(copy, fd + 1);
    guest.memory.write_bytes(buf, b"abcdefgh").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf, 8]) & 0xFFFF_FFFF, 8);
    assert_eq!(guest.call("_lseeki64", &[fd, 4, 0]), 4);
    let mut bytes = [0u8; 4];
    assert_eq!(guest.call("_read", &[copy, buf, 4]) & 0xFFFF_FFFF, 4);
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"efgh", "the position is shared");
    // Closing the original keeps the file open through the duplication.
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_lseeki64", &[copy, 0, 0]), 0);
    // `_dup2` rewires the target, closing whatever it was, and a target that
    // already is the descriptor is itself.
    assert_eq!(guest.call("_dup2", &[copy, copy]) & 0xFFFF_FFFF, copy);
    assert_eq!(guest.call("_dup2", &[copy, 9]) & 0xFFFF_FFFF, 9);
    assert_eq!(guest.call("_read", &[9, buf, 2]) & 0xFFFF_FFFF, 2);
    // A duplication of nothing and a bad target are -1 with EBADF.
    assert_eq!(guest.call("_dup", &[77]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), EBADF);
    assert_eq!(guest.call("_dup2", &[77, 10]) & 0xFFFF_FFFF, MINUS_ONE);
}

/// `_dup2` over a standard descriptor rewires it for real: the CRT table is
/// authoritative, the console fast path only answers while the table does
/// not carry the descriptor. Writes through a rewired stdout land in the
/// file, seeks work as the file's do, and closing the duplication leaves
/// the slot dead - the console does not come back, exactly as the CRT's
/// closed table entry does not resurrect the standard handle.
#[test]
fn dup2_over_a_standard_descriptor_rewires_the_table() {
    let (mut guest, [_stdin, _out, _err]) = stdio_guest();
    let buf = TEXT + 0x4000;
    guest.memory.write_bytes(NAME, b"redir.bin\0").unwrap();
    let fd = guest.call("_open", &[NAME, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    // stdout becomes the file: a write through descriptor 1 lands in it.
    assert_eq!(guest.call("_dup2", &[fd, 1]) & 0xFFFF_FFFF, 1);
    guest.memory.write_bytes(buf, b"redirected").unwrap();
    assert_eq!(guest.call("_write", &[1, buf, 10]) & 0xFFFF_FFFF, 10);
    // The position is the file's: a seek back and a read through the
    // original descriptor prove the bytes took the file path.
    assert_eq!(guest.call("_lseeki64", &[1, 0, 0]), 0);
    let mut bytes = [0u8; 10];
    assert_eq!(guest.call("_read", &[fd, buf, 10]) & 0xFFFF_FFFF, 10);
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"redirected");
    // stdin rewires the same way: the file feeds descriptor 0.
    assert_eq!(guest.call("_dup2", &[fd, 0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_lseeki64", &[fd, 0, 0]), 0);
    let mut bytes = [0u8; 4];
    assert_eq!(guest.call("_read", &[0, buf, 4]) & 0xFFFF_FFFF, 4);
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"redi");
    // Closing the rewired stdout succeeds and the slot stays dead: no write
    // reaches the console through it again.
    assert_eq!(guest.call("_close", &[1]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_write", &[1, buf, 1]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), EBADF);
    // stderr was never rewired and still writes to its stream.
    guest.memory.write_bytes(buf, b"e").unwrap();
    assert_eq!(guest.call("_write", &[2, buf, 1]) & 0xFFFF_FFFF, 1);
}

/// The exact sequence a shell runs for output redirection: save stdout,
/// rewire it onto the file, close the file's own descriptor, then write
/// through stdout. The close of the original hands the stream to the
/// duplication - the write still reaches the file.
#[test]
fn closing_the_original_descriptor_keeps_the_rewired_stdout() {
    let (mut guest, [_stdin, _out, _err]) = stdio_guest();
    let buf = TEXT + 0x4000;
    guest.memory.write_bytes(NAME, b"redir2.bin\0").unwrap();
    let fd = guest.call("_open", &[NAME, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    assert_eq!(guest.call("_dup2", &[fd, 1]) & 0xFFFF_FFFF, 1);
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(buf, b"redirected").unwrap();
    assert_eq!(guest.call("_write", &[1, buf, 10]) & 0xFFFF_FFFF, 10);
    // and the bytes prove they took the file path, position shared.
    assert_eq!(guest.call("_lseeki64", &[1, 0, 0]), 0);
    let mut bytes = [0u8; 10];
    assert_eq!(guest.call("_read", &[1, buf, 10]) & 0xFFFF_FFFF, 10);
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"redirected");
}

/// `_dup` of a standard descriptor copies it as the CRT's table copies the
/// standard handles: the shell's save-redirect-restore frame. The copy
/// answers as the stream itself from whatever number it hangs on, closing
/// it removes only the copy, and duplicating it back restores the original
/// descriptor exactly as the shell restores it.
#[test]
fn dup_of_a_standard_descriptor_frames_a_redirection() {
    let (mut guest, [_stdin, _out, _err]) = stdio_guest();
    let buf = TEXT + 0x4000;
    guest.memory.write_bytes(NAME, b"frame.bin\0").unwrap();
    let fd = guest.call("_open", &[NAME, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    // save: stdout duplicates where it used to fail.
    let save = guest.call("_dup", &[1]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&save), "{save:x}");
    // redirect: stdout becomes the file.
    assert_eq!(guest.call("_dup2", &[fd, 1]) & 0xFFFF_FFFF, 1);
    guest.memory.write_bytes(buf, b"in-file").unwrap();
    assert_eq!(guest.call("_write", &[1, buf, 7]) & 0xFFFF_FFFF, 7);
    assert!(guest.state.standard_output().is_empty());
    // restore: the copy rewires back, and stdout is the console again.
    assert_eq!(guest.call("_dup2", &[save, 1]) & 0xFFFF_FFFF, 1);
    guest.memory.write_bytes(buf, b"on-console").unwrap();
    assert_eq!(guest.call("_write", &[1, buf, 10]) & 0xFFFF_FFFF, 10);
    assert_eq!(guest.state.standard_output(), b"on-console");
    // the file holds only what its redirection captured.
    assert_eq!(guest.call("_lseeki64", &[fd, 0, 0]), 0);
    let mut bytes = [0u8; 7];
    assert_eq!(guest.call("_read", &[fd, buf, 7]) & 0xFFFF_FFFF, 7);
    guest.memory.read_bytes(buf, &mut bytes).unwrap();
    assert_eq!(&bytes, b"in-file");
    // closing the copy removes it alone: stdout answers as before.
    assert_eq!(guest.call("_close", &[save]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(buf, b"!").unwrap();
    assert_eq!(guest.call("_write", &[1, buf, 1]) & 0xFFFF_FFFF, 1);
    // stdin duplicates as well, and the copy consumes the standard input.
    let input = guest.call("_dup", &[0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&input), "{input:x}");
    assert!(guest.call("_read", &[input, buf, 1]) & 0xFFFF_FFFF <= 1);
    // a duplication of nothing is still nothing.
    assert_eq!(guest.call("_dup", &[77]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), EBADF);
}

#[test]
fn legacy_strdup_and_ldexp_run() {
    let mut guest = Guest::new();
    let text = guest.call("malloc", &[32]);
    guest.memory.write_bytes(text, b"copy me\0").unwrap();
    let copy = guest.call("_strdup", &[text]);
    assert_ne!(copy, 0);
    assert_ne!(copy, text);
    let mut bytes = [0u8; 8];
    guest.memory.read_bytes(copy, &mut bytes).unwrap();
    assert_eq!(&bytes, b"copy me\0");
    // The copy is a heap allocation `free` releases.
    assert_eq!(guest.call("free", &[copy]), 0);
    // `ldexp` takes its exponent in RDX and the value in XMM0: the scaling is
    // exact, 1.5 * 2^4 = 24 and the minimum subnormal is 1.0 scaled by -1074.
    let mut scaled = |bits: u64, exponent: i32| {
        guest.xmm[0] = u128::from(bits);
        let (cpu, exit) = guest.run("ldexp", &[0xDEAD_BEEF, exponent as u64]);
        assert_eq!(exit, ExitReason::Halt);
        cpu.xmm[0] as u64
    };
    assert_eq!(scaled(0x3FF8_0000_0000_0000, 4), 0x4038_0000_0000_0000); // 1.5 -> 24
    assert_eq!(scaled(0x3FF0_0000_0000_0000, -1074), 1); // 1.0 -> min subnormal
    assert_eq!(scaled(0x3FF0_0000_0000_0000, -1075), 0); // underflows to zero
    assert_eq!(scaled(0x7FF0_0000_0000_0000, -5), 0x7FF0_0000_0000_0000); // inf stays
}

#[test]
fn legacy_create_and_temporary_names_run() {
    let mut guest = Guest::new();
    let buf = guest.call("malloc", &[64]);
    // `_creat` makes a writable file the descriptor table serves, truncating
    // an existing one.
    guest.memory.write_bytes(buf, b"cr.bin\0").unwrap();
    let fd = guest.call("_creat", &[buf, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    assert_eq!(guest.call("_write", &[fd, buf, 4]) & 0xFFFF_FFFF, 4);
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    // `_mktemp` rewrites the trailing X run into a free name: the letter
    // first, then the counter's digits, and a second call differs.
    guest.memory.write_bytes(buf, b"tmpXXXXXX\0").unwrap();
    assert_eq!(guest.call("_mktemp", &[buf]), buf);
    let mut first = [0u8; 10];
    guest.memory.read_bytes(buf, &mut first).unwrap();
    assert_eq!(&first[..4], b"tmpa", "{first:?}");
    // Once the name is taken a fresh template answers the next candidate.
    let fd = guest.call("_creat", &[buf, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd));
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(buf, b"tmpXXXXXX\0").unwrap();
    assert_eq!(guest.call("_mktemp", &[buf]), buf);
    let mut second = [0u8; 10];
    guest.memory.read_bytes(buf, &mut second).unwrap();
    assert_ne!(&first[..9], &second[..9], "the taken name is skipped");
    // A template without the X run is null with EINVAL.
    guest.memory.write_bytes(buf, b"plain\0").unwrap();
    assert_eq!(guest.call("_mktemp", &[buf]), 0);
    assert_eq!(guest.errno(), EINVAL);
    assert_eq!(guest.call("_mktemp", &[0]), 0);
}

#[test]
fn legacy_fdopen_wraps_a_descriptor() {
    let mut guest = Guest::new();
    let buf = guest.call("malloc", &[64]);
    guest.memory.write_bytes(buf, b"fd.bin\0").unwrap();
    let fd = guest.call("_open", &[buf, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    // `_fdopen` moves the descriptor's state into a stream: writes through
    // the stream move the position the descriptor reads at, as one file.
    guest.memory.write_bytes(buf + 16, b"rb\0").unwrap();
    let file = guest.call("_fdopen", &[fd, buf + 16]);
    assert_ne!(file, 0);
    guest.memory.write_bytes(buf + 32, b"abcdefgh").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf + 32, 8]) & 0xFFFF_FFFF, 8);
    assert_eq!(guest.call("_lseeki64", &[fd, 0, 0]), 0);
    assert_eq!(guest.call("fgets", &[buf + 40, 5, file]), buf + 40);
    let mut bytes = [0u8; 4];
    guest.memory.read_bytes(buf + 40, &mut bytes).unwrap();
    assert_eq!(&bytes, b"abcd");
    // `fclose` takes the descriptor with it: the fd is no longer open.
    assert_eq!(guest.call("fclose", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, MINUS_ONE);
    // A bad mode string and a standard-stream descriptor are null with EINVAL.
    guest.memory.write_bytes(buf + 16, b"zz\0").unwrap();
    let fd = guest.call("_open", &[buf, 0, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd));
    assert_eq!(guest.call("_fdopen", &[fd, buf + 16]), 0);
    assert_eq!(guest.errno(), EINVAL);
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_fdopen", &[0, buf + 16]), 0);
}

#[test]
fn legacy_fstat64_fills_the_legacy_structure() {
    let mut guest = Guest::new();
    let buf = guest.call("malloc", &[64]);
    let stat = guest.call("malloc", &[64]);
    guest.memory.write_bytes(buf, b"st.bin\0").unwrap();
    let fd = guest.call("_open", &[buf, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    guest.memory.write_bytes(buf + 16, b"12345678").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf + 16, 8]) & 0xFFFF_FFFF, 8);
    // The structure answers the mode of a regular file and the length of the
    // content, at the offsets the cross-compiler fixes.
    assert_eq!(guest.call("_fstat64", &[fd, stat]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.memory.read_u16(stat + 6).unwrap() & 0xF000, 0x8000);
    assert_eq!(guest.memory.read_u64(stat + 24).unwrap(), 8);
    assert_eq!(
        guest.memory.read_u64(stat + 32).unwrap(),
        0,
        "no time model"
    );
    // A descriptor that is not open is -1 with EBADF; a null buffer EINVAL.
    assert_eq!(guest.call("_fstat64", &[77, stat]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), EBADF);
    assert_eq!(guest.call("_fstat64", &[fd, 0]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), EINVAL);
}

/// `_fmode` controls the default translation of `_open`, exactly as the
/// CRT documents: an open whose flags say neither `_O_BINARY` nor `_O_TEXT`
/// translates newlines when the variable is text and not when it is binary
/// (#1312). busybox-w32 links the binary default into the CRT cell at
/// startup, and the exact-size copies of its `tar` depend on the byte
/// counts matching. The control case pins the initial text default, so the
/// pair proves the variable itself acts.
#[test]
fn fmode_controls_the_default_translation_of_open() {
    let mut guest = Guest::new();
    let buf = guest.call("malloc", &[0x100]);
    let write_two = |guest: &mut Guest, name: &[u8]| {
        guest.memory.write_bytes(buf, name).unwrap();
        guest.memory.write_u8(buf + name.len() as u64, 0).unwrap();
        let fd = guest.call("_open", &[buf, 1 | 0x100 | 0x200, 0]) & 0xFFFF_FFFF;
        assert!((3..0x8000).contains(&fd), "{fd:x}");
        guest.memory.write_bytes(buf + 32, b"x\n").unwrap();
        assert_eq!(guest.call("_write", &[fd, buf + 32, 2]) & 0xFFFF_FFFF, 2);
        assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    };
    let raw_len = |guest: &mut Guest, name: &[u8]| -> u64 {
        // Reading the file back through an explicitly binary descriptor
        // counts the bytes the drive really carries.
        guest.memory.write_bytes(buf, name).unwrap();
        guest.memory.write_u8(buf + name.len() as u64, 0).unwrap();
        let fd = guest.call("_open", &[buf, 0 | 0x8000, 0]) & 0xFFFF_FFFF;
        assert!((3..0x8000).contains(&fd), "{fd:x}");
        let mut total = 0;
        loop {
            let n = guest.call("_read", &[fd, buf + 32, 16]) & 0xFFFF_FFFF;
            if n == 0 || n == MINUS_ONE {
                break;
            }
            total += n;
        }
        total
    };
    // The documented initial value is text: the newline pair grows a CR.
    write_two(&mut guest, b"tm1.bin");
    assert_eq!(
        raw_len(&mut guest, b"tm1.bin"),
        3,
        "text default translates"
    );
    // Binary selected: the same open writes the bytes exactly.
    let mode_ptr = guest.call("__p__fmode", &[]);
    assert_ne!(mode_ptr, 0);
    guest.memory.write_u32(mode_ptr, 0x8000).unwrap();
    write_two(&mut guest, b"tm2.bin");
    assert_eq!(
        raw_len(&mut guest, b"tm2.bin"),
        2,
        "binary default is exact"
    );
    // An explicit `_O_BINARY` flag overrides even a text variable, and an
    // explicit `_O_TEXT` overrides a binary one.
    guest.memory.write_u32(mode_ptr, 0x4000).unwrap();
    guest.memory.write_bytes(buf, b"tm3.bin\0").unwrap();
    let fd = guest.call("_open", &[buf, 1 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    guest.memory.write_bytes(buf + 32, b"x\n").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf + 32, 2]) & 0xFFFF_FFFF, 2);
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    assert_eq!(raw_len(&mut guest, b"tm3.bin"), 2, "the flag wins");
}

/// `_fstat64` of a pipe end answers the FIFO mode, as the CRT stats an
/// anonymous pipe: busybox-w32's `tar cf -` stats its standard output to
/// refuse a terminal, and the failure killed archive creation before any
/// byte moved. A handle-wrapped file answers the regular-file mode and the
/// content's length, exactly as a CRT-opened one does.
#[test]
fn legacy_fstat64_stats_pipe_ends_and_handle_wrapped_files() {
    let mut guest = Guest::new();
    let buf = guest.call("malloc", &[64]);
    let stat = guest.call("malloc", &[64]);
    let fds = guest.call("malloc", &[16]);
    assert_eq!(guest.call("_pipe", &[fds, 4096, 0]) & 0xFFFF_FFFF, 0);
    let read = guest.memory.read_u32(fds).unwrap() as u64;
    let write = guest.memory.read_u32(fds + 4).unwrap() as u64;
    for fd in [read, write] {
        assert_eq!(guest.call("_fstat64", &[fd, stat]) & 0xFFFF_FFFF, 0);
        assert_eq!(
            guest.memory.read_u16(stat + 6).unwrap() & 0xF000,
            0x1000,
            "pipe ends answer the FIFO mode"
        );
    }
    // A file opened through the descriptor table keeps the regular mode.
    guest.memory.write_bytes(buf, b"hf.bin\0").unwrap();
    let fd = guest.call("_open", &[buf, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    guest.memory.write_bytes(buf + 16, b"abc").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf + 16, 3]) & 0xFFFF_FFFF, 3);
    assert_eq!(guest.call("_fstat64", &[fd, stat]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.memory.read_u16(stat + 6).unwrap() & 0xF000, 0x8000);
    assert_eq!(guest.memory.read_u64(stat + 24).unwrap(), 3);
}

#[test]
fn legacy_directories_are_made_and_removed() {
    let mut guest = Guest::new();
    let buf = guest.call("malloc", &[64]);
    // `_mkdir` makes the directory a file can be written into, nested or not.
    guest.memory.write_bytes(buf, b"adir\0").unwrap();
    assert_eq!(guest.call("_mkdir", &[buf]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_mkdir", &[buf]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), EEXIST);
    guest.memory.write_bytes(buf, b"adir\\inner\0").unwrap();
    assert_eq!(guest.call("_mkdir", &[buf]) & 0xFFFF_FFFF, 0);
    // A file inside the directory blocks its removal until it goes.
    guest
        .memory
        .write_bytes(buf, b"adir\\inner\\f.bin\0")
        .unwrap();
    let fd = guest.call("_open", &[buf, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    assert_eq!(guest.call("_close", &[fd]) & 0xFFFF_FFFF, 0);
    guest.memory.write_bytes(buf, b"adir\0").unwrap();
    assert_eq!(guest.call("_rmdir", &[buf]) & 0xFFFF_FFFF, MINUS_ONE);
    // Missing parents and missing directories are ENOENT.
    guest.memory.write_bytes(buf, b"nope\\deep\0").unwrap();
    assert_eq!(guest.call("_mkdir", &[buf]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), ENOENT);
    guest.memory.write_bytes(buf, b"nope\0").unwrap();
    assert_eq!(guest.call("_rmdir", &[buf]) & 0xFFFF_FFFF, MINUS_ONE);
    assert_eq!(guest.errno(), ENOENT);
    // An empty directory is removed: the inner one first, then the parent
    // once the file is gone.
    assert_eq!(guest.call("remove", &[buf]) & 0xFFFF_FFFF, MINUS_ONE);
}

#[test]
fn legacy_pipes_carry_bytes_between_ends() {
    let mut guest = Guest::new();
    let buf = guest.call("malloc", &[64]);
    // `_pipe` answers two descriptors sharing one queue: what the write end
    // takes the read end gives back, in order.
    assert_eq!(guest.call("_pipe", &[buf, 4096, 0]) & 0xFFFF_FFFF, 0);
    let read = guest.memory.read_u32(buf).unwrap() as u64;
    let write = guest.memory.read_u32(buf + 4).unwrap() as u64;
    assert!(
        (3..0x8000).contains(&read) && read + 1 == write,
        "{read:x} {write:x}"
    );
    guest.memory.write_bytes(buf + 16, b"pipe").unwrap();
    assert_eq!(guest.call("_write", &[write, buf + 16, 4]) & 0xFFFF_FFFF, 4);
    assert_eq!(guest.call("_read", &[read, buf + 32, 4]) & 0xFFFF_FFFF, 4);
    let mut bytes = [0u8; 4];
    guest.memory.read_bytes(buf + 32, &mut bytes).unwrap();
    assert_eq!(&bytes, b"pipe");
    // The directions do not cross: the write end does not read, the read
    // end does not write.
    assert_eq!(
        guest.call("_read", &[write, buf + 32, 1]) & 0xFFFF_FFFF,
        MINUS_ONE
    );
    assert_eq!(
        guest.call("_write", &[read, buf + 16, 1]) & 0xFFFF_FFFF,
        MINUS_ONE
    );
    // Once the write end closes and the queue empties, the read end answers
    // end of file: zero bytes.
    assert_eq!(guest.call("_close", &[write]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_read", &[read, buf + 32, 4]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_close", &[read]) & 0xFFFF_FFFF, 0);
}

#[test]
fn legacy_iob_array_carries_the_standard_descriptors() {
    let mut guest = Guest::new();
    // `__iob_func` answers the one array on every call, and the three
    // legacy `FILE` objects carry their descriptor at offset 28 and the
    // direction flag at 24, 48 bytes apart as the mingw header fixes them.
    let base = guest.call("__iob_func", &[0]);
    assert_ne!(base, 0);
    assert_eq!(guest.call("__iob_func", &[0]), base, "the array is one");
    assert_eq!(guest.memory.read_u32(base + 24).unwrap(), 1); // stdin reads
    assert_eq!(guest.memory.read_u32(base + 28).unwrap(), 0);
    assert_eq!(guest.memory.read_u32(base + 48 + 24).unwrap(), 2); // stdout writes
    assert_eq!(guest.memory.read_u32(base + 48 + 28).unwrap(), 1);
    assert_eq!(guest.memory.read_u32(base + 96 + 24).unwrap(), 2); // stderr writes
    assert_eq!(guest.memory.read_u32(base + 96 + 28).unwrap(), 2);
    // The buffer fields start empty: a legacy stream is unbuffered, and
    // every byte goes through `_filbuf`/`_flsbuf`, as on Windows.
    assert_eq!(guest.memory.read_u64(base).unwrap(), 0);
    assert_eq!(guest.memory.read_u64(base + 8).unwrap(), 0);
    assert_eq!(guest.memory.read_u64(base + 16).unwrap(), 0);
}

#[test]
fn legacy_fprintf_writes_through_the_iob_streams() {
    let mut guest = Guest::new();
    // `stdout` is the second object of the `__iob_func` array, 48 bytes
    // after the first, as the mingw-w64 `_iobuf` stride fixes it.
    let base = guest.call("__iob_func", &[0]);
    assert_ne!(base, 0);
    let stdout = base + 48;
    let stderr = base + 96;
    // `fprintf` reads its variadic arguments from the calling convention.
    let work = guest.call("malloc", &[0x100]);
    assert_ne!(work, 0);
    guest.memory.write_bytes(SCRATCH, b"%d-%s\0").unwrap();
    guest.memory.write_bytes(work + 0x40, b"fin\0").unwrap();
    let len = guest.call("fprintf", &[stdout, SCRATCH, 42, work + 0x40]);
    assert_eq!(len, 6);
    assert_eq!(guest.state.standard_output(), b"42-fin");
    // stderr is the third object, captured apart.
    assert_eq!(guest.call("fprintf", &[stderr, SCRATCH, 7, work + 0x40]), 5);
    // `vfprintf` formats through the argument pointer: the slots sit
    // contiguously in memory, as a Win64 va_list does.
    guest.memory.write_u64(work + 0x80, 42).unwrap();
    guest.memory.write_u64(work + 0x88, work + 0x40).unwrap();
    assert_eq!(guest.call("vfprintf", &[stdout, SCRATCH, work + 0x80]), 6);
    assert_eq!(guest.state.standard_output(), b"42-fin42-fin");
    // A null stream is invalid: -1 with EINVAL, and nothing is written.
    guest.set_errno(0);
    assert_eq!(
        guest.call("fprintf", &[0, SCRATCH, 42, work + 0x40]),
        u64::from(u32::MAX)
    );
    assert_eq!(guest.errno(), EINVAL);
    assert_eq!(guest.state.standard_output(), b"42-fin42-fin");
}

#[test]
fn ferror_reports_the_failed_write_of_a_file_stream() {
    let mut guest = Guest::new();
    // A stream opened read-only refuses the write: the byte is EOF and the
    // error indicator is set, as the CRT sets it for any failed write.
    guest.memory.write_bytes(SCRATCH, b"data.bin\0").unwrap();
    guest.memory.write_bytes(SCRATCH + 0x20, b"r\0").unwrap();
    guest.memory.write_bytes(SCRATCH + 0x28, b"w\0").unwrap();
    // The file exists: create it first with a write-mode open.
    let made = guest.call("fopen", &[SCRATCH, SCRATCH + 0x28]);
    assert_ne!(made, 0);
    guest.call("fclose", &[made]);
    let file = guest.call("fopen", &[SCRATCH, SCRATCH + 0x20]);
    assert_ne!(file, 0);
    assert_eq!(guest.call("ferror", &[file]), 0);
    assert_eq!(guest.call("fputc", &[u64::from(b'x'), file]), MINUS_ONE);
    assert_ne!(guest.call("ferror", &[file]), 0);
    // `clearerr` resets the indicator.
    guest.call("clearerr", &[file]);
    assert_eq!(guest.call("ferror", &[file]), 0);
    guest.call("fclose", &[file]);
}

#[test]
fn putc_writes_one_character_like_fputc() {
    let (mut guest, [_, out, _]) = stdio_guest();
    // `putc` is `fputc` exactly, as Microsoft's documentation states.
    for character in [u64::from(b'A'), u64::from(b'B')] {
        assert_eq!(guest.call("putc", &[character, out]), character);
    }
    assert_eq!(guest.state.standard_output(), b"AB");
    // A null stream is EOF with EINVAL, as for `fputc`.
    guest.set_errno(0);
    assert_eq!(guest.call("putc", &[u64::from(b'C'), 0]), MINUS_ONE);
    assert_eq!(guest.errno(), EINVAL);
}

#[test]
fn wcscpy_copies_and_wcsnicmp_compares_case_insensitively() {
    let mut guest = Guest::new();
    let wide = |text: &[u16]| -> Vec<u8> {
        let mut bytes = Vec::new();
        for unit in text {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    };
    // `wcscpy` copies the terminator too and answers the destination.
    guest
        .memory
        .write_bytes(SCRATCH, &wide(&[u16::from(b'H'), u16::from(b'i')]))
        .unwrap();
    assert_eq!(
        guest.call("wcscpy", &[SCRATCH + 0x40, SCRATCH]),
        SCRATCH + 0x40
    );
    assert_eq!(
        guest.memory.read_u16(SCRATCH + 0x40).unwrap(),
        u16::from(b'H')
    );
    assert_eq!(guest.memory.read_u16(SCRATCH + 0x44).unwrap(), 0);
    // `_wcsnicmp` folds ASCII case: "hi" equals "HI", and orders the rest.
    guest
        .memory
        .write_bytes(SCRATCH + 0x20, &wide(&[u16::from(b'h'), u16::from(b'I')]))
        .unwrap();
    assert_eq!(
        guest.call("_wcsnicmp", &[SCRATCH + 0x20, SCRATCH + 0x40, 2]),
        0
    );
    // The count bounds the comparison: a difference past it is unseen.
    assert_eq!(
        guest.call("_wcsnicmp", &[SCRATCH + 0x20, SCRATCH + 0x40, 1]),
        0
    );
    // 'h' against 'H' alone are equal; ordering shows on real differences.
    guest
        .memory
        .write_bytes(SCRATCH + 0x20, &wide(&[u16::from(b'a')]))
        .unwrap();
    assert_eq!(
        guest.call("_wcsnicmp", &[SCRATCH + 0x20, SCRATCH + 0x40, 1]) & 0xFFFF_FFFF,
        u64::from(u32::MAX)
    );
    assert_eq!(
        guest.call("_wcsnicmp", &[SCRATCH + 0x40, SCRATCH + 0x20, 1]),
        1
    );
    // A unit outside ASCII compares exactly, with no folding.
    guest
        .memory
        .write_bytes(SCRATCH + 0x20, &wide(&[0x100]))
        .unwrap();
    assert_eq!(
        guest.call("_wcsnicmp", &[SCRATCH + 0x20, SCRATCH + 0x20, 1]),
        0
    );
}

#[test]
fn legacy_sscanf_follows_the_reference_vectors() {
    let mut guest = Guest::new();
    let work = guest.call("malloc", &[0x400]);
    assert_ne!(work, 0);
    // input at work, format at work+0x100, outputs at work+0x200 onward.
    let scan = |guest: &mut Guest, input: &[u8], format: &[u8], slots: &[u64]| -> u64 {
        guest.memory.write_bytes(work, input).unwrap();
        guest.memory.write_u8(work + input.len() as u64, 0).unwrap();
        guest.memory.write_bytes(work + 0x100, format).unwrap();
        guest
            .memory
            .write_u8(work + 0x100 + format.len() as u64, 0)
            .unwrap();
        let mut args = vec![work, work + 0x100];
        args.extend_from_slice(slots);
        guest.call("sscanf", &args)
    };
    let int_at = |guest: &Guest, offset: u64| guest.memory.read_u32(work + 0x200 + offset).unwrap();
    // v1: "42 rest" %d -> r=1 d=42. The reference vectors come from the same
    // program compiled for the host, run on this machine.
    assert_eq!(scan(&mut guest, b"42 rest", b"%d", &[work + 0x200]), 1);
    assert_eq!(int_at(&guest, 0), 42);
    // v2: leading whitespace and a negative sign.
    assert_eq!(scan(&mut guest, b"   -17 x", b"%d", &[work + 0x200]), 1);
    assert_eq!(int_at(&guest, 0), (-17i32) as u32);
    // v3: %i reads 0x1F as hexadecimal.
    assert_eq!(scan(&mut guest, b"0x1F end", b"%i", &[work + 0x200]), 1);
    assert_eq!(int_at(&guest, 0), 31);
    // v4: %i reads 010 as octal.
    assert_eq!(scan(&mut guest, b"010 zz", b"%i", &[work + 0x200]), 1);
    assert_eq!(int_at(&guest, 0), 8);
    // v5: %x reads ff.
    assert_eq!(scan(&mut guest, b"ff gg", b"%x", &[work + 0x200]), 1);
    assert_eq!(int_at(&guest, 0), 255);
    // v7/v8: %s stops at whitespace and honors the width.
    assert_eq!(
        scan(&mut guest, b"abc", "%s".as_bytes(), &[work + 0x200]),
        1
    );
    assert_eq!(guest.memory.read_u8(work + 0x200).unwrap(), b'a');
    assert_eq!(guest.memory.read_u8(work + 0x203).unwrap(), 0);
    assert_eq!(scan(&mut guest, b"ab cd", b"%3s", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u8(work + 0x202).unwrap(), 0);
    // v9/v10: whitespace in the format skips it; %c without it does not.
    assert_eq!(scan(&mut guest, b"  q", b" %c", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u8(work + 0x200).unwrap(), b'q');
    assert_eq!(scan(&mut guest, b"  q", b"%c", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u8(work + 0x200).unwrap(), 32);
    // v11: a literal comma must match.
    assert_eq!(
        scan(
            &mut guest,
            b"12,34",
            b"%d,%d",
            &[work + 0x200, work + 0x204]
        ),
        2
    );
    assert_eq!(int_at(&guest, 0), 12);
    assert_eq!(int_at(&guest, 4), 34);
    // v12: suppression consumes but does not assign.
    assert_eq!(scan(&mut guest, b"12 99", b"%d %*d", &[work + 0x200]), 1);
    assert_eq!(int_at(&guest, 0), 12);
    // v13/v14: a mismatch answers 0; empty input answers EOF.
    assert_eq!(scan(&mut guest, b"x", b"%d", &[work + 0x200]), 0);
    assert_eq!(
        scan(&mut guest, b"", b"%d", &[work + 0x200]),
        u64::from(u32::MAX)
    );
    // v18/v19: scansets collect members and non-members.
    assert_eq!(scan(&mut guest, b"abcXYZ", b"%[abc]", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u8(work + 0x203).unwrap(), 0);
    assert_eq!(scan(&mut guest, b"xyzabc", b"%[^abc]", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u8(work + 0x200).unwrap(), b'x');
    assert_eq!(guest.memory.read_u8(work + 0x203).unwrap(), 0);
    // v20: %n writes the consumed count and is not itself counted.
    assert_eq!(
        scan(
            &mut guest,
            b"123abc",
            b"%d%n",
            &[work + 0x200, work + 0x204]
        ),
        1
    );
    assert_eq!(int_at(&guest, 0), 123);
    assert_eq!(int_at(&guest, 4), 3);
    // v21: %lld reads past 32 bits.
    assert_eq!(scan(&mut guest, b"4294967296", b"%lld", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u64(work + 0x200).unwrap(), 4294967296);
    // v22: %hd writes a short.
    assert_eq!(scan(&mut guest, b"327", b"%hd", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u16(work + 0x200).unwrap(), 327);
    // v27: %hhu writes a byte.
    assert_eq!(scan(&mut guest, b"200", b"%hhu", &[work + 0x200]), 1);
    assert_eq!(guest.memory.read_u8(work + 0x200).unwrap(), 200);
}

#[test]
fn vsscanf_scans_through_the_va_list() {
    let mut guest = Guest::new();
    let work = guest.call("malloc", &[0x200]);
    assert_ne!(work, 0);
    // input at work, format at work+0x40, output cell at work+0x60, the
    // va_list slots at work+0x100.
    guest.memory.write_bytes(work, b"42 rest\0").unwrap();
    guest.memory.write_bytes(work + 0x40, b"%d\0").unwrap();
    guest.memory.write_u64(work + 0x100, work + 0x60).unwrap();
    // __stdio_common_vsscanf(options, buffer, count, format, locale,
    // arguments) — the count of the string form is -1, and the locale and
    // the argument pointer ride the stack above the shadow space.
    for options in [0u64, 0x02, 0x04, 0x07] {
        guest.memory.write_u64(work + 0x60, 0).unwrap();
        guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
        guest
            .memory
            .write_u64(STACK_TOP + 40, work + 0x100)
            .unwrap();
        let (cpu, exit) = guest.run(
            "__stdio_common_vsscanf",
            &[options, work, u64::MAX, work + 0x40],
        );
        assert_eq!(
            (cpu.get(Register::Rax) as u32 as i32, exit),
            (1, ExitReason::Halt),
            "options {options:#x}"
        );
        assert_eq!(guest.memory.read_u32(work + 0x60).unwrap(), 42);
    }
}

#[test]
fn synthetic_lifecycle_queue_teardown_is_terminal_only_with_open_handles() {
    use xenora_loader::services::gaming_runtime::register_synthetic_lifecycle;
    let names = [
        "XGameRuntimeInitialize",
        "XGameRuntimeUninitialize",
        "XTaskQueueCreate",
        "XTaskQueueCloseHandle",
    ];
    for close_before_teardown in [true, false] {
        let imports: Vec<_> = names
            .iter()
            .map(|name| ("xgameruntime.dll", Symbol::Name(name)))
            .collect();
        let image = build(&imports);
        let pe = ParsedPe::parse(&image.bytes).unwrap();
        let mut memory = pe.load_into_memory(&image.bytes).unwrap().memory;
        memory
            .map_region(SCRATCH, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        memory
            .map_region(STACK, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        let (mut registry, _, state) = standard_with_state(0);
        register_synthetic_lifecycle(&mut registry, state);
        assert_eq!(
            registry
                .bind_imports(&pe, &image.bytes, BASE, &mut memory)
                .unwrap(),
            4
        );
        let mut engine = DbtEngine::new(256 * 1024).unwrap();
        engine.set_import_registry(registry);
        let mut call = |index: u64, args: &[u64]| {
            let mut cpu = CpuState::new(BASE + u64::from(CODE_RVA) + 16 * index, STACK_TOP);
            for (reg, value) in [Register::Rcx, Register::Rdx, Register::R8, Register::R9]
                .into_iter()
                .zip(args)
            {
                cpu.set(reg, *value);
            }
            assert_eq!(
                engine.run(&mut cpu, &mut memory, 20).exit_reason,
                ExitReason::Halt
            );
            (cpu.get(Register::Rax), memory.read_u64(SCRATCH).unwrap())
        };
        assert_eq!(call(0, &[]).0, 0);
        assert_eq!(call(0, &[]).0, 0);
        let (status, handle) = call(2, &[0, 0, SCRATCH]);
        assert_eq!(status, 0);
        assert_ne!(handle, 0);
        if close_before_teardown {
            call(3, &[handle]);
        }
        call(1, &[]);
        let expected = if close_before_teardown {
            0
        } else {
            0x8924_0105
        };
        assert_eq!(call(0, &[]).0, expected);
        call(3, &[handle]);
        call(1, &[]);
        assert_eq!(call(0, &[]).0, expected);
    }
}

/// `ungetc`: the pushed bytes come back last-pushed-first through the shared
/// descriptor, the end-of-file indicator clears, and EOF in is EOF out with
/// nothing done (ISO C 7.21.7.10).
#[test]
fn ungetc_stacks_bytes_and_steps_the_position_back() {
    let (mut guest, _) = stdio_guest();
    store(&mut guest, "ungetc.bin", b"abcdef");
    guest.memory.write_bytes(NAME, b"ungetc.bin\0").unwrap();
    guest.memory.write_bytes(MODE, b"rb\0").unwrap();
    let file = guest.call("fopen", &[NAME, MODE]);
    assert_ne!(file, 0);
    let fd = guest.call("_fileno", &[file]) & 0xFFFF_FFFF;
    let buf = TEXT + 0x200;
    // Two bytes in, then two pushes come back last-pushed-first and the
    // file resumes where it stopped.
    assert_eq!(guest.call("_read", &[fd, buf, 2]) & 0xFFFF_FFFF, 2);
    let mut verify = [0u8; 8];
    guest.memory.read_bytes(buf, &mut verify).unwrap();
    assert_eq!(&verify[..2], b"ab");
    assert_eq!(
        guest.call("ungetc", &[b'X' as u64, file]) & 0xFFFF_FFFF,
        b'X' as u64
    );
    assert_eq!(
        guest.call("ungetc", &[b'Y' as u64, file]) & 0xFFFF_FFFF,
        b'Y' as u64
    );
    assert_eq!(guest.call("_read", &[fd, buf, 4]) & 0xFFFF_FFFF, 4);
    guest.memory.read_bytes(buf, &mut verify).unwrap();
    assert_eq!(&verify[..4], b"YXcd");
    // EOF in is EOF out and stacks nothing.
    assert_eq!(
        guest.call("ungetc", &[0xFFFF_FFFF, file]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.call("_read", &[fd, buf, 2]) & 0xFFFF_FFFF, 2);
    guest.memory.read_bytes(buf, &mut verify).unwrap();
    assert_eq!(&verify[..2], b"ef");
    // The end-of-file indicator is a stdio notion: a stdio read at the end
    // sets it, and a push clears it again.
    assert!(line(&mut guest, file, 8).is_none(), "at the end");
    assert_ne!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.call("ungetc", &[b'Z' as u64, file]) & 0xFFFF_FFFF,
        b'Z' as u64
    );
    assert_eq!(guest.call("feof", &[file]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_read", &[fd, buf, 1]) & 0xFFFF_FFFF, 1);
    guest.memory.read_bytes(buf, &mut verify).unwrap();
    assert_eq!(&verify[..1], b"Z");
    // A push on a stream that is not open is EOF with EBADF.
    guest.set_errno(0);
    assert_eq!(
        guest.call("ungetc", &[b'Q' as u64, TEXT]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), EBADF);
    assert_eq!(guest.call("fclose", &[file]) & 0xFFFF_FFFF, 0);
}

/// `_open_osfhandle` and `_get_osfhandle`: a kernel pipe end becomes a
/// descriptor the CRT reads and writes, the CRT owns the handle once
/// wrapped, and a write end closing marks the pipe's end of stream.
#[test]
fn osfhandle_interop_wraps_a_kernel_pipe() {
    let (mut guest, _) = stdio_guest();
    let ends = TEXT + 0x400;
    let buf = TEXT + 0x500;
    // A kernel pipe: both ends out.
    assert_eq!(
        guest.call("CreatePipe", &[ends, ends + 8, 0, 0]) & 0xFFFF_FFFF,
        1
    );
    let read_end = guest.memory.read_u64(ends).unwrap();
    let write_end = guest.memory.read_u64(ends + 8).unwrap();
    assert_ne!(read_end, 0);
    assert_ne!(write_end, 0);
    // The write end becomes a descriptor; the handle it wraps comes back.
    let fd_w = guest.call("_open_osfhandle", &[write_end, 0]) & 0xFFFF_FFFF;
    assert_ne!(fd_w as i32, -1);
    assert_eq!(guest.call("_get_osfhandle", &[fd_w]), write_end);
    // Bytes written through the CRT drain through the CRT on the read end.
    guest.memory.write_bytes(buf, b"pipe!").unwrap();
    assert_eq!(guest.call("_write", &[fd_w, buf, 5]) & 0xFFFF_FFFF, 5);
    let fd_r = guest.call("_open_osfhandle", &[read_end, 0]) & 0xFFFF_FFFF;
    assert_ne!(fd_r as i32, -1);
    assert_eq!(guest.call("_read", &[fd_r, buf, 3]) & 0xFFFF_FFFF, 3);
    let mut verify = [0u8; 8];
    guest.memory.read_bytes(buf, &mut verify).unwrap();
    assert_eq!(&verify[..3], b"pip");
    // A handle that is no kernel object is EBADF, and so is a fd with none.
    guest.set_errno(0);
    assert_eq!(
        guest.call("_open_osfhandle", &[0xDEAD, 0]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), EBADF);
    assert_eq!(guest.call("_get_osfhandle", &[77]), u64::MAX);
    // Closing the write descriptor closes the handle: the kernel no longer
    // knows it, and the read end drains what remains then answers empty.
    assert_eq!(guest.call("_close", &[fd_w]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("CloseHandle", &[write_end]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_read", &[fd_r, buf, 8]) & 0xFFFF_FFFF, 2);
    guest.memory.read_bytes(buf, &mut verify).unwrap();
    assert_eq!(&verify[..2], b"e!");
    assert_eq!(guest.call("_read", &[fd_r, buf, 8]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_close", &[fd_r]) & 0xFFFF_FFFF, 0);
}

/// `_get_osfhandle` of a CRT-opened file answers the kernel file object
/// the real CRT always has behind its descriptors (#1312): the object
/// types as a disk file and reports the content's length, exactly the
/// chain a win32 compatibility layer implements its `fstat` through.
/// busybox-w32 opens everything this way, and its `tar` died inside the
/// stat of its own archive before the synthesis existed.
#[test]
fn osfhandle_of_a_crt_file_types_and_sizes_as_the_file() {
    let (mut guest, _) = stdio_guest();
    let buf = guest.call("malloc", &[0x100]);
    let stat = guest.call("malloc", &[0x100]);
    guest.memory.write_bytes(buf, b"of.bin ").unwrap();
    let fd = guest.call("_open", &[buf, 2 | 0x100 | 0x200 | 0x8000, 0]) & 0xFFFF_FFFF;
    assert!((3..0x8000).contains(&fd), "{fd:x}");
    guest.memory.write_bytes(buf + 16, b"12345").unwrap();
    assert_eq!(guest.call("_write", &[fd, buf + 16, 5]) & 0xFFFF_FFFF, 5);
    // The kernel handle exists: before the synthesis every CRT-opened
    // file answered -1 with EBADF here. The kernel-side type and size
    // chain (GetFileType answering disk, the by-handle information
    // carrying the length) is what the end-to-end measurement exercises;
    // those kernel services do not sit in this harness's table.
    let handle = guest.call("_get_osfhandle", &[fd]);
    assert_ne!(handle, u64::MAX);
    assert_ne!(handle, 0);
    assert_eq!(guest.errno(), 0);
    // Asking again answers the same object, and a descriptor that is not
    // open still answers -1 with EBADF.
    assert_eq!(guest.call("_get_osfhandle", &[fd]), handle);
    guest.set_errno(0);
    assert_eq!(guest.call("_get_osfhandle", &[77]), u64::MAX);
    assert_eq!(guest.errno(), EBADF);
}

/// `_filbuf` and `_flsbuf`: the legacy single-byte forms move one byte at
/// a time through the stream, the read answering EOF at the end.
#[test]
fn filbuf_and_flsbuf_move_single_bytes() {
    let (mut guest, _) = stdio_guest();
    guest.memory.write_bytes(NAME, b"bytes.bin\0").unwrap();
    guest.memory.write_bytes(MODE, b"wb\0").unwrap();
    let file = guest.call("fopen", &[NAME, MODE]);
    assert_ne!(file, 0);
    // Bytes out one at a time, each answering itself.
    assert_eq!(
        guest.call("_flsbuf", &[b'o' as u64, file]) & 0xFFFF_FFFF,
        b'o' as u64
    );
    assert_eq!(
        guest.call("_flsbuf", &[b'k' as u64, file]) & 0xFFFF_FFFF,
        b'k' as u64
    );
    assert_eq!(guest.call("fclose", &[file]) & 0xFFFF_FFFF, 0);
    // Back in: the bytes come one at a time and the end is EOF.
    guest.memory.write_bytes(MODE, b"rb\0").unwrap();
    let file = guest.call("fopen", &[NAME, MODE]);
    assert_ne!(file, 0);
    assert_eq!(guest.call("_filbuf", &[file]) & 0xFFFF_FFFF, b'o' as u64);
    assert_eq!(guest.call("_filbuf", &[file]) & 0xFFFF_FFFF, b'k' as u64);
    assert_eq!(guest.call("_filbuf", &[file]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    // A write on the read stream is EOF with EBADF, and so is either form
    // on a pointer that is no stream.
    guest.set_errno(0);
    assert_eq!(
        guest.call("_flsbuf", &[b'x' as u64, file]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), EBADF);
    assert_eq!(guest.call("_filbuf", &[TEXT]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.call("fclose", &[file]) & 0xFFFF_FFFF, 0);
}

#[test]
fn filbuf_and_flsbuf_honor_the_standard_streams() {
    let (mut guest, [input, out, err]) = stdio_guest();
    guest.state.set_standard_input(b"ab");
    // stdin reads consume the host-supplied bytes one at a time, then EOF.
    assert_eq!(guest.call("_filbuf", &[input]) & 0xFFFF_FFFF, b'a' as u64);
    assert_eq!(guest.call("_filbuf", &[input]) & 0xFFFF_FFFF, b'b' as u64);
    assert_eq!(guest.call("_filbuf", &[input]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    // stdout and stderr bytes go through the same capture as every write,
    // text mode included.
    assert_eq!(
        guest.call("_flsbuf", &[b'x' as u64, out]) & 0xFFFF_FFFF,
        b'x' as u64
    );
    assert_eq!(
        guest.call("_flsbuf", &[b'\n' as u64, err]) & 0xFFFF_FFFF,
        b'\n' as u64
    );
    assert_eq!(guest.state.standard_output(), b"x");
    assert_eq!(guest.state.standard_error(), b"\r\n");
    // stdin cannot be written and the output streams cannot be read: EOF
    // with EBADF, as on a file stream open the wrong way.
    guest.set_errno(0);
    assert_eq!(
        guest.call("_flsbuf", &[b'x' as u64, input]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), EBADF);
    guest.set_errno(0);
    assert_eq!(guest.call("_filbuf", &[out]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), EBADF);
}

#[test]
fn an_assertion_prints_and_ends_the_process() {
    let (mut guest, _) = stdio_guest();
    let expression = place(&mut guest, NAME, b"x == 42");
    let file = place(&mut guest, MODE, b"sqlite3.c");
    let (_, exit) = guest.run("_assert", &[expression, file, 1337]);
    assert_eq!(exit, xenora_loader::cpu::ExitReason::ProcessExit(3));
    // stderr is the third captured stream: the message went there.
    assert_eq!(
        guest.state.standard_error(),
        b"Assertion failed: x == 42, file sqlite3.c, line 1337\r\n"
    );
}

#[test]
fn beginthreadex_starts_a_thread_like_createthread() {
    let mut guest = stdio_guest().0;
    // The CRT form refuses what CreateThread refuses: security descriptors,
    // unknown flags and a null start, with EINVAL instead of a last error.
    let start = TEXT; // any non-null guest address
    assert_eq!(guest.call("_beginthreadex", &[1, 0, start, 0]), 0);
    assert_eq!(guest.errno(), 22);
    assert_eq!(guest.call("_beginthreadex", &[0, 0, 0, 0]), 0);
    assert_eq!(guest.errno(), 22);
    guest.memory.write_u64(STACK_TOP + 32, 8).unwrap(); // unknown initflag bit
    assert_eq!(guest.call("_beginthreadex", &[0, 0, start, 0]), 0);
    assert_eq!(guest.errno(), 22);
    // Without an attached scheduler the machine has no threads: ENOMEM.
    guest.memory.write_u64(STACK_TOP + 32, 0).unwrap();
    assert_eq!(guest.call("_beginthreadex", &[0, 0, start, 0]), 0);
    assert_eq!(guest.errno(), 12);

    // Thread creation itself is proven end to end by the hosted fixture:
    // `xenora run` attaches the scheduler, and a thread the fixture starts
    // with _beginthreadex writes the shared memory the main thread reads
    // after waiting on its handle.
}

#[test]
fn the_wide_file_operations_follow_the_drive() {
    let (mut guest, _streams) = stdio_guest();
    // _wfopen opens the same files as fopen, with a wide name and mode.
    let name = place_wide(&mut guest, NAME, "c:\\wide.txt");
    let mode = place_wide(&mut guest, MODE, "w");
    let file = guest.call("_wfopen", &[name, mode]);
    assert_ne!(file, 0);
    write(&mut guest, file, b"wide");
    close(&mut guest, file);

    // _wstat64i32 answers the 48-byte block: regular file, read and write,
    // one link, the size, times of -1.
    let stat = TEXT + 0x3800;
    assert_eq!(guest.call("_wstat64i32", &[name, stat]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.memory.read_u16(stat + 6).unwrap(),
        0x8000 | 0x100 | 0x80
    );
    assert_eq!(guest.memory.read_u16(stat + 8).unwrap(), 1);
    assert_eq!(guest.memory.read_u32(stat + 20).unwrap(), 4);
    assert_eq!(guest.memory.read_u64(stat + 24).unwrap(), u64::MAX);

    // _access: the file exists, in every mode, until it is read-only.
    let narrow = place(&mut guest, TEXT + 0x2000, b"c:\\wide.txt");
    assert_eq!(guest.call("_access", &[narrow, 0]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_waccess", &[name, 6]) & 0xFFFF_FFFF, 0);
    // _wchmod without the write bit makes the file read-only.
    assert_eq!(guest.call("_wchmod", &[name, 0x100]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.call("_waccess", &[name, 2]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), 13);
    assert_eq!(guest.memory.read_u16(stat + 6).unwrap() & 0x80, 0x80); // unchanged: not stat'd again
    assert_eq!(guest.call("_wstat64i32", &[name, stat]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.memory.read_u16(stat + 6).unwrap() & 0x80, 0);
    // A read-only file cannot be written or unlinked.
    assert_eq!(guest.call("_wunlink", &[name]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), 13);
    // Making it writable again restores both.
    assert_eq!(guest.call("_wchmod", &[name, 0x180]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_unlink", &[narrow]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.call("_wstat64i32", &[name, stat]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), 2);

    // _wmkdir creates directories files can live in, once.
    let dir = place_wide(&mut guest, NAME, "c:\\wdir");
    assert_eq!(guest.call("_wmkdir", &[dir]) & 0xFFFF_FFFF, 0);
    assert_eq!(guest.call("_wmkdir", &[dir]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    let inner = place_wide(&mut guest, NAME + 0x40, "c:\\wdir\\in.txt");
    let wmode = place_wide(&mut guest, MODE, "w");
    let file = guest.call("_wfopen", &[inner, wmode]);
    assert_ne!(file, 0);
    close(&mut guest, file);
    // A missing parent fails with ENOENT.
    let deep = place_wide(&mut guest, NAME + 0x80, "c:\\nope\\dir");
    assert_eq!(guest.call("_wmkdir", &[deep]) & 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(guest.errno(), 2);
    // Invalid modes fail with EINVAL.
    let dir_narrow = place(&mut guest, TEXT + 0x2000, b"c:\\wdir");
    assert_eq!(
        guest.call("_access", &[dir_narrow, 8]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_eq!(guest.errno(), 22);
    // The narrow form marks a file the same way: write bit clear, read-only.
    let narrow_mode = place(&mut guest, TEXT + 0x2100, b"c:\\narrowmode.txt");
    let create_mode = place(&mut guest, TEXT + 0x2300, b"w");
    let created = guest.call("fopen", &[narrow_mode, create_mode]);
    assert_ne!(created, 0);
    close(&mut guest, created);
    assert_eq!(guest.call("_chmod", &[narrow_mode, 0x100]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.call("_access", &[narrow_mode, 2]) & 0xFFFF_FFFF,
        0xFFFF_FFFF,
        "a read-only file denies the write probe"
    );
    assert_eq!(guest.call("_chmod", &[narrow_mode, 0x180]) & 0xFFFF_FFFF, 0);
    assert_eq!(
        guest.call("_access", &[narrow_mode, 2]) & 0xFFFF_FFFF,
        0,
        "the write bit restores access"
    );
    // A missing file is ENOENT, an unreadable name EINVAL.
    let missing = place(&mut guest, TEXT + 0x2200, b"c:\\missing-narrow.txt");
    guest.set_errno(0);
    assert_eq!(
        guest.call("_chmod", &[missing, 0x100]) & 0xFFFF_FFFF,
        0xFFFF_FFFF
    );
    assert_ne!(guest.errno(), 0);
}

#[test]
fn co_initialize_ex_tracks_the_apartment_per_thread() {
    let mut guest = Guest::new();
    assert_eq!(guest.call("CoInitializeEx", &[0, 2]), 0);
    assert_eq!(guest.call("CoInitializeEx", &[0, 2]), 1);
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]) as u32, 0x8001_0106);
    guest.teb = 0x1234;
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]), 0);
    assert_eq!(guest.call("CoInitializeEx", &[1, 0]) as u32, 0x8007_0057);
}

#[test]
fn co_uninitialize_balances_each_initialization() {
    let mut guest = Guest::new();
    guest.call("CoInitializeEx", &[0, 2]);
    guest.call("CoInitializeEx", &[0, 2]);
    guest.call("CoUninitialize", &[]);
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]) as u32, 0x8001_0106);
    guest.call("CoUninitialize", &[]);
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]), 0);
}

#[test]
fn co_create_guid_returns_a_version_four_guid() {
    let mut guest = Guest::new();
    assert_eq!(guest.call("CoCreateGuid", &[SCRATCH]), 0);
    assert_eq!(guest.memory.read_u16(SCRATCH + 6).unwrap() & 0xf000, 0x4000);
    assert_eq!(guest.memory.read_u16(SCRATCH + 8).unwrap() & 0xc0, 0x80);
}

#[test]
fn string_from_guid2_renders_the_documented_text_form() {
    let mut guest = Guest::new();
    guest
        .memory
        .write_bytes(
            SCRATCH,
            &[
                0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        )
        .unwrap();
    assert_eq!(
        guest.call("StringFromGUID2", &[SCRATCH, SCRATCH + 32, 38]),
        0
    );
    assert_eq!(
        guest.call("StringFromGUID2", &[SCRATCH, SCRATCH + 32, 39]),
        39
    );
    for (i, unit) in "{00112233-4455-6677-8899-AABBCCDDEEFF}\0"
        .encode_utf16()
        .enumerate()
    {
        assert_eq!(
            guest.memory.read_u16(SCRATCH + 32 + 2 * i as u64).unwrap(),
            unit
        );
    }
}

#[test]
fn clsid_from_string_parses_the_braced_and_bare_forms() {
    let mut guest = Guest::new();
    guest
        .memory
        .write_bytes(SCRATCH + 128, &[0xff; 16])
        .unwrap();
    assert_eq!(guest.call("CLSIDFromString", &[0, SCRATCH + 128]), 0);
    assert_eq!(guest.memory.read_u64(SCRATCH + 128).unwrap(), 0);
    assert_eq!(guest.memory.read_u64(SCRATCH + 136).unwrap(), 0);
    for text in [
        "{00112233-4455-6677-8899-AABBCCDDEEFF}",
        "00112233-4455-6677-8899-aabbccddeeff",
    ] {
        for (i, unit) in text.encode_utf16().chain([0]).enumerate() {
            guest
                .memory
                .write_u16(SCRATCH + 2 * i as u64, unit)
                .unwrap();
        }
        assert_eq!(guest.call("CLSIDFromString", &[SCRATCH, SCRATCH + 128]), 0);
        assert_eq!(guest.memory.read_u32(SCRATCH + 128).unwrap(), 0x0011_2233);
    }
    guest.memory.write_u16(SCRATCH, 0).unwrap();
    assert_eq!(
        guest.call("CLSIDFromString", &[SCRATCH, SCRATCH + 128]) as u32,
        0x8004_01f3
    );
}

#[test]
fn co_task_memory_owns_its_blocks() {
    let mut guest = Guest::new();
    let ptr = guest.call("CoTaskMemAlloc", &[16]);
    assert_ne!(ptr, 0);
    guest.memory.write_u32(ptr, 0x12345678).unwrap();
    guest.call("CoTaskMemFree", &[ptr]);
    assert!(guest.memory.read_u32(ptr).is_err());
    guest.call("CoTaskMemFree", &[0]);
}

#[test]
fn co_task_mem_realloc_preserves_contents_and_refuses_foreign_blocks() {
    let mut guest = Guest::new();
    let ptr = guest.call("CoTaskMemAlloc", &[16]);
    guest.memory.write_u32(ptr, 0x12345678).unwrap();
    let resized = guest.call("CoTaskMemRealloc", &[ptr, 64]);
    assert_ne!(resized, 0);
    assert_eq!(guest.memory.read_u32(resized).unwrap(), 0x12345678);
    assert_eq!(guest.call("CoTaskMemRealloc", &[resized, u64::MAX]), 0);
    assert_eq!(guest.memory.read_u32(resized).unwrap(), 0x12345678);
    assert_eq!(guest.call("CoTaskMemRealloc", &[resized, 0]), 0);
    assert_ne!(guest.run("CoTaskMemFree", &[SCRATCH]).1, ExitReason::Halt);
}

#[test]
fn co_create_instance_reports_an_unregistered_class() {
    let mut guest = Guest::new();
    guest.memory.write_u64(SCRATCH + 64, 42).unwrap();
    assert_eq!(
        call6(
            &mut guest,
            "CoCreateInstance",
            &[SCRATCH, 0, 1, SCRATCH + 16, SCRATCH + 64]
        ) as u32,
        0x8004_01f0
    );
    assert_eq!(guest.memory.read_u64(SCRATCH + 64).unwrap(), 0);
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]), 0);
    assert_eq!(
        call6(
            &mut guest,
            "CoCreateInstance",
            &[SCRATCH, 0, 1, SCRATCH + 16, SCRATCH + 64]
        ) as u32,
        0x8004_0154
    );
    assert_eq!(guest.memory.read_u64(SCRATCH + 64).unwrap(), 0);
}

#[test]
fn synthetic_com_class_requires_explicit_fixture_registration() {
    let mut guest = Guest::new();
    guest
        .memory
        .write_bytes(
            SCRATCH,
            &[
                0x51, 0x37, 0x71, 0x58, 0x90, 0x74, 0x4e, 0x41, 0xa0, 0x58, 0x63, 0x6f, 0x6d, 0, 0,
                1,
            ],
        )
        .unwrap();
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]), 0);
    assert_eq!(
        call6(
            &mut guest,
            "CoCreateInstance",
            &[SCRATCH, 0, 1, SCRATCH + 16, SCRATCH + 64]
        ) as u32,
        0x8004_0154
    );
    assert_eq!(guest.memory.read_u64(SCRATCH + 64).unwrap(), 0);
}

#[test]
fn com_api_set_exports_are_registered_individually() {
    let (registry, _) = standard(0);
    assert!(
        registry
            .binding("api-ms-win-core-com-l1-1-1.dll", "IIDFromString")
            .is_some()
    );
    assert!(
        registry
            .binding("api-ms-win-core-com-l1-1-0.dll", "IIDFromString")
            .is_some()
    );
    assert!(
        registry
            .binding("api-ms-win-core-com-l1-1-0.dll", "CoCreateInstance")
            .is_some()
    );
}

#[test]
fn prop_variant_clear_clears_values_and_frees_task_strings() {
    let mut guest = Guest::new();
    assert_ne!(guest.run("PropVariantClear", &[0]).1, ExitReason::Halt);
    let ptr = guest.call("CoTaskMemAlloc", &[16]);
    guest.memory.write_u16(SCRATCH, 31).unwrap();
    guest.memory.write_u64(SCRATCH + 8, ptr).unwrap();
    assert_eq!(guest.call("PropVariantClear", &[SCRATCH]), 0);
    assert_eq!(guest.memory.read_u16(SCRATCH).unwrap(), 0);
    assert!(guest.memory.read_u32(ptr).is_err());
    guest.memory.write_u16(SCRATCH, 13).unwrap();
    assert_ne!(
        guest.run("PropVariantClear", &[SCRATCH]).1,
        ExitReason::Halt
    );
    assert_eq!(guest.memory.read_u16(SCRATCH).unwrap(), 13);

    guest.memory.write_u16(SCRATCH, 0x8003).unwrap();
    assert_ne!(
        guest.run("PropVariantClear", &[SCRATCH]).1,
        ExitReason::Halt
    );
    assert_eq!(guest.memory.read_u16(SCRATCH).unwrap(), 0x8003);

    let owned = guest.call("CoTaskMemAlloc", &[16]);
    let mut readonly = [0u8; 24];
    readonly[..2].copy_from_slice(&31u16.to_le_bytes());
    readonly[8..16].copy_from_slice(&owned.to_le_bytes());
    guest
        .memory
        .map_region_with_data(CPBUF, 24, MemoryPermissions::READ_ONLY, &readonly)
        .unwrap();
    assert_ne!(guest.run("PropVariantClear", &[CPBUF]).1, ExitReason::Halt);
    guest.memory.write_u32(owned, 42).unwrap();
    guest.call("CoTaskMemFree", &[owned]);
}

#[test]
fn co_initialize_uses_the_single_threaded_model() {
    let mut guest = Guest::new();
    assert_eq!(guest.call("CoInitialize", &[0]), 0);
    assert_eq!(guest.call("CoInitializeEx", &[0, 2]), 1);
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]) as u32, 0x8001_0106);
    guest.call("CoUninitialize", &[]);
    guest.call("CoUninitialize", &[]);
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]), 0);
}

#[test]
fn iid_from_string_parses_a_guid_and_null() {
    let mut guest = Guest::new();
    for (i, unit) in "{00112233-4455-6677-8899-AABBCCDDEEFF}\0"
        .encode_utf16()
        .enumerate()
    {
        guest
            .memory
            .write_u16(SCRATCH + 2 * i as u64, unit)
            .unwrap();
    }
    assert_eq!(guest.call("IIDFromString", &[SCRATCH, SCRATCH + 128]), 0);
    assert_eq!(guest.memory.read_u32(SCRATCH + 128).unwrap(), 0x0011_2233);
    assert_eq!(guest.call("IIDFromString", &[0, SCRATCH + 128]), 0);
    assert_eq!(guest.memory.read_u64(SCRATCH + 128).unwrap(), 0);
    assert_eq!(guest.memory.read_u64(SCRATCH + 136).unwrap(), 0);
    guest.memory.write_u16(SCRATCH, 0).unwrap();
    assert_eq!(
        guest.call("IIDFromString", &[SCRATCH, SCRATCH + 128]) as u32,
        0x8007_0057
    );
}

#[test]
fn co_get_class_object_refuses_unregistered_classes() {
    let mut guest = Guest::new();
    let args = [SCRATCH, 1, 0, SCRATCH + 16, SCRATCH + 64];
    guest.memory.write_u64(SCRATCH + 64, 42).unwrap();
    assert_eq!(
        call6(&mut guest, "CoGetClassObject", &args) as u32,
        0x8004_01f0
    );
    assert_eq!(guest.memory.read_u64(SCRATCH + 64).unwrap(), 0);
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]), 0);
    guest.memory.write_u64(SCRATCH + 64, 42).unwrap();
    assert_eq!(
        call6(&mut guest, "CoGetClassObject", &args) as u32,
        0x8004_0154
    );
    assert_eq!(guest.memory.read_u64(SCRATCH + 64).unwrap(), 0);
}

#[test]
fn co_create_instance_ex_checks_the_bounded_interface_array() {
    let mut guest = Guest::new();
    let record = SCRATCH + 64;
    guest.memory.write_u64(record, SCRATCH + 16).unwrap();
    let args = [SCRATCH, 0, 1, 0, 1, record];
    assert_eq!(
        call6(&mut guest, "CoCreateInstanceEx", &args) as u32,
        0x8004_01f0
    );
    assert_eq!(guest.call("CoInitializeEx", &[0, 0]), 0);
    assert_eq!(
        call6(&mut guest, "CoCreateInstanceEx", &args) as u32,
        0x8004_0154
    );
    assert_eq!(guest.memory.read_u64(record + 8).unwrap(), 0);
    assert_eq!(guest.memory.read_u32(record + 16).unwrap(), 0);
    guest.memory.write_u64(record + 8, 1).unwrap();
    assert_eq!(
        call6(&mut guest, "CoCreateInstanceEx", &args) as u32,
        0x8007_0057
    );
    assert_eq!(
        call6(
            &mut guest,
            "CoCreateInstanceEx",
            &[SCRATCH, 0, 1, 0, 0, record]
        ) as u32,
        0x8007_0057
    );
    guest.memory.write_u64(STACK_TOP + 32, 65).unwrap();
    guest.memory.write_u64(STACK_TOP + 40, record).unwrap();
    assert_ne!(
        guest.run("CoCreateInstanceEx", &[SCRATCH, 0, 1, 0]).1,
        ExitReason::Halt
    );
}

/// The narrow `ctype.h` classification and case conversion of the C locale,
/// the surface legacy mingw binaries bind out of `msvcrt.dll`. The
/// expectations are the ASCII table: characters at or above 128 are in no
/// class, and EOF (-1) is in no class and converts to itself.
#[test]
fn narrow_classification_is_the_c_locale() {
    let (mut guest, _) = stdio_guest();
    // Alpha, digit and the unions and intersections of the classes.
    for (symbol, yes, no) in [
        ("isalpha", b'a', b'0'),
        ("isdigit", b'7', b'a'),
        ("isalnum", b'9', b'_'),
        ("islower", b'z', b'Z'),
        ("isupper", b'Q', b'q'),
        ("isspace", b' ', b'0'),
        ("ispunct", b'_', b'a'),
        ("iscntrl", 0x01_u8, b' '),
        ("isprint", b'~', 0x7f_u8),
        ("isgraph", b'!', b' '),
        ("isxdigit", b'F', b'g'),
    ] {
        assert_eq!(guest.call(symbol, &[u64::from(yes)]), 1, "{symbol} accepts");
        assert_eq!(guest.call(symbol, &[u64::from(no)]), 0, "{symbol} refuses");
        // Bytes at or above 128 are in no class of the C locale.
        assert_eq!(guest.call(symbol, &[0xC0]), 0, "{symbol} above ASCII");
        // EOF is in no class.
        assert_eq!(
            guest.call(symbol, &[u64::from(u32::MAX)]),
            0,
            "{symbol} EOF"
        );
    }
    // The other whitespace bytes of the C locale.
    for byte in [b'\t', b'\n', 0x0B_u8, 0x0C_u8, b'\r'] {
        assert_eq!(guest.call("isspace", &[u64::from(byte)]), 1);
    }
    // Case conversion answers the converted character and leaves the rest.
    assert_eq!(guest.call("tolower", &[u64::from(b'A')]), u64::from(b'a'));
    assert_eq!(guest.call("toupper", &[u64::from(b'x')]), u64::from(b'X'));
    assert_eq!(guest.call("tolower", &[u64::from(b'4')]), u64::from(b'4'));
    assert_eq!(guest.call("toupper", &[u64::from(b'H')]), u64::from(b'H'));
    // EOF converts to itself.
    assert_eq!(
        guest.call("tolower", &[u64::from(u32::MAX)]),
        u64::from(u32::MAX)
    );
    // The same spellings import from msvcrt.dll: the harness binds the
    // legacy module for every symbol in the legacy list above.
}

/// `atoi` and `atof` parse the decimal forms of the C contract: leading
/// ASCII whitespace, an optional sign, digits, and for the floating form a
/// fraction and an exponent. A string with no digits answers zero.
#[test]
fn narrow_decimal_parses_follow_the_c_contract() {
    let (mut guest, _) = stdio_guest();
    for (text, expected) in [
        (b"42" as &[u8], 42_i32),
        (b"  -17", -17),
        (b"+305", 305),
        (b"\t\n99x", 99),
        (b"abc", 0),
        (b"-", 0),
        (b"", 0),
        (b"  00012", 12),
    ] {
        let at = place(&mut guest, TEXT + 0x3000, text);
        assert_eq!(
            guest.call("atoi", &[at]) as u32 as i32,
            expected,
            "atoi {text:?}"
        );
    }
    // The floating form, exact values a binary64 represents.
    for (text, expected) in [
        (b"2.5" as &[u8], 2.5_f64),
        (b"  -0.75e2", -75.0),
        (b"1e-3", 0.001),
        (b".5", 0.5),
        (b"4.", 4.0),
        (b"xyz", 0.0),
        (b"1.5e", 1.5),
        (b"3e+", 3.0),
    ] {
        let at = place(&mut guest, TEXT + 0x3200, text);
        let bits = math_call(&mut guest, "atof", &[], &[at]);
        assert_eq!(f64::from_bits(bits as u64), expected, "atof {text:?}");
    }
    let at = place(&mut guest, TEXT + 0x3300, b"6.25");
    let bits = math_call(&mut guest, "atof", &[], &[at]);
    assert_eq!(f64::from_bits(bits as u64), 6.25);
}

// Itanium C++ ABI guard variables (#934). A refused acquisition has no
// honest answer: compiler-generated callers read any nonzero result as
// permission to initialize, so the refusal stops the guest instead of
// answering.

#[test]
fn guard_acquire_once_release_and_second_acquire_returns_zero() {
    let mut guest = Guest::new();
    guest.memory.write_u8(SCRATCH, 0).unwrap();

    assert_eq!(guest.call("__cxa_guard_acquire", &[SCRATCH]), 1);
    // Acquiring ownership does not write the initialized byte.
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 0);
    guest.call("__cxa_guard_release", &[SCRATCH]);
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 1);
    assert_eq!(guest.call("__cxa_guard_acquire", &[SCRATCH]), 0);

    // A null, unaligned or unmapped guard stops the guest: no answer can
    // both refuse the initialization and satisfy the ABI's errorless
    // contract.
    for guard in [0, SCRATCH + 1, 0x7000_0000] {
        let (_, exit) = guest.run("__cxa_guard_acquire", &[guard]);
        assert_eq!(exit, LIMIT, "guard {guard:#x}");
    }
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 1);
}

#[test]
fn contended_and_reentrant_guard_acquire_stop_without_mutating() {
    let mut guest = Guest::new();
    guest.memory.write_u8(SCRATCH, 0).unwrap();
    assert_eq!(guest.call("__cxa_guard_acquire", &[SCRATCH]), 1);

    // A different guest thread cannot wait on this single-threaded machine,
    // and no nonzero answer may leave the handler: a compiler-generated
    // caller would read it as permission to initialize a second time.
    guest.teb = 0x10000;
    let (_, exit) = guest.run("__cxa_guard_acquire", &[SCRATCH]);
    assert_eq!(exit, LIMIT);
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 0);

    // The owning thread cannot recursively acquire its own guard either.
    guest.teb = 0;
    let (_, exit) = guest.run("__cxa_guard_acquire", &[SCRATCH]);
    assert_eq!(exit, LIMIT);
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 0);

    // The refused acquisitions leave the original owner in charge.
    guest.call("__cxa_guard_release", &[SCRATCH]);
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 1);
    assert_eq!(guest.call("__cxa_guard_acquire", &[SCRATCH]), 0);
}

#[test]
fn invalid_guard_release_and_abort_fail_closed() {
    let mut guest = Guest::new();
    guest.memory.write_u8(SCRATCH, 0).unwrap();

    let (_, exit) = guest.run("__cxa_guard_release", &[SCRATCH]);
    assert_eq!(exit, LIMIT);
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 0);

    let (_, exit) = guest.run("__cxa_guard_abort", &[SCRATCH]);
    assert_eq!(exit, LIMIT);
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 0);

    assert_eq!(guest.call("__cxa_guard_acquire", &[SCRATCH]), 1);
    guest.teb = 0x10000;
    let (_, exit) = guest.run("__cxa_guard_release", &[SCRATCH]);
    assert_eq!(exit, LIMIT, "a different thread cannot release the guard");
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 0);
    guest.teb = 0;
    guest.call("__cxa_guard_abort", &[SCRATCH]);
    assert_eq!(guest.memory.read_u8(SCRATCH).unwrap(), 0);
    assert_eq!(guest.call("__cxa_guard_acquire", &[SCRATCH]), 1);
}

/// E_POINTER for a null out pointer, E_NOTIMPL for a nonzero flag, and a
/// null out pointer after a call that failed.
#[test]
fn xaudio2_create_reports_pointer_and_flag_failures() {
    let mut guest = Guest::new();
    assert_eq!(
        guest.call("XAudio2Create", &[0, 0, 1]) as u32,
        0x8000_4003,
        "a null out pointer"
    );
    guest.memory.write_u64(SCRATCH, 0x1234).unwrap();
    assert_eq!(
        guest.call("XAudio2Create", &[SCRATCH, 1, 1]) as u32,
        0x8000_4001,
        "a nonzero flag"
    );
    assert_eq!(guest.memory.read_u64(SCRATCH).unwrap(), 0);
    assert_eq!(guest.call("XAudio2Create", &[SCRATCH, 0, 1]) as u32, 0);
    assert_ne!(guest.memory.read_u64(SCRATCH).unwrap(), 0);
}

/// The version argument of XAudio2CreateWithVersionInfo is accepted and
/// recorded with the engine it created.
#[test]
fn xaudio2_create_with_version_info_records_the_version_argument() {
    let mut guest = Guest::new();
    guest.memory.write_u64(SCRATCH, 0).unwrap();
    assert_eq!(
        guest.call(
            "XAudio2CreateWithVersionInfo",
            &[SCRATCH, 0, 1, 0x0A00_0000]
        ) as u32,
        0
    );
    let engine = guest.memory.read_u64(SCRATCH).unwrap();
    assert_ne!(engine, 0);
    assert_eq!(
        guest.state.xaudio2_engine_version(engine),
        Some(0x0A00_0000)
    );
}
