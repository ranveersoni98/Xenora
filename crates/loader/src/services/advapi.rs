// SPDX-License-Identifier: GPL-3.0-or-later

//! The cryptographic randomness and user identity of advapi32.
//!
//! The randomness is real host entropy: a simulated machine must not offer
//! predictable bytes behind an interface whose entire contract is
//! unpredictability, so the bytes come from the host's own entropy source.
//! The provider handle is a token in the process table - acquire creates
//! it, generate validates it, release destroys it - because that lifecycle
//! is the observable behavior of the API.

mod bcrypt;

use super::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ServicesState};
use crate::cpu::ExitReason;
use crate::imports::{ImportRegistry, ServiceStatus};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

const MODULE: &str = "advapi32.dll";
const MAX_RANDOM_BYTES: usize = 65_536;
const ERROR_NOT_SUPPORTED: u32 = 50;

/// The live provider tokens of the process.
#[derive(Default)]
pub(super) struct CryptoProviders {
    next: u64,
    live: BTreeSet<u64>,
}

pub(super) fn fill_random(buffer: &mut [u8]) -> Result<(), u32> {
    use std::io::Read;
    let mut source = std::fs::File::open("/dev/urandom").map_err(|_| ERROR_NOT_SUPPORTED)?;
    source.read_exact(buffer).map_err(|_| ERROR_NOT_SUPPORTED)
}

pub(super) fn register(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let providers = Arc::new(Mutex::new(CryptoProviders::default()));

    let acquire = Arc::clone(&providers);
    let acquire_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "CryptAcquireContextA",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            // The provider type must be RSA full and the flags one of the
            // documented machine-default forms; the machine has no key
            // containers, so anything but a fresh default context is honest
            // refusal.
            if args.r9 as u32 != 1
                || args.get(4, memory).map_err(ExitReason::MemoryFault)? & !0xF0000000 != 0
            {
                return acquire_state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            if args.rcx == 0 {
                return acquire_state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let mut live = acquire.lock().expect("crypto provider state");
            if live.live.len() >= 64 {
                return acquire_state.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
            }
            live.next += 4;
            let token = 0xC0DE_0000 + live.next;
            live.live.insert(token);
            memory
                .write_u64(args.rcx, token)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    let release = Arc::clone(&providers);
    let release_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "CryptReleaseContext",
        ServiceStatus::Partial,
        move |args, cpu, _| {
            let mut live = release.lock().expect("crypto provider state");
            if !live.live.remove(&args.rcx) {
                return release_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            Ok(1)
        },
    );

    let generate = Arc::clone(&providers);
    let generate_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "CryptGenRandom",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            if !generate
                .lock()
                .expect("crypto provider state")
                .live
                .contains(&args.rcx)
            {
                return generate_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            let length = args.rdx as usize;
            if length > MAX_RANDOM_BYTES {
                return generate_state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let mut bytes = vec![0u8; length];
            if fill_random(&mut bytes).is_err() {
                return generate_state.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
            }
            memory
                .write_bytes(args.r8, &bytes)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    // SystemFunction036 is RtlGenRandom, the unexported-by-name form the
    // CRT and mingw binaries call directly: no provider, just the bytes.
    let sysfunc_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "SystemFunction036",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            let length = args.rdx as usize;
            if length > MAX_RANDOM_BYTES {
                return sysfunc_state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let mut bytes = vec![0u8; length];
            if fill_random(&mut bytes).is_err() {
                return sysfunc_state.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
            }
            memory
                .write_bytes(args.rcx, &bytes)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    let username_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "GetUserNameA",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            // The machine has one fixed user on its simulated LAN, written
            // with its terminator included in the size contract.
            let name = b"xenora\0";
            if args.rdx == 0 {
                return username_state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let capacity = memory.read_u32(args.rdx).map_err(ExitReason::MemoryFault)? as usize;
            memory
                .write_u32(args.rdx, name.len() as u32)
                .map_err(ExitReason::MemoryFault)?;
            if capacity < name.len() {
                return username_state.fail(cpu.gs_base, 122, 0); // ERROR_INSUFFICIENT_BUFFER
            }
            memory
                .write_bytes(args.rcx, name)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    bcrypt::register(registry, state);
}

// The security-token surface of a machine with exactly one identity.
// There is one user, one logon session, one token: every process token is
// that token, duplication yields the same identity, and the information
// classes answer its fixed contents. AccessCheck follows the same machine
// truth as the SAFER surface below: nothing on the machine is restricted,
// so the one fully trusted identity is never denied. That is not security
// theater - it is what unrestricted execution on a machine without
// privilege separation truthfully answers. What it does not do is evaluate
// a DACL, because the machine models no access control lists; the grant
// is the machine's, not the descriptor's.

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

pub(super) fn register_tokens(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let open = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "OpenProcessToken",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            // The process handle must be the current-process pseudo-handle:
            // there is exactly one process. The token is the machine's one
            // fixed identity token.
            if args.rcx != u64::MAX {
                return open.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            memory
                .write_u64(args.r8, 0x70C0DE)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    let duplicate = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "DuplicateToken",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            if args.rcx != 0x70C0DE {
                return duplicate.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            memory
                .write_u64(args.r8, 0x70C0DE)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    // TokenUser returns an AMD64 SID_AND_ATTRIBUTES header followed by the
    // fixed SID. The header points to the SID in the caller's buffer.
    let info = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "GetTokenInformation",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            if args.rcx != 0x70C0DE {
                return info.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            // Only TokenUser (class 1) has a fixed answer on this machine.
            if args.rdx != 1 {
                return info.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            const HEADER_SIZE: usize = 16;
            const RECORD_SIZE: usize = HEADER_SIZE + MACHINE_SID.len();
            let return_length = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
            let output = args.r8;
            let short = (args.r9 as u32) < RECORD_SIZE as u32;
            if !short {
                memory
                    .check_write(output, RECORD_SIZE)
                    .map_err(ExitReason::MemoryFault)?;
            }
            memory
                .write_u32(return_length, RECORD_SIZE as u32)
                .map_err(ExitReason::MemoryFault)?;
            if short {
                return info.fail(cpu.gs_base, ERROR_INSUFFICIENT_BUFFER, 0);
            }

            let mut record = [0; RECORD_SIZE];
            record[..8].copy_from_slice(&(output + HEADER_SIZE as u64).to_le_bytes());
            record[HEADER_SIZE..].copy_from_slice(&MACHINE_SID);
            memory
                .write_bytes(output, &record)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    // EqualSid compares byte-for-byte: on a machine with one identity it is
    // the honest implementation, not a shortcut.
    let equal = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "EqualSid",
        ServiceStatus::Partial,
        move |args, _cpu, memory| {
            let _ = &equal;
            let read_sid = |address: u64| -> Option<Vec<u8>> {
                let revision = memory.read_u8(address).ok()?;
                let count = memory.read_u8(address + 1).ok()? as u64;
                if revision != 1 || count > 15 {
                    return None;
                }
                let length = 8 + count * 4;
                let mut bytes = vec![0; length as usize];
                memory.read_bytes(address, &mut bytes).ok()?;
                Some(bytes)
            };
            let (Some(left), Some(right)) = (read_sid(args.rcx), read_sid(args.rdx)) else {
                return Ok(0);
            };
            Ok(u64::from(left == right))
        },
    );

    // AccessCheck on a machine with one fully trusted identity and no
    // access control lists: validation is exact, the generic mapping is
    // applied as documented, and the grant is machine truth because
    // nothing here restricts anything. The descriptor is read only far
    // enough to know it is there - no DACL is evaluated, because there is
    // none.
    let check = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "AccessCheck",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            let descriptor = args.rcx;
            let token = args.rdx;
            let desired = args.r8 as u32;
            let mapping = args.r9;
            let privilege_set = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
            let privilege_length = args.get(5, memory).map_err(ExitReason::MemoryFault)?;
            let granted_out = args.get(6, memory).map_err(ExitReason::MemoryFault)?;
            let status_out = args.get(7, memory).map_err(ExitReason::MemoryFault)?;
            if descriptor == 0
                || mapping == 0
                || privilege_length == 0
                || granted_out == 0
                || status_out == 0
            {
                return check.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            if token != MACHINE_TOKEN {
                return check.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            // The descriptor must at least be present to mean anything:
            // its revision and control words are the smallest honest read.
            memory
                .read_u32(descriptor)
                .map_err(ExitReason::MemoryFault)?;
            // The privilege set of a machine that never needs privileges
            // is empty, but its header - count and control, eight bytes -
            // is still written, so the buffer must hold it.
            let length = memory
                .read_u32(privilege_length)
                .map_err(ExitReason::MemoryFault)?;
            if privilege_set != 0 && length < 8 {
                memory
                    .write_u32(privilege_length, 8)
                    .map_err(ExitReason::MemoryFault)?;
                return check.fail(cpu.gs_base, ERROR_INSUFFICIENT_BUFFER, 0);
            }
            if privilege_set != 0 {
                memory
                    .write_u32(privilege_set, 0)
                    .map_err(ExitReason::MemoryFault)?;
                memory
                    .write_u32(privilege_set + 4, 0)
                    .map_err(ExitReason::MemoryFault)?;
                memory
                    .write_u32(privilege_length, 8)
                    .map_err(ExitReason::MemoryFault)?;
            }
            // GENERIC_READ/WRITE/EXECUTE/ALL map through the caller's
            // mapping exactly as the contract documents.
            let generic_read = memory.read_u32(mapping).map_err(ExitReason::MemoryFault)?;
            let generic_write = memory
                .read_u32(mapping + 4)
                .map_err(ExitReason::MemoryFault)?;
            let generic_execute = memory
                .read_u32(mapping + 8)
                .map_err(ExitReason::MemoryFault)?;
            let generic_all = memory
                .read_u32(mapping + 12)
                .map_err(ExitReason::MemoryFault)?;
            let mut granted = desired & !0xF000_0000;
            if desired & 0x8000_0000 != 0 {
                granted |= generic_read;
            }
            if desired & 0x4000_0000 != 0 {
                granted |= generic_write;
            }
            if desired & 0x2000_0000 != 0 {
                granted |= generic_execute;
            }
            if desired & 0x1000_0000 != 0 {
                granted |= generic_all;
            }
            memory
                .write_u32(granted_out, granted)
                .map_err(ExitReason::MemoryFault)?;
            memory
                .write_u32(status_out, 1)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );
}

// The SAFER surface and the remaining token queries. The machine has one
// identity and no privilege separation: every token is the fully trusted
// one because nothing on the machine is restricted. The SAFER bookkeeping
// is real - level handles validate, their levels are remembered, closing
// ends them - but a computed token is the machine's one token, which is
// what unrestricted execution on a machine without privilege separation
// truthfully is. SetTokenInformation would reprogram the one fixed
// identity, so it is honestly unsupported.

/// The machine's one token handle, shared with the token surface above.
const MACHINE_TOKEN: u64 = 0x70C0DE;
/// The machine user's SID bytes: revision 1, one sub-authority, NT
/// authority (5), RID 1000 - the layout GetTokenInformation answers.
const MACHINE_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 0xE8, 0x03, 0, 0];

/// The live SAFER level handles and the level each was opened for.
#[derive(Default)]
pub(super) struct SaferLevels {
    next: u64,
    live: std::collections::BTreeMap<u64, u32>,
}

/// The security-descriptor query. The machine carries one identity, so the
/// owner and group of every object are honestly the machine's user. Access
/// control lists are a different matter: nothing in the machine models them,
/// so a caller asking for a DACL, SACL or a full descriptor gets the honest
/// refusal rather than an invented empty list - an empty DACL means "deny
/// everyone", a null DACL means "allow everyone", and neither is true here.
pub(super) fn register_security_query(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let query = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "GetSecurityInfo",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            use crate::memory::PROCESS_HEAP;
            const OWNER_SECURITY_INFORMATION: u32 = 1;
            const GROUP_SECURITY_INFORMATION: u32 = 2;
            const DACL_SECURITY_INFORMATION: u32 = 4;
            const SACL_SECURITY_INFORMATION: u32 = 8;
            let handle = args.rcx;
            let _object_type = args.rdx as u32;
            let requested = args.r8 as u32;
            let owner_out = args.r9;
            let group_out = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
            let dacl_out = args.get(5, memory).map_err(ExitReason::MemoryFault)?;
            let sacl_out = args.get(6, memory).map_err(ExitReason::MemoryFault)?;
            let descriptor_out = args.get(7, memory).map_err(ExitReason::MemoryFault)?;
            // GetSecurityInfo returns the error code itself, so a failure
            // is the error, not zero.
            let fail = |error: u32| query.fail(cpu.gs_base, error, error as u64);
            if handle == 0 {
                return fail(ERROR_INVALID_PARAMETER);
            }
            // Unknown bits are rejected; the DACL/SACL/descriptor shapes are
            // refused because the machine models no access control lists.
            let modelled = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
            if requested & !(modelled | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION) != 0
            {
                return fail(ERROR_INVALID_PARAMETER);
            }
            if requested & (DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION) != 0
                || descriptor_out != 0
            {
                return fail(ERROR_NOT_SUPPORTED);
            }
            if requested & OWNER_SECURITY_INFORMATION != 0 {
                if owner_out == 0 {
                    return fail(ERROR_INVALID_PARAMETER);
                }
                let sid = match memory.map_heap_allocation(PROCESS_HEAP, MACHINE_SID.len()) {
                    Ok(base) => base,
                    Err(_) => return fail(8), // ERROR_NOT_ENOUGH_MEMORY
                };
                if memory.write_bytes(sid, &MACHINE_SID).is_err()
                    || memory.write_u64(owner_out, sid).is_err()
                {
                    return fail(ERROR_INVALID_PARAMETER);
                }
            }
            if requested & GROUP_SECURITY_INFORMATION != 0 {
                if group_out == 0 {
                    return fail(ERROR_INVALID_PARAMETER);
                }
                let sid = match memory.map_heap_allocation(PROCESS_HEAP, MACHINE_SID.len()) {
                    Ok(base) => base,
                    Err(_) => return fail(8), // ERROR_NOT_ENOUGH_MEMORY
                };
                if memory.write_bytes(sid, &MACHINE_SID).is_err()
                    || memory.write_u64(group_out, sid).is_err()
                {
                    return fail(ERROR_INVALID_PARAMETER);
                }
            }
            let _ = (dacl_out, sacl_out);
            Ok(0)
        },
    );
}

pub(super) fn register_safer(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let levels = Arc::new(Mutex::new(SaferLevels::default()));

    // SaferCreateLevel validates its scope and level and remembers the
    // level under the handle it hands out. The scope ids are USER (1) and
    // MACHINE (2); the levels are the five documented trust steps.
    let create = Arc::clone(&levels);
    let create_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "SaferCreateLevel",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            let scope = args.rcx as u32;
            let level = args.rdx as u32;
            let flags = args.r8;
            let output = args.r9;
            let reserved = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
            const LEVELS: [u32; 5] = [0, 0x1000, 0x10000, 0x20000, 0x40000];
            if !(1..=2).contains(&scope)
                || !LEVELS.contains(&level)
                || flags & !1 != 0
                || reserved != 0
                || output == 0
            {
                return create_state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let mut live = create.lock().expect("SAFER level state");
            if live.live.len() >= 64 {
                return create_state.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
            }
            live.next += 4;
            let handle = 0x5AFE_0000 + live.next;
            live.live.insert(handle, level);
            memory
                .write_u64(output, handle)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    // SaferComputeTokenFromLevel answers the machine's one token for a
    // valid level handle: there is no privilege separation to compute
    // into, so the machine token is what restriction truthfully computes
    // to here. The input token, when given, must be that same token.
    let compute = Arc::clone(&levels);
    let compute_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "SaferComputeTokenFromLevel",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            let output = args.r8;
            if output == 0 {
                return compute_state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let live = compute.lock().expect("SAFER level state");
            if !live.live.contains_key(&args.rcx) {
                return compute_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            if args.rdx != 0 && args.rdx != MACHINE_TOKEN {
                return compute_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            memory
                .write_u64(output, MACHINE_TOKEN)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    // SaferCloseLevel ends the handle's life; a second close is the
    // documented invalid handle.
    let close = Arc::clone(&levels);
    let close_state = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "SaferCloseLevel",
        ServiceStatus::Partial,
        move |args, cpu, _| {
            let mut live = close.lock().expect("SAFER level state");
            if live.live.remove(&args.rcx).is_none() {
                return close_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            Ok(1)
        },
    );

    // CheckTokenMembership answers honestly on a machine with one
    // identity: the machine user's own SID is a member of the machine
    // token, every other SID is not. A null token means the thread's
    // token, which is the same one.
    let membership = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "CheckTokenMembership",
        ServiceStatus::Partial,
        move |args, cpu, memory| {
            if args.rcx != 0 && args.rcx != MACHINE_TOKEN {
                return membership.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            if args.rdx == 0 || args.r8 == 0 {
                return membership.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let mut sid = vec![0u8; MACHINE_SID.len()];
            memory
                .read_bytes(args.rdx, &mut sid)
                .map_err(ExitReason::MemoryFault)?;
            let member = u32::from(sid[..] == MACHINE_SID[..]);
            memory
                .write_u32(args.r8, member)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        },
    );

    // SetTokenInformation would reprogram the machine's one fixed
    // identity. Nothing here is reprogrammable, so the honest answer is
    // refusal, not silent acceptance.
    let set_info = Arc::clone(state);
    registry.register_with_status(
        MODULE,
        "SetTokenInformation",
        ServiceStatus::Implemented,
        move |args, cpu, _| {
            if args.rcx != MACHINE_TOKEN {
                return set_info.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
            set_info.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0)
        },
    );
}

#[cfg(test)]
#[test]
fn crypto_randomness_is_real_and_the_provider_lifecycle_validates() {
    use crate::cpu::{CpuState, Register};
    use crate::import_table::ImportName;
    use crate::imports::Win64Args;
    use crate::memory::{GuestMemory, MemoryPermissions};
    use crate::services::MockClock;

    let mut registry = ImportRegistry::new();
    let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
    register(&mut registry, &state);
    let mut memory = GuestMemory::new();
    memory
        .map_region(0x1000, 8192, MemoryPermissions::READ_WRITE)
        .unwrap();
    let call = |memory: &mut GuestMemory, symbol: &str, args: &[u64]| {
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
            .resolve(MODULE, &ImportName::Name(symbol.to_owned()))
            .unwrap();
        (descriptor.handler)(&Win64Args::new(&cpu), &mut cpu, memory).unwrap()
    };
    // Acquire, generate, release: the lifecycle validates.
    assert_eq!(
        call(
            &mut memory,
            "CryptAcquireContextA",
            &[0x1100, 0, 0, 1, 0xF0000000]
        ),
        1
    );
    let token = memory.read_u64(0x1100).unwrap();
    assert_ne!(token, 0);
    assert_eq!(call(&mut memory, "CryptGenRandom", &[token, 32, 0x1200]), 1);
    // Two generations differ: the bytes are real entropy, not a fixed fill.
    let mut first = [0; 32];
    memory.read_bytes(0x1200, &mut first).unwrap();
    assert_eq!(call(&mut memory, "CryptGenRandom", &[token, 32, 0x1200]), 1);
    let mut second = [0; 32];
    memory.read_bytes(0x1200, &mut second).unwrap();
    assert_ne!(first, second, "real entropy never repeats a 32-byte draw");
    // RtlGenRandom needs no provider.
    assert_eq!(call(&mut memory, "SystemFunction036", &[0x1200, 16]), 1);
    // Release destroys the token; reuse is a bad handle.
    assert_eq!(call(&mut memory, "CryptReleaseContext", &[token, 0]), 1);
    assert_eq!(call(&mut memory, "CryptGenRandom", &[token, 32, 0x1200]), 0);
    // The fixed user name with its size contract.
    memory.write_u32(0x1300, 32).unwrap();
    assert_eq!(call(&mut memory, "GetUserNameA", &[0x1400, 0x1300]), 1);
    assert_eq!(memory.read_u32(0x1300).unwrap(), 7);
    let mut name = [0; 7];
    memory.read_bytes(0x1400, &mut name).unwrap();
    assert_eq!(&name, b"xenora\0");
    // A small buffer reports the needed size and fails honestly.
    memory.write_u32(0x1300, 3).unwrap();
    assert_eq!(call(&mut memory, "GetUserNameA", &[0x1400, 0x1300]), 0);
    assert_eq!(memory.read_u32(0x1300).unwrap(), 7);
}

#[cfg(test)]
#[test]
fn the_fixed_identity_token_answers_its_information_classes() {
    use crate::cpu::{CpuState, Register};
    use crate::import_table::ImportName;
    use crate::imports::Win64Args;
    use crate::memory::{GuestMemory, MemoryPermissions};
    use crate::services::MockClock;

    let mut registry = ImportRegistry::new();
    let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
    register(&mut registry, &state);
    register_tokens(&mut registry, &state);
    let mut memory = GuestMemory::new();
    memory
        .map_region(0x1000, 8192, MemoryPermissions::READ_WRITE)
        .unwrap();
    let try_call = |memory: &mut GuestMemory, symbol: &str, args: &[u64]| {
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
            .resolve(MODULE, &ImportName::Name(symbol.to_owned()))
            .unwrap();
        (descriptor.handler)(&Win64Args::new(&cpu), &mut cpu, memory)
    };
    let call = |memory: &mut GuestMemory, symbol: &str, args: &[u64]| {
        try_call(memory, symbol, args).unwrap()
    };
    // The current process opens its one token; a foreign handle fails.
    assert_eq!(
        call(&mut memory, "OpenProcessToken", &[u64::MAX, 0, 0x1100]),
        1
    );
    assert_eq!(memory.read_u64(0x1100).unwrap(), 0x70C0DE);
    assert_eq!(
        call(&mut memory, "OpenProcessToken", &[0xDEAD, 0, 0x1100]),
        0
    );
    // Duplication yields the same fixed identity.
    assert_eq!(
        call(&mut memory, "DuplicateToken", &[0x70C0DE, 0, 0x1100]),
        1
    );
    // TokenUser answers the fixed SID with its size contract.
    assert_eq!(
        call(
            &mut memory,
            "GetTokenInformation",
            &[0x70C0DE, 1, 0x1200, 64, 0x1180]
        ),
        1
    );
    assert_eq!(memory.read_u32(0x1180).unwrap(), 28);
    assert_eq!(memory.read_u64(0x1200).unwrap(), 0x1210);
    assert_eq!(
        memory.read_u64(0x1208).unwrap(),
        0,
        "attributes and padding"
    );
    assert_eq!(memory.read_u8(0x1210).unwrap(), 1, "SID revision");
    // A small buffer reports the needed size.
    assert_eq!(
        call(
            &mut memory,
            "GetTokenInformation",
            &[0x70C0DE, 1, 0x1200, 4, 0x1180]
        ),
        0
    );
    assert_eq!(memory.read_u32(0x1180).unwrap(), 28);
    // The full record does not fit at the end of this writable mapping.
    // The first 16 bytes and ReturnLength must retain their original values.
    let canary = [0x5a; 16];
    memory.write_bytes(0x2ff0, &canary).unwrap();
    memory.write_u32(0x1180, 0xabcd).unwrap();
    assert!(matches!(
        try_call(
            &mut memory,
            "GetTokenInformation",
            &[MACHINE_TOKEN, 1, 0x2ff0, 28, 0x1180]
        ),
        Err(ExitReason::MemoryFault(_))
    ));
    let mut header = [0; 16];
    memory.read_bytes(0x2ff0, &mut header).unwrap();
    assert_eq!(header, canary);
    assert_eq!(memory.read_u32(0x1180).unwrap(), 0xabcd);
    // EqualSid compares byte-for-byte.
    let sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 0xE8, 0x03, 0, 0];
    memory.write_bytes(0x1300, &sid).unwrap();
    memory.write_bytes(0x1310, &sid).unwrap();
    assert_eq!(call(&mut memory, "EqualSid", &[0x1300, 0x1310]), 1);
    memory.write_u8(0x1318, 0xE9).unwrap();
    assert_eq!(call(&mut memory, "EqualSid", &[0x1300, 0x1310]), 0);
}

#[cfg(test)]
#[test]
fn the_safer_levels_validate_and_compute_the_one_token() {
    use crate::cpu::{CpuState, Register};
    use crate::import_table::ImportName;
    use crate::imports::Win64Args;
    use crate::memory::{GuestMemory, MemoryPermissions};
    use crate::services::MockClock;

    let mut registry = ImportRegistry::new();
    let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
    register(&mut registry, &state);
    register_tokens(&mut registry, &state);
    register_safer(&mut registry, &state);
    let mut memory = GuestMemory::new();
    memory
        .map_region(0x1000, 8192, MemoryPermissions::READ_WRITE)
        .unwrap();
    let call = |memory: &mut GuestMemory, symbol: &str, args: &[u64]| {
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
            .resolve(MODULE, &ImportName::Name(symbol.to_owned()))
            .unwrap();
        (descriptor.handler)(&Win64Args::new(&cpu), &mut cpu, memory).unwrap()
    };
    // A level validates its scope, level, flags and output pointer.
    assert_eq!(
        call(&mut memory, "SaferCreateLevel", &[2, 0x40000, 1, 0x1100, 0]),
        1
    );
    let level = memory.read_u64(0x1100).unwrap();
    assert_ne!(level, 0);
    assert_eq!(
        call(&mut memory, "SaferCreateLevel", &[9, 0x40000, 1, 0x1100, 0]),
        0,
        "an unknown scope is refused"
    );
    assert_eq!(
        call(&mut memory, "SaferCreateLevel", &[2, 0x33333, 1, 0x1100, 0]),
        0,
        "an unknown level is refused"
    );
    // Computing over the level answers the machine's one token, and the
    // input token validates when given.
    assert_eq!(
        call(
            &mut memory,
            "SaferComputeTokenFromLevel",
            &[level, 0, 0x1100]
        ),
        1
    );
    assert_eq!(memory.read_u64(0x1100).unwrap(), MACHINE_TOKEN);
    assert_eq!(
        call(
            &mut memory,
            "SaferComputeTokenFromLevel",
            &[level, 0xDEAD, 0x1100]
        ),
        0,
        "a foreign input token fails"
    );
    assert_eq!(
        call(
            &mut memory,
            "SaferComputeTokenFromLevel",
            &[0xDEAD, 0, 0x1100]
        ),
        0,
        "a foreign level handle fails"
    );
    // Closing ends the level once; the second close is invalid.
    assert_eq!(call(&mut memory, "SaferCloseLevel", &[level]), 1);
    assert_eq!(call(&mut memory, "SaferCloseLevel", &[level]), 0);
    // CheckTokenMembership: the machine user's own SID is a member of the
    // machine token, another SID is not, and a foreign token fails.
    memory.write_bytes(0x1300, &MACHINE_SID).unwrap();
    assert_eq!(
        call(&mut memory, "CheckTokenMembership", &[0, 0x1300, 0x1180]),
        1
    );
    assert_eq!(memory.read_u32(0x1180).unwrap(), 1, "own SID is a member");
    let mut other = MACHINE_SID;
    other[8] = 0xE9;
    memory.write_bytes(0x1300, &other).unwrap();
    assert_eq!(
        call(
            &mut memory,
            "CheckTokenMembership",
            &[MACHINE_TOKEN, 0x1300, 0x1180]
        ),
        1
    );
    assert_eq!(memory.read_u32(0x1180).unwrap(), 0, "another SID is not");
    assert_eq!(
        call(
            &mut memory,
            "CheckTokenMembership",
            &[0xDEAD, 0x1300, 0x1180]
        ),
        0
    );
    // SetTokenInformation validates its token and then honestly refuses.
    assert_eq!(
        call(
            &mut memory,
            "SetTokenInformation",
            &[0x70C0DE, 1, 0x1200, 4]
        ),
        0
    );
    assert_eq!(
        call(&mut memory, "SetTokenInformation", &[0xDEAD, 1, 0x1200, 4]),
        0
    );
}

#[cfg(test)]
#[test]
fn security_info_answers_the_one_identity_and_refuses_acls() {
    use super::ServicesState;
    use crate::cpu::{CpuState, Register};
    use crate::import_table::ImportName;
    use crate::imports::Win64Args;
    use crate::memory::{GuestMemory, MemoryPermissions};
    use crate::services::MockClock;
    use std::sync::Arc;

    let mut registry = ImportRegistry::new();
    let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
    register_security_query(&mut registry, &state);
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

    // Owner and group of any object are the machine's one identity.
    let result = call(
        &mut memory,
        MODULE,
        "GetSecurityInfo",
        &[0x70C0DE, 1, 3, 0x1100, 0x1108, 0, 0, 0],
    );
    assert_eq!(result, 0, "ERROR_SUCCESS for the modelled query");
    let owner = memory.read_u64(0x1100).unwrap();
    let group = memory.read_u64(0x1108).unwrap();
    assert_ne!(owner, 0);
    assert_ne!(group, 0);
    let mut sid = vec![0u8; MACHINE_SID.len()];
    memory.read_bytes(owner, &mut sid).unwrap();
    assert_eq!(
        sid[..],
        MACHINE_SID[..],
        "the owner is the machine identity"
    );
    memory.read_bytes(group, &mut sid).unwrap();
    assert_eq!(
        sid[..],
        MACHINE_SID[..],
        "the group is the machine identity"
    );
    // A DACL query is the honest refusal: the machine models no ACLs, and
    // the error comes back in the return value itself.
    const ERROR_NOT_SUPPORTED: u32 = 50;
    let result = call(
        &mut memory,
        MODULE,
        "GetSecurityInfo",
        &[0x70C0DE, 1, 4, 0x1100, 0, 0x1110, 0, 0],
    );
    assert_eq!(result, ERROR_NOT_SUPPORTED as u64);
}

#[cfg(test)]
#[test]
fn access_check_grants_the_one_identity_and_validates_exactly() {
    use crate::cpu::{CpuState, Register};
    use crate::import_table::ImportName;
    use crate::imports::Win64Args;
    use crate::memory::{GuestMemory, MemoryPermissions};
    use crate::services::MockClock;

    let mut registry = ImportRegistry::new();
    let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
    register(&mut registry, &state);
    register_tokens(&mut registry, &state);
    let mut memory = GuestMemory::new();
    memory
        .map_region(0x1000, 8192, MemoryPermissions::READ_WRITE)
        .unwrap();
    let call = |memory: &mut GuestMemory, args: &[u64]| {
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
            .resolve(MODULE, &ImportName::Name("AccessCheck".to_owned()))
            .unwrap();
        (descriptor.handler)(&Win64Args::new(&cpu), &mut cpu, memory).unwrap()
    };
    // A self-relative descriptor header, the generic mapping of a file
    // object, and the output slots.
    memory.write_u32(0x1100, 1).unwrap(); // descriptor revision presence
    memory.write_u32(0x1200, 0x0012_0089).unwrap(); // generic read
    memory.write_u32(0x1204, 0x0012_0116).unwrap(); // generic write
    memory.write_u32(0x1208, 0x0012_00A0).unwrap(); // generic execute
    memory.write_u32(0x120C, 0x001F_01FF).unwrap(); // generic all
    memory.write_u32(0x1300, 64).unwrap(); // privilege buffer length
    // GENERIC_READ alone maps to the file-read bits and is granted.
    let args = [
        0x1100,
        MACHINE_TOKEN,
        0x8000_0000,
        0x1200,
        0x1400,
        0x1300,
        0x1500,
        0x1504,
    ];
    assert_eq!(call(&mut memory, &args), 1);
    assert_eq!(memory.read_u32(0x1500).unwrap(), 0x0012_0089, "mapped read");
    assert_eq!(memory.read_u32(0x1504).unwrap(), 1, "access granted");
    // The empty privilege set header is written and the length updated.
    assert_eq!(memory.read_u32(0x1400).unwrap(), 0, "no privileges");
    assert_eq!(
        memory.read_u32(0x1300).unwrap(),
        8,
        "length of the empty set"
    );
    // Specific bits pass through unmapped, combined with generic mapping.
    memory.write_u32(0x1300, 64).unwrap();
    let args = [
        0x1100,
        MACHINE_TOKEN,
        0x8000_0004,
        0x1200,
        0x1400,
        0x1300,
        0x1500,
        0x1504,
    ];
    assert_eq!(call(&mut memory, &args), 1);
    assert_eq!(
        memory.read_u32(0x1500).unwrap(),
        0x0012_0089 | 4,
        "specific bits survive beside the mapping"
    );
    // A privilege buffer too small reports the needed eight bytes.
    memory.write_u32(0x1300, 4).unwrap();
    assert_eq!(call(&mut memory, &args), 0);
    assert_eq!(
        memory.read_u32(0x1300).unwrap(),
        8,
        "required size reported"
    );
    // A foreign token is a bad handle; a null descriptor is invalid.
    memory.write_u32(0x1300, 64).unwrap();
    let bad_token = [
        0x1100,
        0xDEAD,
        0x8000_0000,
        0x1200,
        0x1400,
        0x1300,
        0x1500,
        0x1504,
    ];
    assert_eq!(call(&mut memory, &bad_token), 0);
    let null_sd = [
        0,
        MACHINE_TOKEN,
        0x8000_0000,
        0x1200,
        0x1400,
        0x1300,
        0x1500,
        0x1504,
    ];
    assert_eq!(call(&mut memory, &null_sd), 0);
}
