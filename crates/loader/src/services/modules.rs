// SPDX-License-Identifier: GPL-3.0-or-later

//! Module handles and export lookup for the program, built-in services and
//! registered guest modules.
//!
//! The program's handle is the base address its image was loaded at. Kernel32,
//! KernelBase and the UCRT are built in: their handles are identities with no
//! image behind them. Kernel32 and KernelBase, like the program, are never
//! unloaded; the UCRT is when its last reference is released. Prepared guest
//! modules admitted through the crate-internal catalog hook use their image
//! base as their handle and are process-resident because unloading does not
//! exist yet.
//!
//! Documented (Microsoft Learn): the meaning of a null name, the appended `.dll`,
//! case-insensitive comparison, the `GetModuleHandleEx` flags and the exclusion
//! of pinning with an unchanged count, and that a module a call did not count
//! must not be freed. Microsoft gives no error codes here; the ones used are
//! Xenora's choice. No host library is ever searched for or loaded.

use super::{
    CURRENT_PROCESS, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOACCESS,
    ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED, KERNEL32, ObjectState, ServicesState,
};
use crate::cpu::ExitReason;
use crate::export_table::{ExportTable, ExportTarget};
use crate::import_table::ImportName;
use crate::imports::{DynamicTrampolines, ImportRegistry, ServiceStatus};
use crate::memory::{GuestMemory, MainImage, MemoryError};
use crate::module_graph::{
    ExportKey, FileNameError, normalize_module_reference, parse_forwarder, validate_file_name,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

const KERNELBASE: &str = "kernelbase.dll";
const PSAPI: &str = "psapi.dll";
const UCRT: &str = "ucrtbase.dll";
/// Where Microsoft's pages list `GetModuleHandle`, `GetModuleHandleEx`,
/// `GetProcAddress` and `FreeLibrary`, besides `kernel32.dll`.
const LOADER_APIS: [&str; 8] = [
    "api-ms-win-core-libraryloader-l1-1-0.dll",
    "api-ms-win-core-libraryloader-l1-1-1.dll",
    LOADER_API,
    "api-ms-win-core-libraryloader-l1-2-1.dll",
    "api-ms-win-core-libraryloader-l1-2-2.dll",
    "api-ms-win-core-libraryloader-l1-2-3.dll",
    "api-ms-win-downlevel-kernel32-l1-1-0.dll",
    KERNELBASE,
];
const LOADER_API: &str = "api-ms-win-core-libraryloader-l1-2-0.dll";
/// The same for `LoadLibraryA` and `LoadLibraryW`.
const LOAD_LIBRARY_APIS: [&str; 12] = [
    "api-ms-win-core-libraryloader-l1-2-1.dll",
    "api-ms-win-core-libraryloader-l1-2-2.dll",
    "api-ms-win-core-libraryloader-l1-2-3.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
    "api-ms-win-core-kernel32-legacy-l1-1-6.dll",
    "api-ms-win-downlevel-kernel32-l2-1-0.dll",
    KERNELBASE,
];
/// API sets listed for `GetModuleInformation` and `K32GetModuleInformation`
/// together.
const PSAPI_APIS: [&str; 2] = [
    "api-ms-win-core-psapi-l1-1-0.dll",
    "api-ms-win-core-psapi-obsolete-l1-1-0.dll",
];

const MODULE_NOT_FOUND: u32 = 126;
const PROCEDURE_NOT_FOUND: u32 = 127;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const MODULE_BASE: u64 = 0x0000_0007_e000_0000;
const UCRT_HANDLE: u64 = MODULE_BASE + 0x10000;
const KERNELBASE_HANDLE: u64 = MODULE_BASE + 0x20000;

/// `GET_MODULE_HANDLE_EX_FLAG_*`.
const PIN: u32 = 1;
const UNCHANGED_REFCOUNT: u32 = 2;
const FROM_ADDRESS: u32 = 4;

/// Size of `MODULEINFO` on x64: a pointer, a DWORD and a pointer.
const MODULE_INFO_SIZE: usize = 24;
/// Maximum number of forwarder edges followed by a dynamic export lookup.
/// This is the same Xenora policy bound as static package import resolution.
const MAX_DYNAMIC_FORWARDER_HOPS: usize = crate::module_graph::MAX_FORWARDER_HOPS;

#[derive(Default)]
struct Modules {
    names: BTreeMap<String, u64>,
    exports: BTreeMap<u64, HashMap<ImportName, usize>>,
    references: Mutex<References>,
    dynamic: Mutex<DynamicModules>,
}

#[derive(Default)]
struct References {
    counts: BTreeMap<u64, u32>,
    pinned: BTreeSet<u64>,
}

/// Cloneable handle to the process module catalog. The catalog is initialized
/// once when kernel32 services are registered; dynamic registrations then
/// mutate only the closed-world table inside it.
#[derive(Clone, Default)]
pub(crate) struct ModuleCatalog {
    inner: Arc<OnceLock<Modules>>,
}

impl ModuleCatalog {
    fn get(&self) -> Option<&Modules> {
        self.inner.get()
    }

    /// Register one already prepared guest image. The registration is a
    /// metadata operation only: the caller has already mapped, relocated and
    /// bound the image, and this hook neither loads nor executes anything.
    #[allow(dead_code)] // Consumed by the later crate-internal LoadLibrary integration (#923).
    pub(crate) fn register_dynamic_module(
        &self,
        registration: DynamicModuleRegistration,
    ) -> Result<u64, DynamicModuleRegistrationError> {
        let modules = self
            .get()
            .ok_or(DynamicModuleRegistrationError::CatalogUnavailable)?;
        modules.register_dynamic(registration)
    }
}

/// Metadata for one prepared guest module admitted to the in-memory catalog.
/// `name` is the closed-world logical file name, never a host path. `exports`
/// is the already validated export inventory retained by the loader pipeline.
#[allow(dead_code)] // Constructed by the later crate-internal LoadLibrary integration (#923).
pub(crate) struct DynamicModuleRegistration {
    pub name: String,
    pub base: u64,
    pub size: u32,
    pub exports: Option<ExportTable>,
}

/// Why a prepared guest module was not admitted to the catalog.
#[derive(Debug)]
#[allow(dead_code)] // Returned through the crate-internal registration hook for #923.
pub(crate) enum DynamicModuleRegistrationError {
    CatalogUnavailable,
    InvalidName { name: String, reason: FileNameError },
    InvalidRange { base: u64, size: u32 },
    NameCollision { name: String },
    BaseCollision { base: u64 },
    ExportOutsideImage { name: String, rva: u32 },
}

impl fmt::Display for DynamicModuleRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogUnavailable => f.write_str("the module catalog is not initialized"),
            Self::InvalidName { name, reason } => {
                write!(f, "dynamic module name {name:?} is invalid: {reason}")
            }
            Self::InvalidRange { base, size } => write!(
                f,
                "dynamic module range base 0x{base:x}, size 0x{size:x} is invalid"
            ),
            Self::NameCollision { name } => {
                write!(f, "dynamic module name {name:?} is already registered")
            }
            Self::BaseCollision { base } => {
                write!(f, "dynamic module base 0x{base:x} is already registered")
            }
            Self::ExportOutsideImage { name, rva } => write!(
                f,
                "dynamic module {name:?} has an export RVA 0x{rva:x} outside its image"
            ),
        }
    }
}

impl std::error::Error for DynamicModuleRegistrationError {}

#[derive(Default)]
struct DynamicModules {
    modules: Vec<DynamicModule>,
    by_name: BTreeMap<String, usize>,
    by_base: BTreeMap<u64, usize>,
}

struct DynamicModule {
    /// Logical closed-world file name, with its original ASCII casing.
    name: String,
    base: u64,
    size: u32,
    exports: Option<ExportTable>,
}

/// Register a prepared guest image in the process module catalog. This is the
/// crate-internal hook consumed by the later LoadLibrary integration; it is
/// deliberately unavailable outside the loader crate.
#[allow(dead_code)] // Consumed by the later crate-internal LoadLibrary integration (#923).
pub(crate) fn register_dynamic_module(
    registry: &ImportRegistry,
    registration: DynamicModuleRegistration,
) -> Result<u64, DynamicModuleRegistrationError> {
    registry
        .module_catalog
        .register_dynamic_module(registration)
}

/// Modules that are loaded for as long as the process runs.
fn is_resident(memory: &GuestMemory, handle: u64) -> bool {
    matches!(handle, MODULE_BASE | KERNELBASE_HANDLE)
        || memory.main_image.is_some_and(|image| image.base == handle)
}

impl References {
    fn is_loaded(&self, memory: &GuestMemory, handle: u64) -> bool {
        is_resident(memory, handle)
            || self.counts.contains_key(&handle)
            || self.pinned.contains(&handle)
    }

    /// Add a reference. False if the count cannot grow.
    fn add(&mut self, handle: u64) -> bool {
        let count = self.counts.entry(handle).or_default();
        let next = count.checked_add(1);
        if let Some(next) = next {
            *count = next;
        }
        next.is_some()
    }
}

fn read_name(
    memory: &GuestMemory,
    address: u64,
    wide: bool,
) -> Result<Option<String>, MemoryError> {
    let mut name = String::new();
    let width = if wide { 2 } else { 1 };
    for index in 0..260 {
        let slot = address
            .checked_add(index * width)
            .ok_or(MemoryError::Overflow)?;
        let unit = if wide {
            memory.read_u16(slot)?
        } else {
            u16::from(memory.read_u8(slot)?)
        };
        if unit == 0 {
            return Ok(Some(name));
        }
        if !(0x20..=0x7e).contains(&unit) {
            return Ok(None);
        }
        name.push(char::from(unit as u8));
    }
    Ok(None)
}

impl Modules {
    /// Handle of a module a normalized closed-world reference names. Built-in
    /// identities are checked first because provisioned stores refuse a module
    /// identity already owned by the service registry.
    fn handle_for_normalized(&self, normalized: &str) -> Option<u64> {
        if let Some(handle) = self.names.get(normalized) {
            return Some(*handle);
        }
        let dynamic = self.dynamic.lock().expect("dynamic module catalog");
        dynamic
            .by_name
            .get(normalized)
            .map(|&index| dynamic.modules[index].base)
    }

    /// Handle of the module a guest name refers to, loaded or not. Without a
    /// dot `.dll` is appended; a trailing dot stands for no extension.
    fn named(
        &self,
        memory: &GuestMemory,
        address: u64,
        wide: bool,
    ) -> Result<Option<u64>, MemoryError> {
        let Some(name) = read_name(memory, address, wide)? else {
            return Ok(None);
        };
        let normalized = normalize_module_reference(&name);
        Ok(self.handle_for_normalized(&normalized))
    }

    /// Handle of a loaded module by name; a null name is the program.
    fn loaded(
        &self,
        memory: &GuestMemory,
        address: u64,
        wide: bool,
    ) -> Result<Option<u64>, MemoryError> {
        if address == 0 {
            return Ok(memory.main_image.map(|image| image.base));
        }
        let handle = self.named(memory, address, wide)?;
        let references = self.references.lock().expect("module references");
        Ok(handle.filter(|&handle| references.is_loaded(memory, handle)))
    }

    /// Handle of the loaded module that contains an address. A built-in module
    /// has no image, so only its base address is inside it.
    fn containing(&self, memory: &GuestMemory, address: u64) -> Option<u64> {
        if let Some(image) = memory.main_image
            && address
                .checked_sub(image.base)
                .is_some_and(|offset| offset < u64::from(image.size))
        {
            return Some(image.base);
        }
        if let Some(base) = self.dynamic_containing(address) {
            return Some(base);
        }
        let references = self.references.lock().expect("module references");
        let built_in = self.exports.contains_key(&address);
        (built_in && references.is_loaded(memory, address)).then_some(address)
    }

    fn dynamic_containing(&self, address: u64) -> Option<u64> {
        let dynamic = self.dynamic.lock().expect("dynamic module catalog");
        dynamic.modules.iter().find_map(|module| {
            let inside = address
                .checked_sub(module.base)
                .is_some_and(|offset| offset < u64::from(module.size));
            inside.then_some(module.base)
        })
    }

    fn dynamic_name(&self, base: u64) -> Option<String> {
        let dynamic = self.dynamic.lock().expect("dynamic module catalog");
        dynamic
            .by_base
            .get(&base)
            .map(|&index| dynamic.modules[index].name.clone())
    }

    /// Admit one prepared module. Dynamic modules are pinned and carry one
    /// loader-owned reference: Xenora does not yet implement unloading, so a
    /// guest `FreeLibrary` can release references but never unmaps the image.
    /// This is a deliberate process-resident deviation rather than emulation
    /// of Windows loader reference-count teardown.
    #[allow(dead_code)] // Reached through the crate-internal registration hook for #923.
    fn register_dynamic(
        &self,
        registration: DynamicModuleRegistration,
    ) -> Result<u64, DynamicModuleRegistrationError> {
        let name = registration.name;
        if let Err(reason) = validate_file_name(&name) {
            return Err(DynamicModuleRegistrationError::InvalidName { name, reason });
        }
        let canonical_name = name.to_ascii_lowercase();
        let base = registration.base;
        let size = registration.size;
        if base == 0 || size == 0 {
            return Err(DynamicModuleRegistrationError::InvalidRange { base, size });
        }
        let Some(end) = base.checked_add(u64::from(size)) else {
            return Err(DynamicModuleRegistrationError::InvalidRange { base, size });
        };
        if self.names.values().any(|&handle| handle == base) {
            return Err(DynamicModuleRegistrationError::BaseCollision { base });
        }
        if self.names.contains_key(&canonical_name) {
            return Err(DynamicModuleRegistrationError::NameCollision { name });
        }
        if let Some(table) = &registration.exports {
            for entry in &table.entries {
                if let ExportTarget::ExportRva(rva) = entry.target
                    && rva >= size
                {
                    return Err(DynamicModuleRegistrationError::ExportOutsideImage { name, rva });
                }
            }
        }

        let mut dynamic = self.dynamic.lock().expect("dynamic module catalog");
        let mut references = self.references.lock().expect("module references");
        if dynamic.by_name.contains_key(&canonical_name) {
            return Err(DynamicModuleRegistrationError::NameCollision { name });
        }
        let overlaps = dynamic.modules.iter().any(|module| {
            let existing_end = module.base + u64::from(module.size);
            base < existing_end && module.base < end
        });
        if overlaps || dynamic.by_base.contains_key(&base) {
            return Err(DynamicModuleRegistrationError::BaseCollision { base });
        }

        let index = dynamic.modules.len();
        dynamic.by_name.insert(canonical_name.clone(), index);
        dynamic.by_base.insert(base, index);
        dynamic.modules.push(DynamicModule {
            name,
            base,
            size,
            exports: registration.exports,
        });
        references.counts.insert(base, 1);
        references.pinned.insert(base);
        Ok(base)
    }

    /// Resolve a procedure export. Guest-module direct exports are guest image
    /// addresses. A forwarder may cross to another guest module or terminate in
    /// a captured built-in service export, in which case the existing dynamic
    /// service trampoline is exposed. At most eight forwarder edges are used.
    fn procedure_address(
        &self,
        memory: &GuestMemory,
        start_handle: u64,
        export: &ImportName,
        trampolines: &DynamicTrampolines,
    ) -> Option<u64> {
        let mut handle = start_handle;
        let mut key = match export {
            ImportName::Name(name) => ExportKey::Name(name.clone()),
            ImportName::Ordinal(ordinal) => ExportKey::Ordinal(u32::from(*ordinal)),
        };
        let mut forwarder_hops = 0usize;
        loop {
            let dynamic_lookup = {
                let dynamic = self.dynamic.lock().expect("dynamic module catalog");
                dynamic.by_base.get(&handle).map(|&index| {
                    let module = &dynamic.modules[index];
                    let target = module
                        .exports
                        .as_ref()
                        .and_then(|table| export_target(table, &key));
                    (module.base, target)
                })
            };
            if let Some((base, target)) = dynamic_lookup {
                match target? {
                    ExportTarget::Empty => return None,
                    ExportTarget::ExportRva(rva) => {
                        return base.checked_add(u64::from(rva));
                    }
                    ExportTarget::Forwarder { target, .. } => {
                        if forwarder_hops >= MAX_DYNAMIC_FORWARDER_HOPS {
                            return None;
                        }
                        forwarder_hops += 1;
                        let (target_module, target_export) = parse_forwarder(&target).ok()?;
                        let target_handle = self.handle_for_normalized(&target_module)?;
                        let target_loaded = {
                            let references = self.references.lock().expect("module references");
                            references.is_loaded(memory, target_handle)
                        };
                        if !target_loaded {
                            return None;
                        }
                        handle = target_handle;
                        key = target_export;
                        continue;
                    }
                }
            }

            let exports = self.exports.get(&handle)?;
            let import = match key {
                ExportKey::Name(name) => ImportName::Name(name),
                ExportKey::Ordinal(ordinal) => ImportName::Ordinal(u16::try_from(ordinal).ok()?),
            };
            return exports.get(&import).map(|&index| trampolines.expose(index));
        }
    }
}

fn export_target(table: &ExportTable, key: &ExportKey) -> Option<ExportTarget> {
    table
        .entries
        .iter()
        .find(|entry| match key {
            ExportKey::Name(name) => entry.names.iter().any(|candidate| candidate == name),
            ExportKey::Ordinal(ordinal) => entry.ordinal == *ordinal,
        })
        .map(|entry| entry.target.clone())
}

pub(super) fn register(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let modules = registry.module_catalog.clone();
    let catalog = |modules: &ModuleCatalog| modules.clone();

    for (symbol, wide) in [("GetModuleHandleA", false), ("GetModuleHandleW", true)] {
        let state = Arc::clone(state);
        let modules = catalog(&modules);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let modules = modules.get().expect("built-in module catalog");
            let handle = modules.loaded(memory, args.rcx, wide);
            match handle.map_err(ExitReason::MemoryFault)? {
                Some(handle) => Ok(handle),
                None => state.fail(cpu.gs_base, MODULE_NOT_FOUND, 0),
            }
        });
    }

    // `GetModuleFileName` answers the path the program was started with for
    // its own image - the same string the command line is built from. Any
    // other module does not exist here, as no library is ever loaded into
    // the address space as an image.
    for (symbol, wide) in [("GetModuleFileNameA", false), ("GetModuleFileNameW", true)] {
        let state = Arc::clone(state);
        let modules = catalog(&modules);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let modules = modules.get().expect("module catalog");
            let (module, buffer, capacity) = (args.rcx, args.rdx, args.r8 as u32);
            let main = module == 0 || memory.main_image.is_some_and(|image| module == image.base);
            let dynamic_name = (!main).then(|| modules.dynamic_name(module)).flatten();
            if !main && dynamic_name.is_none() {
                return state.fail(cpu.gs_base, MODULE_NOT_FOUND, 0);
            }
            if capacity == 0 {
                return state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let path = if main {
                // The process image path is the image the process runs, not
                // its first argument: a multi-call binary re-executed under
                // an applet name still has the one image, as busybox-w32's
                // forkshell re-execution does when it passes the shell's
                // name as argv[0] and then stats its own executable before
                // spawning (#1290). The argument form stays as the fallback
                // of a machine that keeps no image.
                let image = state.spawn_image_name();
                if image.is_empty() {
                    state
                        .crt_arguments()
                        .for_command_line()
                        .first()
                        .cloned()
                        .unwrap_or_default()
                } else {
                    // Windows always answers an absolute path here, and the
                    // guests rely on it: busybox-w32 stats this very path
                    // before every spawn, so a relative form stops resolving
                    // as soon as the process leaves the directory it started
                    // in (#1342). The canonical drive key anchored at the
                    // volume root is the absolute form of the provisioned
                    // image wherever the working directory stands.
                    match ObjectState::drive_path(image.as_bytes()) {
                        Some(key) if !key.is_empty() => format!("c:\\{}", key),
                        _ => image,
                    }
                }
            } else {
                dynamic_name.expect("validated dynamic module name")
            };
            // The count semantics are the documented truncation form: a
            // small buffer receives what fits, terminated, and the answer
            // is the capacity itself with ERROR_INSUFFICIENT_BUFFER.
            let units: Vec<u16> = if wide {
                path.encode_utf16().collect()
            } else {
                path.bytes().map(u16::from).collect()
            };
            let width = if wide { 2u64 } else { 1u64 };
            let fits = units.len() < capacity as usize;
            let copied = if fits {
                units.len()
            } else {
                capacity as usize - 1
            };
            for (index, unit) in units.iter().take(copied).enumerate() {
                let at = buffer + index as u64 * width;
                if wide {
                    memory
                        .write_u16(at, *unit)
                        .map_err(ExitReason::MemoryFault)?;
                } else {
                    memory
                        .write_u8(at, *unit as u8)
                        .map_err(ExitReason::MemoryFault)?;
                }
            }
            let end = buffer + copied as u64 * width;
            if wide {
                memory.write_u16(end, 0).map_err(ExitReason::MemoryFault)?;
            } else {
                memory.write_u8(end, 0).map_err(ExitReason::MemoryFault)?;
            }
            if fits {
                Ok(units.len() as u64)
            } else {
                state.fail(cpu.gs_base, ERROR_INSUFFICIENT_BUFFER, u64::from(capacity))
            }
        });
    }

    for (symbol, wide) in [("GetModuleHandleExA", false), ("GetModuleHandleExW", true)] {
        let state = Arc::clone(state);
        let modules = catalog(&modules);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let modules = modules.get().expect("built-in module catalog");
            let (flags, name, output) = (args.rcx as u32, args.rdx, args.r8);
            if output == 0 {
                return state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            // The handle is null on failure, so it is written first.
            if memory.write_u64(output, 0).is_err() {
                return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            if flags & !(PIN | UNCHANGED_REFCOUNT | FROM_ADDRESS) != 0
                || flags & (PIN | UNCHANGED_REFCOUNT) == PIN | UNCHANGED_REFCOUNT
                || (flags & FROM_ADDRESS != 0 && name == 0)
            {
                return state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let handle = if flags & FROM_ADDRESS != 0 {
                modules.containing(memory, name)
            } else {
                modules
                    .loaded(memory, name, wide)
                    .map_err(ExitReason::MemoryFault)?
            };
            let Some(handle) = handle else {
                return state.fail(cpu.gs_base, MODULE_NOT_FOUND, 0);
            };
            let mut references = modules.references.lock().expect("module references");
            if flags & PIN != 0 {
                references.pinned.insert(handle);
            } else if flags & UNCHANGED_REFCOUNT == 0 && !references.add(handle) {
                return state.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, 0);
            }
            memory
                .write_u64(output, handle)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        });
    }

    for (symbol, wide) in [("LoadLibraryA", false), ("LoadLibraryW", true)] {
        let state = Arc::clone(state);
        let modules = catalog(&modules);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let modules = modules.get().expect("built-in module catalog");
            let handle = match args.rcx {
                0 => None,
                name => modules
                    .named(memory, name, wide)
                    .map_err(ExitReason::MemoryFault)?,
            };
            let Some(handle) = handle else {
                return state.fail(cpu.gs_base, MODULE_NOT_FOUND, 0);
            };
            let mut references = modules.references.lock().expect("module references");
            if !references.add(handle) {
                return state.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, 0);
            }
            Ok(handle)
        });
    }

    // The Ex forms add flags. hFile must be null as documented, and the
    // flags do not alter built-in resolution: the catalog is not a search
    // path, there are no DLL references to defer, and a data-file load of a
    // built-in module is the same module. That is documented in the module
    // rather than hidden.
    for (symbol, wide) in [("LoadLibraryExA", false), ("LoadLibraryExW", true)] {
        let state = Arc::clone(state);
        let modules = catalog(&modules);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            if args.rdx != 0 {
                return state.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let modules = modules.get().expect("built-in module catalog");
            let handle = match args.rcx {
                0 => None,
                name => modules
                    .named(memory, name, wide)
                    .map_err(ExitReason::MemoryFault)?,
            };
            let Some(handle) = handle else {
                return state.fail(cpu.gs_base, MODULE_NOT_FOUND, 0);
            };
            let mut references = modules.references.lock().expect("module references");
            if !references.add(handle) {
                return state.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, 0);
            }
            Ok(handle)
        });
    }

    let release = catalog(&modules);
    let release_state = Arc::clone(state);
    let release_trampolines = registry.dynamic_trampolines();
    registry.register(KERNEL32, "FreeLibrary", move |args, cpu, memory| {
        let modules = release.get().expect("built-in module catalog");
        let mut references = modules.references.lock().expect("module references");
        let Some(count) = references.counts.get_mut(&args.rcx) else {
            return release_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        };
        *count -= 1;
        if *count == 0 {
            references.counts.remove(&args.rcx);
            if !references.is_loaded(memory, args.rcx)
                && let Some(exports) = modules.exports.get(&args.rcx)
            {
                release_trampolines.revoke(exports.values().copied());
            }
        }
        Ok(1)
    });

    let lookup = catalog(&modules);
    let trampolines = registry.dynamic_trampolines();
    let lookup_state = Arc::clone(state);
    registry.register(KERNEL32, "GetProcAddress", move |args, cpu, memory| {
        let modules = lookup.get().expect("module catalog");
        let loaded = {
            let references = modules.references.lock().expect("module references");
            references.is_loaded(memory, args.rcx)
        };
        if !loaded {
            return lookup_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        }
        let export = if let Ok(ordinal) = u16::try_from(args.rdx) {
            ImportName::Ordinal(ordinal)
        } else {
            let Some(symbol) =
                read_name(memory, args.rdx, false).map_err(ExitReason::MemoryFault)?
            else {
                return lookup_state.fail(cpu.gs_base, PROCEDURE_NOT_FOUND, 0);
            };
            ImportName::Name(symbol)
        };
        // The program's own export table is not read. Dynamic guest exports
        // resolve to image addresses; only a chain ending in a built-in service
        // produces a service trampoline.
        match modules.procedure_address(memory, args.rcx, &export, &trampolines) {
            Some(address) => Ok(address),
            None => lookup_state.fail(cpu.gs_base, PROCEDURE_NOT_FOUND, 0),
        }
    });

    // kernel32.dll exports this with a K32 prefix and psapi.dll without.
    for (module, symbol) in [
        (KERNEL32, "K32GetModuleInformation"),
        (PSAPI, "GetModuleInformation"),
    ] {
        let state = Arc::clone(state);
        let modules = catalog(&modules);
        registry.register(module, symbol, move |args, cpu, memory| {
            let modules = modules.get().expect("built-in module catalog");
            let (process, handle, output, size) =
                (args.rcx, args.rdx, args.r8, args.r9 as u32 as usize);
            let fail = |error| state.fail(cpu.gs_base, error, 0);
            if process != CURRENT_PROCESS {
                return fail(ERROR_INVALID_HANDLE);
            }
            let image = memory.main_image.filter(|image| image.base == handle);
            let Some(MainImage {
                base,
                size: image_size,
                entry_point,
            }) = image
            else {
                let references = modules.references.lock().expect("module references");
                // A built-in module has no image to describe.
                return fail(if references.is_loaded(memory, handle) {
                    ERROR_NOT_SUPPORTED
                } else {
                    ERROR_INVALID_HANDLE
                });
            };
            if size < MODULE_INFO_SIZE {
                return fail(ERROR_INSUFFICIENT_BUFFER);
            }
            let mut info = [0; MODULE_INFO_SIZE];
            info[..8].copy_from_slice(&base.to_le_bytes());
            info[8..12].copy_from_slice(&image_size.to_le_bytes());
            info[16..].copy_from_slice(&entry_point.to_le_bytes());
            if memory.write_bytes(output, &info).is_err() {
                return fail(ERROR_NOACCESS);
            }
            Ok(1)
        });
        for api_set in PSAPI_APIS {
            registry.alias(api_set, module, symbol);
        }
        registry.set_status(module, symbol, ServiceStatus::Partial);
    }
    registry.alias(KERNELBASE, KERNEL32, "K32GetModuleInformation");

    for symbol in [
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetModuleHandleExA",
        "GetModuleHandleExW",
        "GetModuleFileNameA",
        "GetModuleFileNameW",
        "GetProcAddress",
        "FreeLibrary",
    ] {
        for module in LOADER_APIS {
            registry.alias(module, KERNEL32, symbol);
        }
        registry.set_status(KERNEL32, symbol, ServiceStatus::Partial);
    }
    for symbol in [
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
    ] {
        for module in LOAD_LIBRARY_APIS {
            registry.alias(module, KERNEL32, symbol);
        }
        // Not on Microsoft's list, but registered here before it was checked.
        registry.alias(LOADER_API, KERNEL32, symbol);
        registry.set_status(KERNEL32, symbol, ServiceStatus::Partial);
    }

    let mut built_in = Modules::default();
    // Preserve the startup UCRT binding.
    let references = built_in.references.get_mut().expect("module references");
    references.counts.insert(UCRT_HANDLE, 1);
    for (module, handle) in [(KERNEL32, MODULE_BASE), (UCRT, UCRT_HANDLE)] {
        built_in.names.insert(module.to_owned(), handle);
        built_in.exports.insert(
            handle,
            registry
                .canonical_exports(module)
                .map(|(key, index)| (key.clone(), index))
                .collect(),
        );
        for (alias, _, canonical) in registry.iter_aliases() {
            if canonical == module {
                built_in.names.insert(alias.to_owned(), handle);
            }
        }
    }
    // A module of its own, not another name for kernel32.
    built_in
        .names
        .insert(KERNELBASE.to_owned(), KERNELBASE_HANDLE);
    built_in.exports.insert(
        KERNELBASE_HANDLE,
        registry
            .aliased_exports(KERNELBASE)
            .map(|(key, index)| (key.clone(), index))
            .collect(),
    );
    assert!(modules.inner.set(built_in).is_ok());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{CpuState, Register};
    use crate::imports::Win64Args;
    use crate::memory::MemoryPermissions;
    use crate::module_graph::{ModuleGraph, PackageModule};
    use crate::services::{MockClock, register_standard_services};

    const OPTIONAL: usize = 0x98;
    const CODE_RVA: u32 = 0x1000;
    const DATA_RVA: u32 = 0x2000;
    const DATA_RAW: usize = 0x400;
    const DATA_LEN: usize = 0x4000;
    const EXPORT_RVA: u32 = DATA_RVA;
    const EXPORT_LEN: u32 = 0x1000;
    const EXPORT_END: u32 = EXPORT_RVA + EXPORT_LEN;
    const EAT_RVA: u32 = EXPORT_RVA + 0x100;
    const NPT_RVA: u32 = EXPORT_RVA + 0x200;
    const EOT_RVA: u32 = EXPORT_RVA + 0x280;
    const EXPORT_STRINGS: u32 = EXPORT_RVA + 0x300;

    enum Target {
        Export,
        Forward(&'static str),
    }

    struct ExportSlot {
        target: Target,
        names: &'static [&'static str],
    }

    struct ExportSpec<'a> {
        module_name: &'static str,
        slots: &'a [ExportSlot],
    }

    const fn slot(target: Target, names: &'static [&'static str]) -> ExportSlot {
        ExportSlot { target, names }
    }

    fn put(pe: &mut [u8], at: usize, bytes: &[u8]) {
        pe[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn put16(pe: &mut [u8], at: usize, value: u16) {
        put(pe, at, &value.to_le_bytes());
    }

    fn put32(pe: &mut [u8], at: usize, value: u32) {
        put(pe, at, &value.to_le_bytes());
    }

    fn data_offset(rva: u32) -> usize {
        DATA_RAW + (rva - DATA_RVA) as usize
    }

    fn put32_rva(pe: &mut [u8], rva: u32, value: u32) {
        put32(pe, data_offset(rva), value);
    }

    fn allocate(cursor: &mut u32, len: usize) -> u32 {
        let start = *cursor;
        let next = start + u32::try_from(len).unwrap();
        *cursor = next.next_multiple_of(8);
        assert!(*cursor <= EXPORT_END);
        start
    }

    fn write_string(pe: &mut [u8], cursor: &mut u32, text: &str) -> u32 {
        let rva = allocate(cursor, text.len() + 1);
        put(pe, data_offset(rva), text.as_bytes());
        rva
    }

    fn write_exports(pe: &mut [u8], exports: &ExportSpec<'_>) {
        put32(pe, OPTIONAL + 112, EXPORT_RVA);
        put32(pe, OPTIONAL + 116, EXPORT_LEN);
        let mut cursor = EXPORT_STRINGS;
        let module = write_string(pe, &mut cursor, exports.module_name);
        let mut named = Vec::new();
        for (index, export_slot) in exports.slots.iter().enumerate() {
            for name in export_slot.names {
                named.push((*name, index));
            }
        }
        named.sort();
        for (position, (name, index)) in named.iter().enumerate() {
            let name_rva = write_string(pe, &mut cursor, name);
            put32_rva(pe, NPT_RVA + 4 * position as u32, name_rva);
            put16(
                pe,
                data_offset(EOT_RVA) + 2 * position,
                u16::try_from(*index).unwrap(),
            );
        }
        for (index, export_slot) in exports.slots.iter().enumerate() {
            let value = match export_slot.target {
                Target::Export => CODE_RVA + 4 * index as u32,
                Target::Forward(text) => write_string(pe, &mut cursor, text),
            };
            put32_rva(pe, EAT_RVA + 4 * index as u32, value);
        }
        let name_count = named.len() as u32;
        put32_rva(pe, EXPORT_RVA + 12, module);
        put32_rva(pe, EXPORT_RVA + 16, 1);
        put32_rva(pe, EXPORT_RVA + 20, exports.slots.len() as u32);
        put32_rva(pe, EXPORT_RVA + 24, name_count);
        put32_rva(pe, EXPORT_RVA + 28, EAT_RVA);
        put32_rva(pe, EXPORT_RVA + 32, NPT_RVA);
        put32_rva(pe, EXPORT_RVA + 36, EOT_RVA);
    }

    /// Build an original byte-built synthetic PE32+ DLL fixture. It is only
    /// export inventory input for this test; no fixture code is executed.
    fn build_exports_image(exports: &ExportSpec<'_>) -> Vec<u8> {
        let mut pe = vec![0; DATA_RAW + DATA_LEN];
        put(&mut pe, 0, b"MZ");
        put32(&mut pe, 0x3c, 0x80);
        put(&mut pe, 0x80, b"PE\0\0");
        put16(&mut pe, 0x84, 0x8664);
        put16(&mut pe, 0x86, 2);
        put16(&mut pe, 0x94, 240);
        put16(&mut pe, 0x96, 0x2000);
        put16(&mut pe, OPTIONAL, 0x20b);
        put32(&mut pe, OPTIONAL + 32, 0x1000);
        put32(&mut pe, OPTIONAL + 36, 0x200);
        put32(&mut pe, OPTIONAL + 56, DATA_RVA + DATA_LEN as u32);
        put32(&mut pe, OPTIONAL + 60, 0x200);
        put32(&mut pe, OPTIONAL + 108, 16);
        for (index, (name, rva, raw, len, flags)) in [
            (b".text", CODE_RVA, 0x200usize, 0x200usize, 0x6000_0020u32),
            (b".data", DATA_RVA, DATA_RAW, DATA_LEN, 0xc000_0040u32),
        ]
        .into_iter()
        .enumerate()
        {
            let section = OPTIONAL + 240 + 40 * index;
            put(&mut pe, section, name);
            put32(&mut pe, section + 8, len as u32);
            put32(&mut pe, section + 12, rva);
            put32(&mut pe, section + 16, len as u32);
            put32(&mut pe, section + 20, raw as u32);
            put32(&mut pe, section + 36, flags);
        }
        write_exports(&mut pe, exports);
        pe
    }

    fn parsed_exports(file_name: &str, bytes: &[u8]) -> ExportTable {
        let package = [PackageModule { file_name, bytes }];
        let graph = ModuleGraph::build(&package).unwrap();
        assert!(graph.inspection_is_complete());
        graph.modules()[0].exports.clone().unwrap()
    }

    fn call_service(
        registry: &ImportRegistry,
        memory: &mut GuestMemory,
        symbol: &str,
        rcx: u64,
        rdx: u64,
        r8: u64,
    ) -> u64 {
        let mut cpu = CpuState::default();
        cpu.set(Register::Rcx, rcx);
        cpu.set(Register::Rdx, rdx);
        cpu.set(Register::R8, r8);
        let service = registry
            .resolve(LOADER_API, &ImportName::Name(symbol.to_owned()))
            .unwrap();
        (service.handler)(&Win64Args::new(&cpu), &mut cpu, memory).unwrap()
    }

    #[test]
    fn registered_guest_modules_use_image_handles_and_exports() {
        const PROVIDER_BASE: u64 = 0x1_8000_0000;
        const FORWARDER_BASE: u64 = 0x1_8001_0000;
        const IMAGE_SIZE: u32 = 0x6000;

        let provider_slots = [slot(Target::Export, &["Value"]), slot(Target::Export, &[])];
        let provider_spec = ExportSpec {
            module_name: "Provider.dll",
            slots: &provider_slots,
        };
        let provider_image = build_exports_image(&provider_spec);
        let provider_exports = parsed_exports("Provider.dll", &provider_image);

        let forwarder_slots = [
            slot(Target::Forward("provider.Value"), &["ForwardedValue"]),
            slot(
                Target::Forward("kernel32.GetLastError"),
                &["ForwardedService"],
            ),
            slot(
                Target::Forward("forwarder.ForwardedValue"),
                &["ChainedValue"],
            ),
            slot(Target::Forward("provider.#2"), &["ForwardedOrdinal"]),
        ];
        let forwarder_spec = ExportSpec {
            module_name: "Forwarder.dll",
            slots: &forwarder_slots,
        };
        let forwarder_image = build_exports_image(&forwarder_spec);
        let forwarder_exports = parsed_exports("Forwarder.dll", &forwarder_image);

        let mut registry = ImportRegistry::new();
        let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
        register_standard_services(&mut registry, Arc::clone(&state));
        assert_eq!(
            register_dynamic_module(
                &registry,
                DynamicModuleRegistration {
                    name: "Provider.dll".to_owned(),
                    base: PROVIDER_BASE,
                    size: IMAGE_SIZE,
                    exports: Some(provider_exports),
                },
            )
            .unwrap(),
            PROVIDER_BASE
        );
        assert_eq!(
            register_dynamic_module(
                &registry,
                DynamicModuleRegistration {
                    name: "Forwarder.dll".to_owned(),
                    base: FORWARDER_BASE,
                    size: IMAGE_SIZE,
                    exports: Some(forwarder_exports),
                },
            )
            .unwrap(),
            FORWARDER_BASE
        );

        let mut memory = GuestMemory::new();
        memory
            .map_region(0x30000, 0x10000, MemoryPermissions::READ_WRITE)
            .unwrap();
        memory.write_bytes(0x30000, b"pRoViDeR\0").unwrap();
        memory.write_bytes(0x30040, b"Value\0").unwrap();
        memory.write_bytes(0x30080, b"ForwardedValue\0").unwrap();
        memory.write_bytes(0x300c0, b"ForwardedService\0").unwrap();
        memory.write_bytes(0x30100, b"ChainedValue\0").unwrap();
        memory.write_bytes(0x30120, b"ForwardedOrdinal\0").unwrap();
        memory.write_bytes(0x30140, b"kernel32\0").unwrap();
        memory.write_bytes(0x30180, b"GetLastError\0").unwrap();
        memory.write_bytes(0x30200, b"Provider.\0").unwrap();
        memory.write_bytes(0x30240, b"value\0").unwrap();

        let provider = call_service(&registry, &mut memory, "GetModuleHandleA", 0x30000, 0, 0);
        assert_eq!(provider, PROVIDER_BASE);
        // A trailing dot means exactly that extensionless name; it does not
        // become another spelling of Provider.dll.
        assert_eq!(
            call_service(&registry, &mut memory, "GetModuleHandleA", 0x30200, 0, 0),
            0
        );
        let forwarder = FORWARDER_BASE;

        // FROM_ADDRESS uses the registered image range, not just the base.
        let output = 0x30800;
        assert_eq!(
            call_service(
                &registry,
                &mut memory,
                "GetModuleHandleExA",
                u64::from(FROM_ADDRESS | UNCHANGED_REFCOUNT),
                PROVIDER_BASE + 0x1000,
                output,
            ),
            1
        );
        assert_eq!(memory.read_u64(output).unwrap(), PROVIDER_BASE);
        assert_eq!(
            call_service(
                &registry,
                &mut memory,
                "GetModuleHandleExA",
                u64::from(FROM_ADDRESS | UNCHANGED_REFCOUNT),
                PROVIDER_BASE + u64::from(IMAGE_SIZE),
                output,
            ),
            0
        );
        assert_eq!(memory.read_u64(output).unwrap(), 0);

        // Direct guest exports return image addresses, never service trampolines.
        let direct = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            provider,
            0x30040,
            0,
        );
        assert_eq!(direct, PROVIDER_BASE + u64::from(CODE_RVA));
        assert!(!registry.is_service_trampoline(direct));
        assert_eq!(
            call_service(
                &registry,
                &mut memory,
                "GetProcAddress",
                provider,
                0x30240,
                0
            ),
            0
        );
        let ordinal = call_service(&registry, &mut memory, "GetProcAddress", provider, 2, 0);
        assert_eq!(ordinal, PROVIDER_BASE + u64::from(CODE_RVA + 4));
        assert!(!registry.is_service_trampoline(ordinal));

        // Forwarders may terminate in another guest module, including through
        // a bounded guest-to-guest chain.
        let forwarded = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            forwarder,
            0x30080,
            0,
        );
        assert_eq!(forwarded, direct);
        let chained = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            forwarder,
            0x30100,
            0,
        );
        assert_eq!(chained, direct);
        let forwarded_ordinal = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            forwarder,
            0x30120,
            0,
        );
        assert_eq!(forwarded_ordinal, ordinal);

        // A forwarder that terminates in kernel32 uses the captured built-in
        // export map and exposes the service trampoline instead.
        let service = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            forwarder,
            0x300c0,
            0,
        );
        assert!(registry.is_service_trampoline(service));
        let kernel32 = call_service(&registry, &mut memory, "GetModuleHandleA", 0x30140, 0, 0);
        let direct_service = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            kernel32,
            0x30180,
            0,
        );
        assert_eq!(service, direct_service);

        // A dynamic module file name is its closed-world logical name, not a
        // host path. The original ASCII casing is preserved in the answer.
        let length = call_service(
            &registry,
            &mut memory,
            "GetModuleFileNameA",
            provider,
            0x30900,
            64,
        );
        assert_eq!(length, 12);
        let mut name = [0; 13];
        memory.read_bytes(0x30900, &mut name).unwrap();
        assert_eq!(&name[..12], b"Provider.dll");
        assert_eq!(name[12], 0);

        // Xenora has no unloading yet: freeing the loader-owned reference does
        // not make the pinned process-resident image disappear.
        assert_eq!(
            call_service(&registry, &mut memory, "FreeLibrary", provider, 0, 0),
            1
        );
        assert_eq!(
            call_service(&registry, &mut memory, "GetModuleHandleA", 0x30000, 0, 0),
            PROVIDER_BASE
        );
        assert_eq!(
            call_service(&registry, &mut memory, "FreeLibrary", provider, 0, 0),
            0
        );
    }

    #[test]
    fn dynamic_registration_rejects_collisions_and_out_of_image_exports() {
        const BASE: u64 = 0x1_8004_0000;
        const IMAGE_SIZE: u32 = 0x6000;
        let slots = [slot(Target::Export, &["Value"])];
        let spec = ExportSpec {
            module_name: "provider.dll",
            slots: &slots,
        };
        let image = build_exports_image(&spec);
        let exports = parsed_exports("provider.dll", &image);
        let mut registry = ImportRegistry::new();
        let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
        register_standard_services(&mut registry, Arc::clone(&state));
        let registration = |name: &str, base, exports| DynamicModuleRegistration {
            name: name.to_owned(),
            base,
            size: IMAGE_SIZE,
            exports,
        };
        register_dynamic_module(
            &registry,
            registration("provider.dll", BASE, Some(exports.clone())),
        )
        .unwrap();
        assert!(matches!(
            register_dynamic_module(
                &registry,
                registration("PROVIDER.dll", BASE + 0x10000, Some(exports.clone())),
            ),
            Err(DynamicModuleRegistrationError::NameCollision { .. })
        ));
        assert!(matches!(
            register_dynamic_module(
                &registry,
                registration("overlap.dll", BASE + 0x1000, Some(exports.clone())),
            ),
            Err(DynamicModuleRegistrationError::BaseCollision { .. })
        ));
        assert!(matches!(
            register_dynamic_module(
                &registry,
                registration("bad\\path.dll", BASE + 0x20000, Some(exports.clone())),
            ),
            Err(DynamicModuleRegistrationError::InvalidName { .. })
        ));

        let mut outside = exports;
        outside.entries[0].target = ExportTarget::ExportRva(IMAGE_SIZE);
        assert!(matches!(
            register_dynamic_module(
                &registry,
                registration("outside.dll", BASE + 0x20000, Some(outside)),
            ),
            Err(DynamicModuleRegistrationError::ExportOutsideImage { .. })
        ));
    }

    #[test]
    fn dynamic_forwarders_stop_at_the_eight_hop_bound() {
        const PROVIDER_BASE: u64 = 0x1_8002_0000;
        const CHAIN_BASE: u64 = 0x1_8003_0000;
        const IMAGE_SIZE: u32 = 0x6000;

        let provider_slots = [slot(Target::Export, &["Value"])];
        let provider_spec = ExportSpec {
            module_name: "provider.dll",
            slots: &provider_slots,
        };
        let provider_image = build_exports_image(&provider_spec);
        let provider_exports = parsed_exports("provider.dll", &provider_image);

        let chain_slots = [
            slot(Target::Forward("provider.Value"), &["Hop0"]),
            slot(Target::Forward("chain.Hop0"), &["Hop1"]),
            slot(Target::Forward("chain.Hop1"), &["Hop2"]),
            slot(Target::Forward("chain.Hop2"), &["Hop3"]),
            slot(Target::Forward("chain.Hop3"), &["Hop4"]),
            slot(Target::Forward("chain.Hop4"), &["Hop5"]),
            slot(Target::Forward("chain.Hop5"), &["Hop6"]),
            slot(Target::Forward("chain.Hop6"), &["Hop7"]),
            slot(Target::Forward("chain.Hop7"), &["Hop8"]),
        ];
        let chain_spec = ExportSpec {
            module_name: "chain.dll",
            slots: &chain_slots,
        };
        let chain_image = build_exports_image(&chain_spec);
        let chain_exports = parsed_exports("chain.dll", &chain_image);

        let mut registry = ImportRegistry::new();
        let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
        register_standard_services(&mut registry, Arc::clone(&state));
        for (name, base, exports) in [
            ("provider.dll", PROVIDER_BASE, provider_exports),
            ("chain.dll", CHAIN_BASE, chain_exports),
        ] {
            register_dynamic_module(
                &registry,
                DynamicModuleRegistration {
                    name: name.to_owned(),
                    base,
                    size: IMAGE_SIZE,
                    exports: Some(exports),
                },
            )
            .unwrap();
        }

        let mut memory = GuestMemory::new();
        memory
            .map_region(0x30000, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        memory.write_bytes(0x30000, b"Hop7\0").unwrap();
        memory.write_bytes(0x30020, b"Hop8\0").unwrap();
        let within_bound = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            CHAIN_BASE,
            0x30000,
            0,
        );
        assert_eq!(within_bound, PROVIDER_BASE + u64::from(CODE_RVA));
        let beyond_bound = call_service(
            &registry,
            &mut memory,
            "GetProcAddress",
            CHAIN_BASE,
            0x30020,
            0,
        );
        assert_eq!(beyond_bound, 0);
    }

    #[test]
    fn guest_module_references_control_dynamic_export_lifetime() {
        let mut registry = ImportRegistry::new();
        registry.register(UCRT, "SyntheticOrdinalExport", |_, _, _| Ok(42));
        registry
            .try_ordinal_alias(UCRT, "SyntheticOrdinalExport", 42)
            .unwrap();
        registry.register(UCRT, "OtherSyntheticExport", |_, _, _| Ok(43));
        assert!(
            registry
                .try_ordinal_alias(UCRT, "OtherSyntheticExport", 42)
                .is_err()
        );
        register_standard_services(
            &mut registry,
            Arc::new(ServicesState::new(Arc::new(MockClock::new(0)))),
        );
        let mut memory = GuestMemory::new();
        memory
            .map_region(0x10000, 4096, MemoryPermissions::READ_WRITE)
            .unwrap();
        memory.write_bytes(0x10000, b"UCRTBASE\0").unwrap();
        memory.write_bytes(0x10100, b"sqrt\0").unwrap();
        memory.write_bytes(0x10200, b"/unknown.dll\0").unwrap();
        memory.write_bytes(0x10300, b"Ordinal#42\0").unwrap();
        let mut call = |symbol: &str, first, second| {
            let mut cpu = CpuState::default();
            cpu.set(Register::Rcx, first);
            cpu.set(Register::Rdx, second);
            let service = registry
                .resolve(LOADER_API, &ImportName::Name(symbol.to_owned()))
                .unwrap();
            (service.handler)(&Win64Args::new(&cpu), &mut cpu, &mut memory).unwrap()
        };
        assert_eq!(call("LoadLibraryA", 0x10200, 0), 0);
        let handle = call("GetModuleHandleA", 0x10000, 0);
        assert_ne!(handle, 0);
        assert_eq!(call("LoadLibraryA", 0x10000, 0), handle);
        let export = call("GetProcAddress", handle, 0x10100);
        let ordinal = call("GetProcAddress", handle, 42);
        assert!(registry.is_service_trampoline(ordinal));
        assert_ne!(ordinal, export);
        assert_eq!(call("GetProcAddress", handle, 43), 0);
        assert_eq!(call("GetProcAddress", handle, 0x10300), 0);
        assert!(registry.is_service_trampoline(export));
        assert_eq!(call("FreeLibrary", handle, 0), 1);
        assert!(registry.is_service_trampoline(export));
        assert_eq!(call("FreeLibrary", handle, 0), 1);
        assert!(!registry.is_service_trampoline(export));
        assert!(!registry.is_service_trampoline(ordinal));
        assert_eq!(call("GetModuleHandleA", 0x10000, 0), 0);
        assert_eq!(call("GetProcAddress", handle, 0x10100), 0);
        assert_eq!(call("FreeLibrary", handle, 0), 0);
        assert_eq!(call("LoadLibraryA", 0x10000, 0), handle);
        assert_ne!(call("GetProcAddress", handle, 0x10100), 0);
        let ordinal = call("GetProcAddress", handle, 42);
        let mut cpu = CpuState::new(ordinal, 0x10400);
        memory.write_u64(0x10400, 0x1234).unwrap();
        registry.dispatch(ordinal, &mut cpu, &mut memory).unwrap();
        assert_eq!(cpu.get(Register::Rax), 42);
        assert_eq!(cpu.rip, 0x1234);
    }

    #[test]
    fn the_module_file_name_answers_the_program_path_with_truncation() {
        let mut registry = ImportRegistry::new();
        let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
        state
            .set_program_arguments(&["c:\\games\\probe.exe"])
            .unwrap();
        register_standard_services(&mut registry, state);
        let mut memory = GuestMemory::new();
        memory
            .map_region(0x20000, 4096, MemoryPermissions::READ_WRITE)
            .unwrap();
        memory.main_image = Some(MainImage {
            base: 0x150000000,
            size: 0x1000,
            entry_point: 0x150001000,
        });
        let narrow_length;
        let wide_length;
        let truncated_length;
        let foreign;
        {
            let memory = &mut memory;
            let mut call = |symbol: &str, module, buffer, capacity| {
                let mut cpu = CpuState::default();
                cpu.set(Register::Rcx, module);
                cpu.set(Register::Rdx, buffer);
                cpu.set(Register::R8, capacity);
                let service = registry
                    .resolve(LOADER_API, &ImportName::Name(symbol.to_owned()))
                    .unwrap();
                (service.handler)(&Win64Args::new(&cpu), &mut cpu, memory).unwrap()
            };
            narrow_length = call("GetModuleFileNameA", 0, 0x20000, 64);
            wide_length = call("GetModuleFileNameW", 0x150000000, 0x20100, 64);
            truncated_length = call("GetModuleFileNameA", 0, 0x20200, 8);
            foreign = call("GetModuleFileNameA", 0xdead0000, 0x20000, 64);
        }
        // The narrow form copies the whole path and answers its length.
        let length = narrow_length;
        assert_eq!(length, 18);
        let mut bytes = [0u8; 20];
        memory.read_bytes(0x20000, &mut bytes).unwrap();
        assert_eq!(&bytes[..18], b"c:\\games\\probe.exe");
        assert_eq!(bytes[18], 0);
        // The wide form counts wide units; the main-image handle is the
        // module itself.
        assert_eq!(wide_length, 18);
        assert_eq!(memory.read_u16(0x20100).unwrap(), u16::from(b'c'));
        // A small buffer truncates, terminates and answers the capacity
        // with ERROR_INSUFFICIENT_BUFFER - the documented truncation form.
        assert_eq!(truncated_length, 8);
        let mut small = [0u8; 8];
        memory.read_bytes(0x20200, &mut small).unwrap();
        assert_eq!(&small[..7], b"c:\\game");
        assert_eq!(small[7], 0);
        // A foreign module does not exist here.
        assert_eq!(foreign, 0);
    }
}
