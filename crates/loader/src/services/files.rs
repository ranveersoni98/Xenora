// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded synthetic C: drive with no host filesystem mapping.

use super::crt_files::{EEXIST, ENOENT, ENOSPC};
use super::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_LOCK_VIOLATION,
    ERROR_NOACCESS, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_LOCKED, ERROR_NOT_SUPPORTED, GuestObject,
    KERNEL32, ServicesState, crt::UCRT,
};
use crate::cpu::ExitReason;
use crate::imports::{ImportRegistry, ServiceStatus};
use crate::memory::{GuestMemory, MemoryError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const FILE_API: &str = "api-ms-win-core-file-l1-1-0.dll";
const CRT_FILESYSTEM_API: &str = "api-ms-win-crt-filesystem-l1-1-0.dll";
const INVALID_HANDLE: u64 = u64::MAX;
const READ: u32 = 0x8000_0000;
const WRITE: u32 = 0x4000_0000;
/// FILE_WRITE_ATTRIBUTES, the one granular right the simplified access
/// model accepts beside the generic pair: opening with it writes times and
/// nothing else, as Windows orders the rights.
const WRITE_ATTRIBUTES: u32 = 0x100;
const FILE_NOT_FOUND: u32 = 2;
const PATH_NOT_FOUND: u32 = 3;
const DIRECTORY_NOT_EMPTY: u32 = 145;
const FILE_EXISTS: u32 = 80;
const ALREADY_EXISTS: u32 = 183;
const INVALID_NAME: u32 = 123;
const NEGATIVE_SEEK: u32 = 131;
const SHARING_VIOLATION: u32 = 32;
const DISK_FULL: u32 = 112;
const MAX_FILES: usize = 256;
const MAX_DIRECTORIES: usize = 256;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_TRANSFER: usize = 1024 * 1024;

#[derive(Clone)]
pub(super) struct OpenFile {
    pub(super) path: String,
    // The object table serializes all operations on this open instance.
    position: Arc<AtomicU64>,
    open_access: u32,
    pub(super) access: u32,
    share: u32,
    // A directory opens only through the backup-semantics flag and supports
    // no read or write: the handle exists so callers can prove the entry is
    // a directory and close it again, which is all the win32 opendir chain
    // of a real binary needs before it enumerates by path.
    pub(super) directory: bool,
}

impl OpenFile {
    /// The CRT interop synthesizes the kernel file object every real CRT
    /// descriptor has behind it, for a stream that was opened through the
    /// CRT alone (#1312): the object's position starts where the stream's
    /// is now, and the two move independently afterward exactly as a real
    /// CRT stream's buffered position and its kernel handle do.
    pub(super) fn for_interop(path: String, access: u32, position: u64) -> Self {
        OpenFile {
            path,
            position: Arc::new(AtomicU64::new(position)),
            open_access: access,
            access,
            share: 0,
            directory: false,
        }
    }

    /// The CRT interop reads and writes the object through these, under the
    /// same serialization the object table gives the kernel calls.
    pub(super) fn path(&self) -> &str {
        &self.path
    }

    pub(super) fn position(&self) -> &Arc<AtomicU64> {
        &self.position
    }
}

fn read_guest_path(memory: &GuestMemory, address: u64) -> Result<Option<String>, MemoryError> {
    if address == 0 {
        return Ok(None);
    }
    let mut units = Vec::new();
    for index in 0..260 {
        let slot = address
            .checked_add(index * 2)
            .ok_or(MemoryError::Overflow)?;
        let unit = memory.read_u16(slot)?;
        if unit == 0 {
            let Ok(path) = String::from_utf16(&units) else {
                return Ok(None);
            };
            // The empty string is no path at all: every operation on it
            // fails as invalid. Dot components stay untouched here - the
            // consumers resolve them at the point the path becomes
            // root-anchored, because a relative `..` must first join the
            // working directory before it knows what it climbs.
            if path.is_empty() {
                return Ok(None);
            }
            let path = path.replace('/', "\\").to_ascii_lowercase();
            // A drive-rooted `c:\foo` is an absolute path: it anchors at
            // the volume root exactly as a leading separator does, so it
            // keeps its anchor rather than collapsing into the relative
            // `foo` - which would resolve against the working directory and
            // stop resolving the moment the process leaves its start
            // directory (#1342).
            let name = match path.strip_prefix("c:\\") {
                Some(rest) => format!("\\{rest}"),
                None => path,
            };
            return Ok(Some(name));
        }
        units.push(unit);
    }
    Ok(None)
}

// The object keys of the drive are relative to its root, so a leading
// separator - which anchors the path at the drive root on Windows - is
// consumed rather than validated as a component: the anchor itself names no
// component. Exactly one separator is consumed. A second would be the UNC
// prefix this model cannot express, and stays invalid through the empty
// leading component it leaves behind; so does the bare root, which no
// object operation names. Consumers that resolve paths lexically against
// the working directory read the raw form instead, because the anchor is
// load-bearing there.
fn strip_root_anchor(name: &str) -> &str {
    name.strip_prefix('\\').unwrap_or(name)
}

/// The NUL device, as DOS device names resolve: the final component's base
/// name - before any extension - is `nul`, in any directory position. The
/// device needs no directory behind it, and nothing traverses into it: a
/// component after the device name cannot resolve. The paths the drive
/// compares here are already lowercase.
pub(super) fn is_nul_path(path: &str) -> bool {
    let final_component = path.rsplit('\\').next().unwrap_or_default();
    final_component.split('.').next().unwrap_or_default() == "nul"
}

/// The lexical resolution the path rules document: `.` is the directory the
/// path is already in and drops, `..` is its parent and pops one component,
/// and a `..` at the root stays at the root because there is nothing to pop.
/// The resolution is purely lexical - `a\..\b` is exactly `b` whether or
/// not `a` ever existed - and it runs ahead of validation, so the dot
/// components are never file names at all while a real name ending with a
/// dot stays rejected exactly as before.
fn resolve_dots(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('\\') {
        match component {
            "." => {}
            ".." => {
                // The leading empty component of an anchored path is no real
                // component: the root cannot be climbed past, so it stays.
                if components.last().is_some_and(|last| !last.is_empty()) {
                    components.pop();
                }
            }
            _ => components.push(component),
        }
    }
    components.join("\\")
}

fn valid_key(name: &str) -> bool {
    // The empty key is the root: a path of dot components resolves to it.
    if name.is_empty() {
        return true;
    }
    if is_nul_path(name) {
        // The device resolves in any directory position; the components
        // before its name still have to be valid ones, and a trailing
        // component after the device name makes the path no device path at
        // all - it is rejected as a component, exactly as before.
        let directory = parent(name);
        return directory.is_empty() || directory.split('\\').all(valid_component);
    }
    name.split('\\').all(valid_component)
}

/// The bare drive key a guest path names, resolved as the drive resolves
/// every path: separators of either kind fold, dot segments resolve against
/// the process working directory, the drive prefix drops, and the empty key
/// is the volume root. `None` when any component is not a name the drive
/// accepts.
fn resolve_bare_path(state: &ServicesState, name: &str) -> Option<String> {
    let cwd = state.crt_streams().working_directory();
    // A drive prefix (`c:`) anchors at the volume; what remains resolves
    // against the working directory, dot segments included.
    let stripped = name.replace('/', "\\");
    let body = stripped.strip_prefix("c:").unwrap_or(&stripped);
    let resolved = super::crt::resolve_directory(&cwd, body);
    if resolved
        .split('\\')
        .all(|part| part.is_empty() || valid_component(part))
    {
        Some(resolved)
    } else {
        None
    }
}

fn guest_path(memory: &GuestMemory, address: u64) -> Result<Option<String>, MemoryError> {
    Ok(read_guest_path(memory, address)?
        .map(|name| resolve_dots(strip_root_anchor(&name)))
        .filter(|name| valid_key(name)))
}

/// The narrow form of `read_guest_path`: the process code page is UTF-8, so
/// the bytes are UTF-8 and no code page conversion applies. Invalid UTF-8
/// is no path, like an invalid wide string.
fn read_guest_path_a(memory: &GuestMemory, address: u64) -> Result<Option<String>, MemoryError> {
    if address == 0 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    for index in 0..260u64 {
        let slot = address.checked_add(index).ok_or(MemoryError::Overflow)?;
        let byte = memory.read_u8(slot)?;
        if byte == 0 {
            let Ok(path) = String::from_utf8(bytes) else {
                return Ok(None);
            };
            if path.is_empty() {
                return Ok(None);
            }
            let path = path.replace('/', "\\").to_ascii_lowercase();
            // A drive-rooted `c:\foo` is an absolute path: it anchors at
            // the volume root exactly as a leading separator does, so it
            // keeps its anchor rather than collapsing into the relative
            // `foo` - which would resolve against the working directory and
            // stop resolving the moment the process leaves its start
            // directory (#1342).
            let name = match path.strip_prefix("c:\\") {
                Some(rest) => format!("\\{rest}"),
                None => path,
            };
            return Ok(Some(name));
        }
        bytes.push(byte);
    }
    Ok(None)
}

fn guest_path_a(memory: &GuestMemory, address: u64) -> Result<Option<String>, MemoryError> {
    Ok(read_guest_path_a(memory, address)?
        .map(|name| resolve_dots(strip_root_anchor(&name)))
        .filter(|name| valid_key(name)))
}

// The operations the wide and narrow forms share. Each answers the error
// code it fails with, and the closures translate it through `fail`.

fn create_directory(objects: &mut super::ObjectState, path: &str) -> Result<(), u32> {
    let parent = parent(path);
    if !parent.is_empty() && !objects.directories.contains(parent) {
        return Err(PATH_NOT_FOUND);
    }
    if objects.directories.contains(path) || objects.files.contains_key(path) {
        return Err(ALREADY_EXISTS);
    }
    if objects.directories.len() >= MAX_DIRECTORIES {
        return Err(DISK_FULL);
    }
    objects.directories.insert(path.to_owned());
    Ok(())
}

fn remove_directory(objects: &mut super::ObjectState, path: &str) -> Result<(), u32> {
    if !objects.directories.contains(path) {
        return Err(PATH_NOT_FOUND);
    }
    if objects.directories.iter().any(|key| parent(key) == path)
        || objects.files.keys().any(|key| parent(key) == path)
    {
        return Err(DIRECTORY_NOT_EMPTY);
    }
    objects.directories.remove(path);
    Ok(())
}

fn move_file(objects: &mut super::ObjectState, source: &str, target: &str) -> Result<(), u32> {
    if [parent(source), parent(target)]
        .into_iter()
        .any(|path| !path.is_empty() && !objects.directories.contains(path))
    {
        return Err(PATH_NOT_FOUND);
    }
    if objects.directories.contains(source) {
        return Err(ERROR_NOT_SUPPORTED);
    }
    if !objects.files.contains_key(source) {
        return Err(FILE_NOT_FOUND);
    }
    if objects.files.contains_key(target) || objects.directories.contains(target) {
        return Err(ALREADY_EXISTS);
    }
    if objects
        .handles
        .values()
        .any(|object| matches!(object, GuestObject::File(file) if file.path == source))
    {
        return Err(SHARING_VIOLATION);
    }
    let data = objects.files.remove(source).expect("source file exists");
    objects.files.insert(target.to_owned(), data);
    Ok(())
}

/// Copies a file inside the drive: `CopyFile` of either width. Windows
/// refuses a copy onto itself with a sharing violation, and the copy of an
/// open file shares the content the opener sees.
fn copy_file(
    objects: &mut super::ObjectState,
    source: &str,
    target: &str,
    fail_if_exists: bool,
) -> Result<(), u32> {
    if source == target {
        return Err(SHARING_VIOLATION);
    }
    if [parent(source), parent(target)]
        .into_iter()
        .any(|path| !path.is_empty() && !objects.directories.contains(path))
    {
        return Err(PATH_NOT_FOUND);
    }
    if objects.directories.contains(source) || objects.directories.contains(target) {
        return Err(ERROR_ACCESS_DENIED);
    }
    let Some(data) = objects.files.get(source).cloned() else {
        return Err(FILE_NOT_FOUND);
    };
    if fail_if_exists && objects.files.contains_key(target) {
        return Err(FILE_EXISTS);
    }
    objects.files.insert(target.to_owned(), data);
    Ok(())
}

struct SearchEntry {
    name: String,
    attributes: u32,
    size: u64,
    times: [u64; 3],
}

pub(super) struct Search {
    entries: Vec<SearchEntry>,
    next: usize,
}

fn write_find_data(
    memory: &mut GuestMemory,
    output: u64,
    entry: &SearchEntry,
) -> Result<(), MemoryError> {
    if output == 0 {
        return Err(MemoryError::UnmappedAddress(0));
    }
    // WIN32_FIND_DATAW: attributes, three FILETIMEs, size high/low,
    // two reserved DWORDs, WCHAR[260], then WCHAR[14].
    // The three FILETIMEs are the times the drive tracks for the entry, or
    // the fixed Unix epoch for one it does not know - a valid time every
    // conversion accepts.
    let mut bytes = [0u8; 592];
    bytes[..4].copy_from_slice(&entry.attributes.to_le_bytes());
    for (slot, offset) in [8usize, 16, 24].into_iter().enumerate() {
        bytes[offset..offset + 8].copy_from_slice(&entry.times[slot].to_le_bytes());
    }
    bytes[28..32].copy_from_slice(&((entry.size >> 32) as u32).to_le_bytes());
    bytes[32..36].copy_from_slice(&(entry.size as u32).to_le_bytes());
    for (slot, unit) in bytes[44..564]
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(entry.name.encode_utf16())
    {
        slot.copy_from_slice(&unit.to_le_bytes());
    }
    memory.write_bytes(output, &bytes)
}

/// The narrow find data: the same layout, the name in the UTF-8 process
/// code page. A name that does not fit in 260 bytes ends the search entry
/// truncated, as the fixed-size field requires.
fn write_find_data_a(
    memory: &mut GuestMemory,
    output: u64,
    entry: &SearchEntry,
) -> Result<(), MemoryError> {
    if output == 0 {
        return Err(MemoryError::UnmappedAddress(0));
    }
    // WIN32_FIND_DATAA is 318 bytes: the 44-byte head, CHAR[260],
    // CHAR[14]. Writing the wide 592 bytes here would smash the caller's
    // stack - the fixture caught exactly that.
    let mut bytes = [0u8; 318];
    bytes[..4].copy_from_slice(&entry.attributes.to_le_bytes());
    bytes[28..32].copy_from_slice(&((entry.size >> 32) as u32).to_le_bytes());
    bytes[32..36].copy_from_slice(&(entry.size as u32).to_le_bytes());
    let name = entry.name.as_bytes();
    let length = name.len().min(259);
    bytes[44..44 + length].copy_from_slice(&name[..length]);
    memory.write_bytes(output, &bytes)
}

fn wildcard_match(pattern: &str, name: &str) -> bool {
    let pattern: Vec<_> = pattern.encode_utf16().collect();
    let name: Vec<_> = name.encode_utf16().collect();
    let (mut p, mut n, mut retry) = (0, 0, None);
    while n < name.len() {
        match pattern.get(p).copied() {
            Some(42) => {
                p += 1;
                retry = Some((p, n));
            }
            Some(unit) if unit == 63 || unit == name[n] => {
                p += 1;
                n += 1;
            }
            _ => {
                let Some((after_star, previous)) = retry else {
                    return false;
                };
                n = previous + 1;
                p = after_star;
                retry = Some((p, n));
            }
        }
    }
    pattern[p..].iter().all(|&unit| unit == 42)
}

fn valid_component(name: &str) -> bool {
    let device = name.split('.').next().unwrap_or_default();
    !name.is_empty()
        && !name.ends_with([' ', '.'])
        && !name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
        && !matches!(device, "con" | "prn" | "aux" | "nul")
        && !(device.len() == 4
            && (device.starts_with("com") || device.starts_with("lpt"))
            && device.as_bytes()[3].is_ascii_digit())
}

/// The fixed Unix epoch in Windows FILETIME form for a file whose times the
/// drive does not know: creation, access and write slots in one value.
const EPOCH_FILETIME3: [u64; 3] = [116_444_736_000_000_000; 3];

fn parent(path: &str) -> &str {
    path.rsplit_once('\\').map_or("", |(parent, _)| parent)
}

fn share_mask(access: u32) -> u32 {
    u32::from(access & READ != 0) | (u32::from(access & WRITE != 0) << 1)
}

/// `FindFirstFile` of either width: the search snapshot is the directory's
/// matching entries sorted by name, and the first answer is written before
/// the handle exists, as the contract requires.
fn find_first(
    state: &ServicesState,
    memory: &mut GuestMemory,
    path: &str,
    output: u64,
    write: fn(&mut GuestMemory, u64, &SearchEntry) -> Result<(), MemoryError>,
    search_op: u32,
) -> Result<u64, u32> {
    // The search root resolves exactly as opening a file does: separators of
    // either kind fold, and a relative portion hangs under the process
    // working directory. Only the trailing component is the wildcard
    // pattern, so a search of `./*` enumerates the working directory as
    // Windows does.
    let folded = path.replace('/', "\\");
    let (root, pattern) = match folded.rsplit_once('\\') {
        Some((root, pattern)) => (root, pattern),
        None => ("", folded.as_str()),
    };
    if pattern.is_empty() || !valid_component(&pattern.replace(['*', '?'], "x")) {
        return Err(INVALID_NAME);
    }
    let pattern = if pattern == "*.*" { "*" } else { pattern };
    let cwd = state.crt_streams().working_directory();
    // A bare drive root (`c:` as the whole directory portion) anchors at the
    // volume root: the wildcard split consumed the separating backslash.
    let resolved = if root.len() == 2 && root.as_bytes()[1] == b':' {
        String::new()
    } else {
        super::crt::resolve_directory(&cwd, root)
    };
    if !resolved
        .split('\\')
        .all(|part| part.is_empty() || valid_component(part))
    {
        return Err(INVALID_NAME);
    }
    // The drive keys are the bare volume-relative form everywhere, with the
    // empty name for the root, exactly as creating or opening a file keys
    // them: the search compares like with like.
    let directory = resolved;
    let mut objects = state.objects.lock().expect("guest object state");
    if !directory.is_empty() && !objects.directories.contains(directory.as_str()) {
        return Err(PATH_NOT_FOUND);
    }
    let candidates = objects
        .directories
        .iter()
        .map(|path| (path, 0x10, 0))
        .chain(
            objects
                .files
                .iter()
                .map(|(path, data)| (path, 0x80, data.len() as u64)),
        );
    let mut entries = Vec::new();
    for (path, attributes, size) in
        candidates.filter(|(path, _, _)| parent(path) == directory.as_str())
    {
        let name = path.rsplit('\\').next().expect("candidate name");
        let is_directory = attributes & 0x10 != 0;
        // FindExSearchLimitToDirectories keeps only directories and
        // FindExSearchLimitToFiles only files; the name match keeps both.
        if search_op == 1 && !is_directory {
            continue;
        }
        if search_op == 2 && is_directory {
            continue;
        }
        if wildcard_match(pattern, name) {
            let times = objects
                .file_times
                .get(path.as_str())
                .copied()
                .unwrap_or(EPOCH_FILETIME3);
            entries.push(SearchEntry {
                name: name.to_owned(),
                attributes,
                size,
                times,
            });
        }
    }
    // The real enumeration of a directory always begins with the dot
    // entries: `.` is the directory itself and `..` its parent, both
    // directories, and even an empty directory answers them to a `*`
    // pattern. They go through the same wildcard match as real names.
    for dot in [".", ".."] {
        if wildcard_match(pattern, dot) {
            entries.push(SearchEntry {
                name: dot.to_owned(),
                attributes: 0x10,
                size: 0,
                times: EPOCH_FILETIME3,
            });
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let Some(first) = entries.first() else {
        return Err(FILE_NOT_FOUND);
    };
    if objects
        .handles
        .values()
        .filter(|object| matches!(object, GuestObject::Search(_)))
        .count()
        >= 32
    {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    }
    let Some(handle) = objects.next_handle() else {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    };
    if write(memory, output, first).is_err() {
        return Err(ERROR_NOACCESS);
    }
    objects.insert_handle(handle, GuestObject::Search(Search { entries, next: 1 }));
    Ok(handle)
}

/// The display form of a normalized drive name, `c:\name`, or nothing for
/// an empty or invalid name.
/// Resolve a guest path against the process working directory, lexically,
/// dot segments included: a drive letter or a leading backslash anchors at
/// the volume root, anything else hangs under the working directory. The
/// working directory itself starts at the root, which keeps the resolution
/// of a fresh process the historical one. The CRT `_chdir` moves it, so the
/// kernel file operations and the CRT forms stay consistent, the behaviour
/// a single Windows process exposes.
fn full_name(cwd: &str, name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let resolved = super::crt::resolve_directory(cwd, name);
    if !resolved
        .split('\\')
        .all(|part| part.is_empty() || valid_component(part))
    {
        return None;
    }
    Some(format!("c:\\{resolved}"))
}

/// The CRT `_finddata64i32_t` layout of mingw-w64: attributes at 0, the
/// three 64-bit times at 8/16/24, the 32-bit size at 32, the narrow name at
/// 36, 296 bytes in all. The drive does not track times yet, so the times
/// answer -1, which is what a volume without time stamps reports.
fn crt_write_finddata64i32(
    memory: &mut GuestMemory,
    output: u64,
    entry: &SearchEntry,
) -> Result<(), MemoryError> {
    if output == 0 {
        return Err(MemoryError::UnmappedAddress(0));
    }
    let mut bytes = [0u8; 296];
    bytes[0..4].copy_from_slice(&entry.attributes.to_le_bytes());
    // The CRT form carries seconds: the tracked times convert from Windows
    // FILETIMEs, and a file the drive does not know answers the zero
    // time_t, the 1970 epoch every conversion accepts.
    for (slot, offset) in [8usize, 16, 24].into_iter().enumerate() {
        let seconds =
            (entry.times[slot].saturating_sub(116_444_736_000_000_000) / 10_000_000) as i64;
        bytes[offset..offset + 8].copy_from_slice(&seconds.to_le_bytes());
    }
    bytes[32..36].copy_from_slice(&(entry.size as u32).to_le_bytes());
    let name = entry.name.as_bytes();
    let length = name.len().min(259);
    bytes[36..36 + length].copy_from_slice(&name[..length]);
    memory.write_bytes(output, &bytes)
}

/// Update a file's byte-range locks. Conflicting synchronous acquisitions
/// fail immediately because waiting for a lock is not modeled.
fn update_range_lock(
    ranges: &mut Vec<(u64, u64, u64, bool)>,
    handle: u64,
    offset: u64,
    length: u64,
    exclusive: bool,
    unlock: bool,
) -> Result<(), u32> {
    if unlock {
        // When a handle owns both kinds on the exact range, release the
        // exclusive one first, even if the vector has been reordered.
        let matching = ranges
            .iter()
            .enumerate()
            .filter(|entry| {
                let &(owner, at, len, _) = entry.1;
                owner == handle && at == offset && len == length
            })
            .max_by_key(|(_, range)| range.3);
        let Some((index, _)) = matching else {
            return Err(ERROR_NOT_LOCKED);
        };
        ranges.swap_remove(index);
        return Ok(());
    }

    let end = u128::from(offset) + u128::from(length);
    let conflicts = ranges.iter().any(|&(owner, at, len, other_exclusive)| {
        u128::from(offset) < u128::from(at) + u128::from(len)
            && u128::from(at) < end
            && (exclusive || (other_exclusive && owner != handle))
    });
    if conflicts {
        return Err(ERROR_LOCK_VIOLATION);
    }
    ranges.push((handle, offset, length, exclusive));
    Ok(())
}

/// The machine has exactly one volume, mounted at C:. Its GUID name is
/// fixed: there is no mount manager to generate one.
pub(super) const VOLUME_GUID: &str = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\";
pub(super) const VOLUME_LABEL: &str = "XENORA";
pub(super) const VOLUME_FS: &str = "XENORA-FS";
pub(super) const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_MORE_DATA: u32 = 234;

fn write_string(
    memory: &mut GuestMemory,
    output: u64,
    capacity: u64,
    text: &str,
    wide: bool,
) -> bool {
    let units = text.chars().count() as u64 + 1;
    if output == 0 || capacity < units {
        return false;
    }
    if wide {
        let wide_units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        for (index, unit) in wide_units.iter().enumerate() {
            if memory.write_u16(output + index as u64 * 2, *unit).is_err() {
                return false;
            }
        }
    } else {
        let bytes = format!("{text}\0");
        if memory.write_bytes(output, bytes.as_bytes()).is_err() {
            return false;
        }
    }
    true
}

pub(super) fn register(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let open = Arc::clone(state);
    registry.register(KERNEL32, "CreateFileW", move |args, cpu, memory| {
        let access = args.rdx as u32;
        let share = args.r8 as u32;
        let disposition = args.get(4, memory).map_err(ExitReason::MemoryFault)? as u32;
        let flags = args.get(5, memory).map_err(ExitReason::MemoryFault)? as u32;
        let template = args.get(6, memory).map_err(ExitReason::MemoryFault)?;
        // FILE_FLAG_BACKUP_SEMANTICS is a flag, no attribute: it is the only
        // flag bit the machine models, and it matters only for directories.
        let backup_semantics = flags & 0x0200_0000 != 0;
        if args.r9 != 0
            // BACKUP_SEMANTICS is accepted beside the zero and normal
            // attribute flags: on a file it is a no-op on Windows itself, the
            // machine models no backup privilege, and directories refuse on
            // their own path below.
            || template != 0
            || !matches!(flags & !0x0200_0000, 0 | 0x80)
            || access & !(READ | WRITE | WRITE_ATTRIBUTES) != 0
            || share & !3 != 0
        {
            return open.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, INVALID_HANDLE);
        }
        if !(1..=5).contains(&disposition) {
            return open.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, INVALID_HANDLE);
        }
        if matches!(disposition, 2 | 5) && access & WRITE == 0 {
            return open.fail(cpu.gs_base, ERROR_ACCESS_DENIED, INVALID_HANDLE);
        }
        let Some(path) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return open.fail(cpu.gs_base, INVALID_NAME, INVALID_HANDLE);
        };
        let mut objects = open.objects.lock().expect("guest object state");
        if is_nul_path(&path) {
            // The NUL device needs no directory behind it, exists under every
            // disposition and takes no part in sharing or the drive's space:
            // the open is the handle alone.
            let Some(handle) = objects.next_handle() else {
                return open.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
            };
            objects.insert_handle(
                handle,
                GuestObject::File(OpenFile {
                    path,
                    position: Arc::new(AtomicU64::new(0)),
                    open_access: access,
                    access,
                    share,
                    directory: false,
                }),
            );
            return Ok(handle);
        }
        let parent = parent(&path);
        if !parent.is_empty() && !objects.directories.contains(parent) {
            return open.fail(cpu.gs_base, PATH_NOT_FOUND, INVALID_HANDLE);
        }
        if objects.directories.contains(&path) {
            // CreateFile never creates or truncates a directory, so only the
            // plain open of an existing one is meaningful, and the
            // documentation gates even that behind the backup-semantics
            // flag.
            if !backup_semantics || disposition != 3 {
                return open.fail(cpu.gs_base, ERROR_ACCESS_DENIED, INVALID_HANDLE);
            }
            let Some(handle) = objects.next_handle() else {
                return open.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
            };
            objects.insert_handle(
                handle,
                GuestObject::File(OpenFile {
                    path,
                    position: Arc::new(AtomicU64::new(0)),
                    open_access: access,
                    access,
                    share,
                    directory: true,
                }),
            );
            return Ok(handle);
        }
        let exists = objects.files.contains_key(&path);
        if exists && disposition == 1 {
            return open.fail(cpu.gs_base, FILE_EXISTS, INVALID_HANDLE);
        }
        if !exists && matches!(disposition, 3 | 5) {
            return open.fail(cpu.gs_base, FILE_NOT_FOUND, INVALID_HANDLE);
        }
        for object in objects.handles.values() {
            if let GuestObject::File(file) = object
                && file.path == path
                && (share_mask(access) & !file.share != 0
                    || share_mask(file.open_access) & !share != 0)
            {
                return open.fail(cpu.gs_base, SHARING_VIOLATION, INVALID_HANDLE);
            }
        }
        let Some(handle) = objects.next_handle() else {
            return open.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
        };
        if !exists {
            if objects.files.len() >= MAX_FILES {
                return open.fail(cpu.gs_base, DISK_FULL, INVALID_HANDLE);
            }
            objects.files.insert(path.clone(), Vec::new());
            let now = open.clock.now_filetime();
            objects.file_times.insert(path.clone(), [now; 3]);
        } else if matches!(disposition, 2 | 5) {
            *objects.files.get_mut(&path).expect("existing file") = Vec::new();
        }
        if matches!(disposition, 2 | 4) {
            open.fail(cpu.gs_base, if exists { ALREADY_EXISTS } else { 0 }, 0)?;
        }
        objects.insert_handle(
            handle,
            GuestObject::File(OpenFile {
                path,
                position: Arc::new(AtomicU64::new(0)),
                open_access: access,
                access,
                share,
                directory: false,
            }),
        );
        Ok(handle)
    });

    let open_a = Arc::clone(state);
    registry.register(KERNEL32, "CreateFileA", move |args, cpu, memory| {
        let access = args.rdx as u32;
        let share = args.r8 as u32;
        let disposition = args.get(4, memory).map_err(ExitReason::MemoryFault)? as u32;
        let flags = args.get(5, memory).map_err(ExitReason::MemoryFault)? as u32;
        let template = args.get(6, memory).map_err(ExitReason::MemoryFault)?;
        // FILE_FLAG_BACKUP_SEMANTICS is a flag, no attribute: it is the only
        // flag bit the machine models, and it matters only for directories.
        let backup_semantics = flags & 0x0200_0000 != 0;
        if args.r9 != 0
            || template != 0
            || !matches!(flags & !0x0200_0000, 0 | 0x80)
            || access & !(READ | WRITE | WRITE_ATTRIBUTES) != 0
            || share & !3 != 0
        {
            return open_a.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, INVALID_HANDLE);
        }
        if !(1..=5).contains(&disposition) {
            return open_a.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, INVALID_HANDLE);
        }
        if matches!(disposition, 2 | 5) && access & WRITE == 0 {
            return open_a.fail(cpu.gs_base, ERROR_ACCESS_DENIED, INVALID_HANDLE);
        }
        let Some(path) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return open_a.fail(cpu.gs_base, INVALID_NAME, INVALID_HANDLE);
        };
        let mut objects = open_a.objects.lock().expect("guest object state");
        if is_nul_path(&path) {
            // The NUL device needs no directory behind it, exists under every
            // disposition and takes no part in sharing or the drive's space:
            // the open is the handle alone.
            let Some(handle) = objects.next_handle() else {
                return open_a.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
            };
            objects.insert_handle(
                handle,
                GuestObject::File(OpenFile {
                    path,
                    position: Arc::new(AtomicU64::new(0)),
                    open_access: access,
                    access,
                    share,
                    directory: false,
                }),
            );
            return Ok(handle);
        }
        let parent = parent(&path);
        if !parent.is_empty() && !objects.directories.contains(parent) {
            return open_a.fail(cpu.gs_base, PATH_NOT_FOUND, INVALID_HANDLE);
        }
        if objects.directories.contains(&path) {
            if !backup_semantics || disposition != 3 {
                return open_a.fail(cpu.gs_base, ERROR_ACCESS_DENIED, INVALID_HANDLE);
            }
            let Some(handle) = objects.next_handle() else {
                return open_a.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
            };
            objects.insert_handle(
                handle,
                GuestObject::File(OpenFile {
                    path,
                    position: Arc::new(AtomicU64::new(0)),
                    open_access: access,
                    access,
                    share,
                    directory: true,
                }),
            );
            return Ok(handle);
        }
        let exists = objects.files.contains_key(&path);
        if exists && disposition == 1 {
            return open_a.fail(cpu.gs_base, FILE_EXISTS, INVALID_HANDLE);
        }
        if !exists && matches!(disposition, 3 | 5) {
            return open_a.fail(cpu.gs_base, FILE_NOT_FOUND, INVALID_HANDLE);
        }
        for object in objects.handles.values() {
            if let GuestObject::File(file) = object
                && file.path == path
                && (share_mask(access) & !file.share != 0
                    || share_mask(file.open_access) & !share != 0)
            {
                return open_a.fail(cpu.gs_base, SHARING_VIOLATION, INVALID_HANDLE);
            }
        }
        let Some(handle) = objects.next_handle() else {
            return open_a.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
        };
        if !exists {
            if objects.files.len() >= MAX_FILES {
                return open_a.fail(cpu.gs_base, DISK_FULL, INVALID_HANDLE);
            }
            objects.files.insert(path.clone(), Vec::new());
            let now = open_a.clock.now_filetime();
            objects.file_times.insert(path.clone(), [now; 3]);
        } else if matches!(disposition, 2 | 5) {
            *objects.files.get_mut(&path).expect("existing file") = Vec::new();
        }
        if matches!(disposition, 2 | 4) {
            open_a.fail(cpu.gs_base, if exists { ALREADY_EXISTS } else { 0 }, 0)?;
        }
        objects.insert_handle(
            handle,
            GuestObject::File(OpenFile {
                path,
                position: Arc::new(AtomicU64::new(0)),
                open_access: access,
                access,
                share,
                directory: false,
            }),
        );
        Ok(handle)
    });

    let create = Arc::clone(state);
    registry.register(KERNEL32, "CreateDirectoryW", move |args, cpu, memory| {
        if args.rdx != 0 {
            return create.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
        }
        let Some(path) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return create.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = create.objects.lock().expect("guest object state");
        match create_directory(&mut objects, &path) {
            Ok(()) => Ok(1),
            Err(error) => create.fail(cpu.gs_base, error, 0),
        }
    });

    let create_a = Arc::clone(state);
    registry.register(KERNEL32, "CreateDirectoryA", move |args, cpu, memory| {
        if args.rdx != 0 {
            return create_a.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
        }
        let Some(path) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return create_a.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = create_a.objects.lock().expect("guest object state");
        match create_directory(&mut objects, &path) {
            Ok(()) => Ok(1),
            Err(error) => create_a.fail(cpu.gs_base, error, 0),
        }
    });

    let remove = Arc::clone(state);
    registry.register(KERNEL32, "RemoveDirectoryW", move |args, cpu, memory| {
        let Some(path) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return remove.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = remove.objects.lock().expect("guest object state");
        match remove_directory(&mut objects, &path) {
            Ok(()) => Ok(1),
            Err(error) => remove.fail(cpu.gs_base, error, 0),
        }
    });

    let remove_a = Arc::clone(state);
    registry.register(KERNEL32, "RemoveDirectoryA", move |args, cpu, memory| {
        let Some(path) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return remove_a.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = remove_a.objects.lock().expect("guest object state");
        match remove_directory(&mut objects, &path) {
            Ok(()) => Ok(1),
            Err(error) => remove_a.fail(cpu.gs_base, error, 0),
        }
    });

    let delete = Arc::clone(state);
    registry.register(KERNEL32, "DeleteFileW", move |args, cpu, memory| {
        let Some(path) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return delete.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = delete.objects.lock().expect("guest object state");
        if objects.directories.contains(&path) {
            return delete.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
        }
        let parent = parent(&path);
        if !parent.is_empty() && !objects.directories.contains(parent) {
            return delete.fail(cpu.gs_base, PATH_NOT_FOUND, 0);
        }
        if objects
            .handles
            .values()
            .any(|object| matches!(object, GuestObject::File(file) if file.path == path))
        {
            return delete.fail(cpu.gs_base, SHARING_VIOLATION, 0);
        }
        if objects.files.remove(&path).is_none() {
            return delete.fail(cpu.gs_base, FILE_NOT_FOUND, 0);
        }
        Ok(1)
    });

    let attributes = Arc::clone(state);
    registry.register(KERNEL32, "GetFileAttributesW", move |args, cpu, memory| {
        const INVALID_ATTRIBUTES: u64 = u32::MAX as u64;
        let Some(path) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return attributes.fail(cpu.gs_base, INVALID_NAME, INVALID_ATTRIBUTES);
        };
        let objects = attributes.objects.lock().expect("guest object state");
        if objects.directories.contains(&path) {
            return Ok(0x10); // FILE_ATTRIBUTE_DIRECTORY
        }
        if objects.files.contains_key(&path) {
            return Ok(0x80); // FILE_ATTRIBUTE_NORMAL
        }
        let parent = parent(&path);
        let error = if parent.is_empty() || objects.directories.contains(parent) {
            FILE_NOT_FOUND
        } else {
            PATH_NOT_FOUND
        };
        attributes.fail(cpu.gs_base, error, INVALID_ATTRIBUTES)
    });

    let attributes_a = Arc::clone(state);
    registry.register(KERNEL32, "GetFileAttributesA", move |args, cpu, memory| {
        const INVALID_ATTRIBUTES: u64 = u32::MAX as u64;
        let Some(path) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return attributes_a.fail(cpu.gs_base, INVALID_NAME, INVALID_ATTRIBUTES);
        };
        let objects = attributes_a.objects.lock().expect("guest object state");
        if objects.directories.contains(&path) {
            return Ok(0x10); // FILE_ATTRIBUTE_DIRECTORY
        }
        if objects.files.contains_key(&path) {
            return Ok(0x80); // FILE_ATTRIBUTE_NORMAL
        }
        let parent = parent(&path);
        let error = if parent.is_empty() || objects.directories.contains(parent) {
            FILE_NOT_FOUND
        } else {
            PATH_NOT_FOUND
        };
        attributes_a.fail(cpu.gs_base, error, INVALID_ATTRIBUTES)
    });

    let rename = Arc::clone(state);
    registry.register(KERNEL32, "MoveFileW", move |args, cpu, memory| {
        let Some(source) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return rename.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let Some(target) = guest_path(memory, args.rdx).map_err(ExitReason::MemoryFault)? else {
            return rename.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = rename.objects.lock().expect("guest object state");
        match move_file(&mut objects, &source, &target) {
            Ok(()) => Ok(1),
            Err(error) => rename.fail(cpu.gs_base, error, 0),
        }
    });

    let rename_a = Arc::clone(state);
    registry.register(KERNEL32, "MoveFileA", move |args, cpu, memory| {
        let Some(source) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return rename_a.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let Some(target) = guest_path_a(memory, args.rdx).map_err(ExitReason::MemoryFault)? else {
            return rename_a.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = rename_a.objects.lock().expect("guest object state");
        match move_file(&mut objects, &source, &target) {
            Ok(()) => Ok(1),
            Err(error) => rename_a.fail(cpu.gs_base, error, 0),
        }
    });

    let rename_ex = Arc::clone(state);
    registry.register(KERNEL32, "MoveFileExA", move |args, cpu, memory| {
        // MOVEFILE_DELAY_UNTIL_REBOOT is meaningless without a boot to wait
        // for; the copy-across-volumes flag is inert with the one drive.
        const REPLACE_EXISTING: u64 = 1;
        const DELAY_UNTIL_REBOOT: u64 = 4;
        if args.r8 & DELAY_UNTIL_REBOOT != 0 {
            return rename_ex.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
        }
        let Some(source) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return rename_ex.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let Some(target) = guest_path_a(memory, args.rdx).map_err(ExitReason::MemoryFault)? else {
            return rename_ex.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = rename_ex.objects.lock().expect("guest object state");
        if args.r8 & REPLACE_EXISTING != 0 {
            objects.files.remove(&target);
        }
        match move_file(&mut objects, &source, &target) {
            Ok(()) => Ok(1),
            Err(error) => rename_ex.fail(cpu.gs_base, error, 0),
        }
    });

    let rename_ex_w = Arc::clone(state);
    registry.register(KERNEL32, "MoveFileExW", move |args, cpu, memory| {
        // MOVEFILE_DELAY_UNTIL_REBOOT is meaningless without a boot to wait
        // for; the copy-across-volumes flag is inert with the one drive.
        const REPLACE_EXISTING: u64 = 1;
        const DELAY_UNTIL_REBOOT: u64 = 4;
        if args.r8 & DELAY_UNTIL_REBOOT != 0 {
            return rename_ex_w.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
        }
        let Some(source) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return rename_ex_w.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let Some(target) = guest_path(memory, args.rdx).map_err(ExitReason::MemoryFault)? else {
            return rename_ex_w.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut objects = rename_ex_w.objects.lock().expect("guest object state");
        if args.r8 & REPLACE_EXISTING != 0 {
            objects.files.remove(&target);
        }
        match move_file(&mut objects, &source, &target) {
            Ok(()) => Ok(1),
            Err(error) => rename_ex_w.fail(cpu.gs_base, error, 0),
        }
    });

    // The volume enumeration walks the machine's one volume, then ends.
    for (symbol, wide) in [("FindFirstVolumeW", true), ("FindFirstVolumeA", false)] {
        let first_volume = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let mut objects = first_volume.objects.lock().expect("guest object state");
            let Some(handle) = objects.next_handle() else {
                return first_volume.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
            };
            if !write_string(memory, args.rcx, args.rdx, VOLUME_GUID, wide) {
                return first_volume.fail(cpu.gs_base, ERROR_MORE_DATA, INVALID_HANDLE);
            }
            let entries = vec![SearchEntry {
                name: VOLUME_GUID.to_owned(),
                attributes: 0,
                size: 0,
                times: EPOCH_FILETIME3,
            }];
            objects.insert_handle(handle, GuestObject::Search(Search { entries, next: 1 }));
            Ok(handle)
        });
    }

    for (symbol, _wide) in [("FindNextVolumeW", true), ("FindNextVolumeA", false)] {
        let next_volume = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let _ = memory;
            {
                let objects = next_volume.objects.lock().expect("guest object state");
                if !matches!(objects.handles.get(&args.rcx), Some(GuestObject::Search(_))) {
                    return next_volume.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
                }
            }
            // The machine has exactly one volume; the first call after the
            // enumeration always ends it.
            next_volume.fail(cpu.gs_base, ERROR_NO_MORE_FILES, 0)
        });
    }

    let volume_close = Arc::clone(state);
    registry.register(KERNEL32, "FindVolumeClose", move |args, cpu, memory| {
        let _ = memory;
        let mut objects = volume_close.objects.lock().expect("guest object state");
        if !matches!(objects.handles.get(&args.rcx), Some(GuestObject::Search(_))) {
            return volume_close.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        }
        objects.handles.remove(&args.rcx);
        Ok(1)
    });

    // The volume information is fixed: one label, one serial, the hosted
    // filesystem's limits.
    for (symbol, wide) in [
        ("GetVolumeInformationW", true),
        ("GetVolumeInformationA", false),
    ] {
        let volume_info = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let root = if wide {
                read_guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)?
            } else {
                read_guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)?
            };
            let Some(root) = root else {
                return volume_info.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            // read_guest_path strips the c:\ prefix, so the root is empty.
            if !root.is_empty() {
                return volume_info.fail(cpu.gs_base, FILE_NOT_FOUND, 0);
            }
            let serial_out = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
            let component_out = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
            let flags_out = args.get(5, memory).map_err(ExitReason::MemoryFault)?;
            let fs_name = args.get(6, memory).map_err(ExitReason::MemoryFault)?;
            let fs_capacity = args.get(7, memory).map_err(ExitReason::MemoryFault)?;
            if args.rdx != 0 && !write_string(memory, args.rdx, args.r8, VOLUME_LABEL, wide) {
                return volume_info.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            if serial_out != 0 {
                memory
                    .write_u32(serial_out, 0x58414E4F)
                    .map_err(ExitReason::MemoryFault)?;
            }
            if component_out != 0 {
                memory
                    .write_u32(component_out, 255)
                    .map_err(ExitReason::MemoryFault)?;
            }
            if flags_out != 0 {
                // Case-preserving names, Unicode stored on disk, persistent ACLs absent.
                memory
                    .write_u32(flags_out, 0x2 | 0x4)
                    .map_err(ExitReason::MemoryFault)?;
            }
            if fs_name != 0 && !write_string(memory, fs_name, fs_capacity, VOLUME_FS, wide) {
                return volume_info.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            Ok(1)
        });
    }

    // Mount point and volume name translations are exact on a one-volume
    // machine.
    for (symbol, wide) in [
        ("GetVolumeNameForVolumeMountPointW", true),
        ("GetVolumeNameForVolumeMountPointA", false),
    ] {
        let mount_point = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let reader = if wide {
                read_guest_path
            } else {
                read_guest_path_a
            };
            let Some(point) = reader(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
                return mount_point.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            if !point.is_empty() {
                return mount_point.fail(cpu.gs_base, FILE_NOT_FOUND, 0);
            }
            if !write_string(memory, args.rdx, args.r8, VOLUME_GUID, wide) {
                return mount_point.fail(cpu.gs_base, ERROR_MORE_DATA, 0);
            }
            Ok(1)
        });
    }

    for (symbol, wide) in [
        ("GetVolumePathNamesForVolumeNameW", true),
        ("GetVolumePathNamesForVolumeNameA", false),
    ] {
        let path_names = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let reader = if wide {
                read_guest_path
            } else {
                read_guest_path_a
            };
            let Some(name) = reader(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
                return path_names.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            // The reader lowercases: compare case-insensitively, with or
            // without the trailing separator.
            let canonical = VOLUME_GUID.to_ascii_lowercase();
            if name != canonical && name != canonical.trim_end_matches('\\') {
                return path_names.fail(cpu.gs_base, FILE_NOT_FOUND, 0);
            }
            // A multi-string of one entry: C:\ then the terminating empty string.
            let needed = if wide { 10 } else { 5 };
            if args.r8 < needed {
                return path_names.fail(cpu.gs_base, ERROR_MORE_DATA, 0);
            }
            if wide {
                for (index, unit) in "C:\\".encode_utf16().enumerate() {
                    memory
                        .write_u16(args.rdx + index as u64 * 2, unit)
                        .map_err(ExitReason::MemoryFault)?;
                }
                memory
                    .write_u16(args.rdx + 6, 0)
                    .map_err(ExitReason::MemoryFault)?;
                memory
                    .write_u16(args.rdx + 8, 0)
                    .map_err(ExitReason::MemoryFault)?;
            } else {
                memory
                    .write_bytes(args.rdx, b"C:\\")
                    .map_err(ExitReason::MemoryFault)?;
                memory
                    .write_bytes(args.rdx + 3, b"\0\0")
                    .map_err(ExitReason::MemoryFault)?;
            }
            Ok(1)
        });
    }

    // CopyFile of both widths: the copy shares the content within the drive,
    // the `fail_if_exists` flag is the third parameter of the contract.
    for (symbol, narrow) in [("CopyFileW", false), ("CopyFileA", true)] {
        let copy = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let reader = if narrow { guest_path_a } else { guest_path };
            let Some(source) = reader(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
                return copy.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            let Some(target) = reader(memory, args.rdx).map_err(ExitReason::MemoryFault)? else {
                return copy.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            let mut objects = copy.objects.lock().expect("guest object state");
            match copy_file(&mut objects, &source, &target, args.r8 != 0) {
                Ok(()) => Ok(1),
                Err(error) => copy.fail(cpu.gs_base, error, 0),
            }
        });
    }

    for (symbol, narrow) in [("FindFirstFileW", false), ("FindFirstFileA", true)] {
        let find = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let reader = if narrow {
                read_guest_path_a
            } else {
                read_guest_path
            };
            let Some(path) = reader(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
                return find.fail(cpu.gs_base, INVALID_NAME, INVALID_HANDLE);
            };
            let write = if narrow {
                write_find_data_a
            } else {
                write_find_data
            };
            match find_first(&find, memory, &path, args.rdx, write, 0) {
                Ok(handle) => Ok(handle),
                Err(error) => find.fail(cpu.gs_base, error, INVALID_HANDLE),
            }
        });
    }

    // `FindFirstFileEx` of either width: the information levels Standard and
    // Basic share the one output layout, the search operations filter the
    // snapshot by kind, and the flags are performance hints the answers do
    // not depend on. An unknown level or operation refuses honestly rather
    // than guessing.
    for (symbol, narrow) in [("FindFirstFileExW", false), ("FindFirstFileExA", true)] {
        let find_ex = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let level = args.rdx as u32;
            let search_op = args.r9 as u32;
            if level > 1 || search_op > 2 {
                return find_ex.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, INVALID_HANDLE);
            }
            let reader = if narrow {
                read_guest_path_a
            } else {
                read_guest_path
            };
            let Some(path) = reader(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
                return find_ex.fail(cpu.gs_base, INVALID_NAME, INVALID_HANDLE);
            };
            let write = if narrow {
                write_find_data_a
            } else {
                write_find_data
            };
            match find_first(&find_ex, memory, &path, args.r8, write, search_op) {
                Ok(handle) => Ok(handle),
                Err(error) => find_ex.fail(cpu.gs_base, error, INVALID_HANDLE),
            }
        });
    }

    for (symbol, narrow) in [("FindNextFileW", false), ("FindNextFileA", true)] {
        let find_next = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let mut objects = find_next.objects.lock().expect("guest object state");
            let Some(GuestObject::Search(search)) = objects.handles.get_mut(&args.rcx) else {
                return find_next.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            };
            let Some(entry) = search.entries.get(search.next) else {
                return find_next.fail(cpu.gs_base, 18, 0); // ERROR_NO_MORE_FILES
            };
            let write = if narrow {
                write_find_data_a
            } else {
                write_find_data
            };
            if write(memory, args.rdx, entry).is_err() {
                return find_next.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            search.next += 1;
            Ok(1)
        });
    }

    let find_close = Arc::clone(state);
    registry.register(KERNEL32, "FindClose", move |args, cpu, _| {
        let mut objects = find_close.objects.lock().expect("guest object state");
        if !matches!(objects.handles.get(&args.rcx), Some(GuestObject::Search(_))) {
            return find_close.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        }
        objects.handles.remove(&args.rcx);
        Ok(1)
    });

    let size = Arc::clone(state);
    registry.register(KERNEL32, "GetFileSizeEx", move |args, cpu, memory| {
        let objects = size.objects.lock().expect("guest object state");
        let Some(GuestObject::File(file)) = objects.handles.get(&args.rcx) else {
            return size.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        };
        let bytes = objects
            .files
            .get(&file.path)
            .expect("open file exists")
            .len();
        if args.rdx == 0 || memory.write_u64(args.rdx, bytes as u64).is_err() {
            return size.fail(cpu.gs_base, ERROR_NOACCESS, 0);
        }
        Ok(1)
    });

    // Record the selected file API mode. Narrow paths use UTF-8 in both modes.
    let ansi_query = Arc::clone(state);
    registry.register(KERNEL32, "AreFileApisANSI", move |_, _, _| {
        Ok(u64::from(ansi_query.file_apis_use_ansi()))
    });
    let ansi_set = Arc::clone(state);
    registry.register(KERNEL32, "SetFileApisToANSI", move |_, _, _| {
        ansi_set.set_file_apis_ansi(true);
        Ok(0)
    });
    let oem_set = Arc::clone(state);
    registry.register(KERNEL32, "SetFileApisToOEM", move |_, _, _| {
        oem_set.set_file_apis_ansi(false);
        Ok(0)
    });

    // Free space of the confined synthetic volume: the drive's byte budget
    // and the bytes its files hold, in clusters of one 4096-byte sector.
    // The volume is memory-backed, so the budget is the honest capacity.
    for (symbol, narrow) in [("GetDiskFreeSpaceA", true), ("GetDiskFreeSpaceW", false)] {
        let disk = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            // A null root selects the current drive. An explicit C:\ root
            // normalizes to an empty path in both string readers.
            if args.rcx != 0 {
                let read = if narrow {
                    read_guest_path_a
                } else {
                    read_guest_path
                };
                match read(memory, args.rcx) {
                    Ok(Some(root)) if root.is_empty() => {}
                    Ok(Some(_)) => return disk.fail(cpu.gs_base, PATH_NOT_FOUND, 0),
                    Ok(None) => return disk.fail(cpu.gs_base, INVALID_NAME, 0),
                    Err(_) => return disk.fail(cpu.gs_base, ERROR_NOACCESS, 0),
                }
            }
            let fourth = match args.get(4, memory) {
                Ok(p) => p,
                Err(_) => return disk.fail(cpu.gs_base, ERROR_NOACCESS, 0),
            };
            let outputs = [args.rdx, args.r8, args.r9, fourth];
            if outputs
                .iter()
                .any(|&at| at == 0 || memory.check_write(at, 4).is_err())
            {
                return disk.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            let objects = disk.objects.lock().expect("guest object state");
            let used = objects.files.values().map(Vec::len).sum::<usize>();
            const SECTOR_BYTES: usize = 4096;
            let clusters = |bytes: usize| (bytes / SECTOR_BYTES) as u32;
            for (at, value) in outputs.into_iter().zip([
                1,
                SECTOR_BYTES as u32,
                clusters(MAX_BYTES.saturating_sub(used)),
                clusters(MAX_BYTES),
            ]) {
                memory
                    .write_u32(at, value)
                    .map_err(ExitReason::MemoryFault)?;
            }
            Ok(1)
        });
    }

    let seek = Arc::clone(state);
    registry.register(KERNEL32, "SetFilePointerEx", move |args, cpu, memory| {
        let mut objects = seek.objects.lock().expect("guest object state");
        let super::ObjectState { handles, files, .. } = &mut *objects;
        let Some(GuestObject::File(file)) = handles.get_mut(&args.rcx) else {
            return seek.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        };
        if file.access & (READ | WRITE) == 0 {
            return seek.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
        }
        let origin = match args.r9 as u32 {
            0 => None,
            1 => Some(file.position.load(Ordering::Relaxed)),
            2 => Some(files.get(&file.path).expect("open file exists").len() as u64),
            _ => return seek.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0),
        };
        let position = match origin {
            None => args.rdx,
            Some(origin) => {
                let distance = args.rdx as i64;
                if distance.is_negative() && distance.unsigned_abs() > origin {
                    return seek.fail(cpu.gs_base, NEGATIVE_SEEK, 0);
                }
                let Some(position) = origin.checked_add_signed(distance) else {
                    return seek.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
                };
                position
            }
        };
        if args.r8 != 0 && memory.write_u64(args.r8, position).is_err() {
            return seek.fail(cpu.gs_base, ERROR_NOACCESS, 0);
        }
        file.position.store(position, Ordering::Relaxed);
        Ok(1)
    });

    let truncate = Arc::clone(state);
    registry.register(KERNEL32, "SetEndOfFile", move |args, cpu, _| {
        let mut objects = truncate.objects.lock().expect("guest object state");
        let super::ObjectState { handles, files, .. } = &mut *objects;
        let Some(GuestObject::File(file)) = handles.get(&args.rcx) else {
            return truncate.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        };
        if file.access & WRITE == 0 {
            return truncate.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
        }
        let position = file.position.load(Ordering::Relaxed);
        if position > MAX_BYTES as u64 {
            return truncate.fail(cpu.gs_base, DISK_FULL, 0);
        }
        let used = files.values().map(Vec::len).sum::<usize>();
        let data = files.get_mut(&file.path).expect("open file exists");
        let length = position as usize;
        let growth = length.saturating_sub(data.len());
        if growth > MAX_BYTES - used {
            return truncate.fail(cpu.gs_base, DISK_FULL, 0);
        }
        data.try_reserve_exact(growth)
            .map_err(|_| ExitReason::MemoryFault(MemoryError::AllocationFailed))?;
        if length < data.len() {
            data.truncate(length);
            data.shrink_to_fit();
        } else {
            data.resize(length, 0);
        }
        Ok(1)
    });

    // GetFullPathName resolves a relative name against the synthetic root
    // and answers the `c:\` form, in either width. There is no current
    // directory yet, so a relative input is relative to the root - which
    // is what every fixture uses; the buffer-too-small answer counts the
    // terminator as the pages document.
    for (symbol, narrow) in [("GetFullPathNameW", false), ("GetFullPathNameA", true)] {
        let full = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let reader = if narrow {
                read_guest_path_a
            } else {
                read_guest_path
            };
            let Some(name) = reader(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
                return full.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            let cwd = full.crt_streams().working_directory();
            let Some(full_path) = full_name(&cwd, &name) else {
                return full.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            // args: rcx input, rdx buffer size in characters, r8 buffer, r9 file-part output.
            let size = args.rdx as usize;
            let buffer = args.r8;
            if narrow {
                let bytes = full_path.as_bytes();
                if size < bytes.len() + 1 {
                    return Ok((bytes.len() + 1) as u64);
                }
                if memory.write_bytes(buffer, bytes).is_err()
                    || memory.write_u8(buffer + bytes.len() as u64, 0).is_err()
                {
                    return full.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                }
                Ok(bytes.len() as u64)
            } else {
                let units: Vec<u16> = full_path.encode_utf16().collect();
                if size < units.len() + 1 {
                    return Ok((units.len() + 1) as u64);
                }
                let mut ok = true;
                for (index, unit) in units.iter().enumerate() {
                    if memory.write_u16(buffer + index as u64 * 2, *unit).is_err() {
                        ok = false;
                        break;
                    }
                }
                if ok
                    && memory
                        .write_u16(buffer + units.len() as u64 * 2, 0)
                        .is_err()
                {
                    ok = false;
                }
                if !ok {
                    return full.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                }
                Ok(units.len() as u64)
            }
        });
    }

    // GetFileInformationByHandle: the attributes, size and index of an open
    // file in the fixed BY_HANDLE_FILE_INFORMATION layout. Times are zero:
    // the drive has no clock, documented at the top of this file.
    let information = Arc::clone(state);
    registry.register(
        KERNEL32,
        "GetFileInformationByHandle",
        move |args, cpu, memory| {
            let objects = information.objects.lock().expect("guest object state");
            let Some(GuestObject::File(file)) = objects.handles.get(&args.rcx) else {
                return information.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            };
            let Some(data) = objects.files.get(&file.path) else {
                return information.fail(cpu.gs_base, FILE_NOT_FOUND, 0);
            };
            let mut bytes = [0u8; 52];
            bytes[..4].copy_from_slice(&0x80u32.to_le_bytes()); // FILE_ATTRIBUTE_NORMAL
            bytes[28..32].copy_from_slice(&(1u32).to_le_bytes()); // one link
            bytes[32..36].copy_from_slice(&((data.len() >> 32) as u32).to_le_bytes());
            bytes[36..40].copy_from_slice(&(data.len() as u32).to_le_bytes());
            if args.rdx == 0 || memory.write_bytes(args.rdx, &bytes).is_err() {
                return information.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            Ok(1)
        },
    );

    // SetFileAttributesW: only the normal/archive bit is modelled - the
    // drive keeps no attribute state yet, so setting normal succeeds and
    // anything else is refused rather than silently dropped.
    let set_attributes = Arc::clone(state);
    registry.register(KERNEL32, "SetFileAttributesW", move |args, cpu, memory| {
        let Some(path) = guest_path(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return set_attributes.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        if args.rdx != 0x80 && args.rdx != 0x20 {
            return set_attributes.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
        }
        let objects = set_attributes.objects.lock().expect("guest object state");
        if !objects.files.contains_key(&path) && !objects.directories.contains(&path) {
            return set_attributes.fail(cpu.gs_base, FILE_NOT_FOUND, 0);
        }
        Ok(1)
    });

    let set_attributes_a = Arc::clone(state);
    registry.register(KERNEL32, "SetFileAttributesA", move |args, cpu, memory| {
        let Some(path) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
            return set_attributes_a.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        if args.rdx != 0x80 && args.rdx != 0x20 {
            return set_attributes_a.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
        }
        let objects = set_attributes_a.objects.lock().expect("guest object state");
        if !objects.files.contains_key(&path) && !objects.directories.contains(&path) {
            return set_attributes_a.fail(cpu.gs_base, FILE_NOT_FOUND, 0);
        }
        Ok(1)
    });

    // SetFilePointer: the 32-bit distance plus the high word in/out, the
    // pre-Ex form. Its error answer is u32::MAX with NO_ERROR ambiguity the
    // page documents; the guest reads GetLastError to disambiguate.
    let pointer = Arc::clone(state);
    registry.register(KERNEL32, "SetFilePointer", move |args, cpu, memory| {
        let objects = pointer.objects.lock().expect("guest object state");
        let Some(GuestObject::File(file)) = objects.handles.get(&args.rcx) else {
            return pointer.fail(cpu.gs_base, ERROR_INVALID_HANDLE, u32::MAX as u64);
        };
        let low = args.rdx as u32;
        let high_in = if args.r8 == 0 {
            0i32
        } else {
            memory.read_u32(args.r8).unwrap_or(0) as i32
        };
        let distance = ((high_in as i64) << 32) | (low as i64 & 0xFFFF_FFFF);
        let position = file.position.load(Ordering::Relaxed) as i64;
        let length = objects
            .files
            .get(&file.path)
            .map(|data| data.len() as i64)
            .unwrap_or(0);
        let base = match args.r9 as u32 {
            0 => 0,
            1 => position,
            2 => length,
            _ => return pointer.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, u32::MAX as u64),
        };
        let Some(new_position) = base.checked_add(distance) else {
            return pointer.fail(cpu.gs_base, NEGATIVE_SEEK, u32::MAX as u64);
        };
        if new_position < 0 {
            return pointer.fail(cpu.gs_base, NEGATIVE_SEEK, u32::MAX as u64);
        }
        file.position.store(new_position as u64, Ordering::Relaxed);
        if args.r8 != 0 {
            let _ = memory.write_u32(args.r8, (new_position >> 32) as u32);
        }
        Ok(new_position as u64 & 0xFFFF_FFFF)
    });

    // GetTempFileNameA: a unique name of the `xxxTMP` form in the given
    // directory, in the narrow width the survey measured. The counter makes
    // each answer unique within the run.
    let temp = Arc::clone(state);
    registry.register(KERNEL32, "GetTempFileNameA", move |args, cpu, memory| {
        let Some(directory) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)?
        else {
            return temp.fail(cpu.gs_base, INVALID_NAME, 0);
        };
        let mut prefix_bytes = Vec::new();
        for index in 0..3u64 {
            match memory.read_u8(args.rdx + index) {
                Ok(0) | Err(_) => break,
                Ok(byte) => prefix_bytes.push(byte),
            }
        }
        let prefix = String::from_utf8_lossy(&prefix_bytes).to_ascii_lowercase();
        if prefix.is_empty() {
            return temp.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
        }
        let mut objects = temp.objects.lock().expect("guest object state");
        if !directory.is_empty() && !objects.directories.contains(&directory) {
            return temp.fail(cpu.gs_base, PATH_NOT_FOUND, 0);
        }
        // The unique number: the guest's own when nonzero, else the next one.
        let mut number = args.r8 as u32;
        if number == 0 {
            objects.next_temp = objects.next_temp.max(1) + 1;
            number = objects.next_temp;
        }
        let name = format!("{prefix}{number:x}.tmp");
        let path = if directory.is_empty() {
            name.clone()
        } else {
            format!("{directory}\\{name}")
        };
        if !valid_component(&name) || objects.files.contains_key(&path) {
            return temp.fail(cpu.gs_base, FILE_EXISTS, 0);
        }
        if objects.files.len() >= MAX_FILES {
            return temp.fail(cpu.gs_base, DISK_FULL, 0);
        }
        objects.files.insert(path, Vec::new());
        let mut output = name.clone().into_bytes();
        output.push(0);
        if memory.write_bytes(args.r9, &output).is_err() {
            return temp.fail(cpu.gs_base, ERROR_NOACCESS, 0);
        }
        Ok(u64::from(number))
    });

    for (symbol, writing) in [("ReadFile", false), ("WriteFile", true)] {
        let state = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            if args.get(4, memory).map_err(ExitReason::MemoryFault)? != 0 {
                return state.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
            }
            let count = args.r8 as u32 as usize;
            if count > MAX_TRANSFER {
                return state.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
            }
            let pipe_end = {
                let objects = state.objects.lock().expect("guest object state");
                match objects.handles.get(&args.rcx) {
                    Some(GuestObject::Pipe {
                        state: pipe_state,
                        write,
                    }) => Some((Arc::clone(pipe_state), *write)),
                    _ => None,
                }
            };
            if let Some((pipe_state, is_write_end)) = pipe_end {
                if writing != is_write_end {
                    return state.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
                }
                if args.r9 == 0 || memory.check_write(args.r9, 4).is_err() {
                    return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                }
                let mut pipe = pipe_state.lock().expect("pipe state");
                let transferred = if writing {
                    if count == 0 {
                        0
                    } else {
                        if !pipe.read_open {
                            return state.fail(cpu.gs_base, 109, 0); // ERROR_BROKEN_PIPE
                        }
                        if pipe.buffer.len() + count > MAX_BYTES {
                            return state.fail(cpu.gs_base, ERROR_NOT_ENOUGH_MEMORY, 0);
                        }
                        let mut input = vec![0; count];
                        if args.rdx == 0 || memory.read_bytes(args.rdx, &mut input).is_err() {
                            return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                        }
                        pipe.buffer.extend(input);
                        count
                    }
                } else if pipe.buffer.is_empty() {
                    if pipe.write_open {
                        // A blocking read cannot be served: the guest would have
                        // to run for the pipe to fill, and it is the one waiting.
                        return state.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
                    }
                    0
                } else {
                    let transferred = count.min(pipe.buffer.len());
                    let mut output = vec![0; transferred];
                    for byte in output.iter_mut() {
                        *byte = pipe.buffer.pop_front().expect("bounded length");
                    }
                    if args.rdx == 0 || memory.write_bytes(args.rdx, &output).is_err() {
                        return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                    }
                    transferred
                };
                memory
                    .write_u32(args.r9, transferred as u32)
                    .map_err(ExitReason::MemoryFault)?;
                return Ok(1);
            }
            let mut objects = state.objects.lock().expect("guest object state");
            let super::ObjectState { handles, files, .. } = &mut *objects;
            let Some(GuestObject::File(file)) = handles.get_mut(&args.rcx) else {
                return state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            };
            let required = if writing { WRITE } else { READ };
            if file.access & required == 0 {
                return state.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
            }
            if file.directory {
                // A directory handle supports no transfer, exactly as on
                // Windows: the open exists to prove the entry and to close
                // again, never to read or write through.
                return state.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
            }
            if args.r9 == 0 || memory.check_write(args.r9, 4).is_err() {
                return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }

            if is_nul_path(&file.path) {
                // The NUL device: a write discards and reports the count, a
                // read is end of file, and neither touches the drive or even
                // the guest buffer - the device has no backing store.
                let transferred = if writing { count } else { 0 };
                memory
                    .write_u32(args.r9, transferred as u32)
                    .map_err(ExitReason::MemoryFault)?;
                return Ok(1);
            }
            let used = if writing {
                files.values().map(Vec::len).sum::<usize>()
            } else {
                0
            };
            let data = files.get_mut(&file.path).expect("open file exists");
            let position = file.position.load(Ordering::Relaxed);
            let transferred = if writing {
                if count == 0 {
                    0
                } else {
                    let Some(end) = position
                        .checked_add(count as u64)
                        .filter(|end| *end <= MAX_BYTES as u64)
                    else {
                        return state.fail(cpu.gs_base, DISK_FULL, 0);
                    };
                    let end = end as usize;
                    let growth = end.saturating_sub(data.len());
                    if growth > MAX_BYTES - used {
                        return state.fail(cpu.gs_base, DISK_FULL, 0);
                    }
                    let mut input = vec![0; count];
                    if args.rdx == 0 || memory.read_bytes(args.rdx, &mut input).is_err() {
                        return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                    }
                    if growth != 0 {
                        data.try_reserve_exact(growth)
                            .map_err(|_| ExitReason::MemoryFault(MemoryError::AllocationFailed))?;
                        data.resize(end, 0);
                    }
                    data[position as usize..end].copy_from_slice(&input);
                    count
                }
            } else {
                let start = position.min(data.len() as u64) as usize;
                let transferred = count.min(data.len() - start);
                if transferred != 0
                    && (args.rdx == 0
                        || memory
                            .write_bytes(args.rdx, &data[start..start + transferred])
                            .is_err())
                {
                    return state.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                }
                transferred
            };
            memory
                .write_u32(args.r9, transferred as u32)
                .map_err(ExitReason::MemoryFault)?;
            file.position
                .store(position + transferred as u64, Ordering::Relaxed);
            Ok(1)
        });
    }

    // The Ex forms take their 64-bit offset from the two DWORDs after
    // the Internal fields of the x64 OVERLAPPED. UnlockFileEx has no flags,
    // so its length and pointer arguments appear one place earlier.
    for (symbol, unlock, length_arg) in [("LockFileEx", false, 3), ("UnlockFileEx", true, 2)] {
        let lock_state = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let handle = args.rcx;
            let mut objects = lock_state.objects.lock().expect("guest object state");
            let path = match objects.handles.get(&handle) {
                Some(GuestObject::File(file)) if file.access & (READ | WRITE) != 0 => {
                    file.path.clone()
                }
                Some(GuestObject::File(_)) => {
                    return lock_state.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
                }
                _ => return lock_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
            };
            let overlapped = args
                .get(length_arg + 2, memory)
                .map_err(ExitReason::MemoryFault)?;
            let offsets = overlapped
                .checked_add(16)
                .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
            let offset = memory.read_u64(offsets).map_err(ExitReason::MemoryFault)?;
            let length = u64::from(
                args.get(length_arg + 1, memory)
                    .map_err(ExitReason::MemoryFault)? as u32,
            ) << 32
                | u64::from(
                    args.get(length_arg, memory)
                        .map_err(ExitReason::MemoryFault)? as u32,
                );
            let exclusive = !unlock && args.rdx & 2 != 0;
            let ranges = objects.locks.entry(path).or_default();
            match update_range_lock(ranges, handle, offset, length, exclusive, unlock) {
                Ok(()) => Ok(1),
                Err(error) => lock_state.fail(cpu.gs_base, error, 0),
            }
        });
    }

    for (symbol, unlock) in [("LockFile", false), ("UnlockFile", true)] {
        let lock_state = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            let handle = args.rcx;
            let mut objects = lock_state.objects.lock().expect("guest object state");
            let path = match objects.handles.get(&handle) {
                Some(GuestObject::File(file)) if file.access & (READ | WRITE) != 0 => {
                    file.path.clone()
                }
                Some(GuestObject::File(_)) => {
                    return lock_state.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
                }
                _ => return lock_state.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
            };
            let offset = (args.r8 as u32 as u64) << 32 | args.rdx as u32 as u64;
            let length = (args.get(4, memory).map_err(ExitReason::MemoryFault)? as u32 as u64)
                << 32
                | args.r9 as u32 as u64;
            let ranges = objects.locks.entry(path).or_default();
            match update_range_lock(ranges, handle, offset, length, true, unlock) {
                Ok(()) => Ok(1),
                Err(error) => lock_state.fail(cpu.gs_base, error, 0),
            }
        });
    }

    // The CRT file-system services the runtime library links against
    // `ucrtbase.dll`. `_fullpath` is GetFullPathName of the narrow form with
    // the CRT contract: a null buffer means the caller wants a heap copy it
    // frees, an empty or invalid path sets EINVAL, and a buffer that is too
    // small - or a result longer than the 260 characters a null buffer gets -
    // sets ERANGE. The display form is lowercase because the drive's names
    // are case-folded.
    let fullpath_state = Arc::clone(state);
    registry.register(UCRT, "_fullpath", move |args, cpu, memory| {
        let fail = |memory: &mut GuestMemory, error: u32| -> Result<u64, ExitReason> {
            super::crt::set_errno(memory, cpu.gs_base, error)?;
            Ok(0)
        };
        let Some(name) = read_guest_path_a(memory, args.rdx).map_err(ExitReason::MemoryFault)?
        else {
            return fail(memory, super::crt_files::EINVAL);
        };
        let cwd = fullpath_state.crt_streams().working_directory();
        let Some(resolved) = full_name(&cwd, &name) else {
            return fail(memory, super::crt_files::EINVAL);
        };
        // `full_name` already answers the machine's display form - the
        // lowercase drive letter the case-folded drive uses everywhere.
        let full_path = resolved;
        let bytes = full_path.as_bytes();
        let needed = bytes.len() + 1;
        let buffer = if args.rcx == 0 {
            if needed > 260 {
                return fail(memory, super::crt_files::ERANGE);
            }
            match memory.map_heap_allocation(crate::memory::PROCESS_HEAP, needed.max(1)) {
                Ok(address) if address != 0 => address,
                _ => return fail(memory, super::crt_files::ENOMEM),
            }
        } else {
            if args.r8 < needed as u64 {
                return fail(memory, super::crt_files::ERANGE);
            }
            args.rcx
        };
        if memory.write_bytes(buffer, bytes).is_err()
            || memory.write_u8(buffer + bytes.len() as u64, 0).is_err()
        {
            return fail(memory, super::crt_files::ENOMEM);
        }
        Ok(buffer)
    });

    // The CRT search is the same snapshot the kernel32 search hands out;
    // only the record layout and the error channel differ: errno and -1
    // instead of GetLastError and INVALID_HANDLE_VALUE. A search that finds
    // nothing sets ENOENT.
    let crt_first = Arc::clone(state);
    registry.register(UCRT, "_findfirst64i32", move |args, cpu, memory| {
        let Some(path) = read_guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)?
        else {
            super::crt::set_errno(memory, cpu.gs_base, super::crt_files::EINVAL)?;
            return Ok(u64::MAX);
        };
        match find_first(
            &crt_first,
            memory,
            &path,
            args.rdx,
            crt_write_finddata64i32,
            0,
        ) {
            Ok(handle) => Ok(handle),
            Err(code) => {
                let errno = match code {
                    FILE_NOT_FOUND | PATH_NOT_FOUND => super::crt_files::ENOENT,
                    ERROR_NOACCESS => super::crt_files::EACCES,
                    ERROR_NOT_ENOUGH_MEMORY => super::crt_files::ENOMEM,
                    _ => super::crt_files::EINVAL,
                };
                super::crt::set_errno(memory, cpu.gs_base, errno)?;
                Ok(u64::MAX)
            }
        }
    });

    let crt_next = Arc::clone(state);
    registry.register(UCRT, "_findnext64i32", move |args, cpu, memory| {
        let error = {
            let mut objects = crt_next.objects.lock().expect("guest object state");
            let Some(GuestObject::Search(search)) = objects.handles.get_mut(&args.rcx) else {
                super::crt::set_errno(memory, cpu.gs_base, super::crt_files::EINVAL)?;
                return Ok(u64::MAX);
            };
            let Some(entry) = search.entries.get(search.next) else {
                drop(objects);
                super::crt::set_errno(memory, cpu.gs_base, super::crt_files::ENOENT)?;
                return Ok(u64::MAX);
            };
            if crt_write_finddata64i32(memory, args.rdx, entry).is_err() {
                Some(super::crt_files::EACCES)
            } else {
                search.next += 1;
                None
            }
        };
        if let Some(error) = error {
            super::crt::set_errno(memory, cpu.gs_base, error)?;
            return Ok(u64::MAX);
        }
        Ok(0)
    });

    let crt_close = Arc::clone(state);
    registry.register(UCRT, "_findclose", move |args, cpu, memory| {
        let mut objects = crt_close.objects.lock().expect("guest object state");
        if !matches!(objects.handles.get(&args.rcx), Some(GuestObject::Search(_))) {
            drop(objects);
            super::crt::set_errno(memory, cpu.gs_base, super::crt_files::EBADF)?;
            return Ok(u64::MAX);
        }
        objects.handles.remove(&args.rcx);
        Ok(0)
    });

    for symbol in [
        "_fullpath",
        "_findfirst64i32",
        "_findnext64i32",
        "_findclose",
    ] {
        registry.alias(CRT_FILESYSTEM_API, UCRT, symbol);
        registry.set_status(UCRT, symbol, ServiceStatus::Partial);
    }

    let peek = Arc::clone(state);
    registry.register(KERNEL32, "PeekNamedPipe", move |args, cpu, memory| {
        // The pipe is never copied out through the data argument here: the
        // hosted caller peeks to know how much there is, not to take it early.
        let pipe_end = {
            let objects = peek.objects.lock().expect("guest object state");
            match objects.handles.get(&args.rcx) {
                Some(GuestObject::Pipe { state, write }) => Some((Arc::clone(state), *write)),
                Some(_) => None,
                None => return peek.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
            }
        };
        let Some((pipe_state, is_write_end)) = pipe_end else {
            return peek.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        };
        if is_write_end {
            return peek.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
        }
        let pipe = pipe_state.lock().expect("pipe state");
        // An empty pipe reports broken once no write can arrive: the write
        // end closed, or it is open only in processes that stay suspended
        // while this one runs - the synchronous process world means the
        // block a reader would enter here can never lift. A process polling
        // a pipe it writes itself later in the same run is the documented
        // approximation, as the pipe reads are.
        if pipe.buffer.is_empty() {
            drop(pipe);
            return peek.fail(cpu.gs_base, 109, 0); // ERROR_BROKEN_PIPE
        }
        let available = pipe.buffer.len() as u32;
        // lpBytesRead is the number of bytes copied into the caller's buffer:
        // nothing leaves the pipe, the copy is a look at the front bytes.
        let copied = if args.rdx != 0 && args.r8 != 0 {
            let take = (args.r8 as u32).min(available) as usize;
            let bytes: Vec<u8> = pipe.buffer.iter().take(take).copied().collect();
            if memory.write_bytes(args.rdx, &bytes).is_err() {
                return peek.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            take as u32
        } else {
            0
        };
        if args.r9 != 0 {
            memory
                .write_u32(args.r9, copied)
                .map_err(ExitReason::MemoryFault)?;
        }
        let total = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
        if total != 0 {
            memory
                .write_u32(total, available)
                .map_err(ExitReason::MemoryFault)?;
        }
        let left = args.get(5, memory).map_err(ExitReason::MemoryFault)?;
        if left != 0 {
            memory.write_u32(left, 0).map_err(ExitReason::MemoryFault)?;
        }
        Ok(1)
    });

    // The drive the hosted machine has: one fixed disk, letter C, large and
    // empty enough that the exact numbers do not matter to a correct program.
    registry.register(KERNEL32, "GetLogicalDrives", |_, _, _| Ok(1 << 2));
    for symbol in ["GetDriveTypeA", "GetDriveTypeW"] {
        registry.register(KERNEL32, symbol, |_, _, _| {
            // Whatever the path, the machine's drives are the one fixed disk:
            // DRIVE_FIXED is 3.
            Ok(3)
        });
    }
    for symbol in ["GetDiskFreeSpaceExA", "GetDiskFreeSpaceExW"] {
        let space = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            // The three output counts are 64-bit integers the caller reads as
            // ULARGE_INTEGER: free to the user, total, free in total. A memory
            // drive of one gigabyte with no quota difference.
            let gig = 1u64 << 30;
            // The three outputs are the register parameters rdx, r8 and r9:
            // free to the caller, total bytes, total free bytes.
            for pointer in [args.rdx, args.r8, args.r9] {
                if pointer == 0 {
                    continue;
                }
                if memory.check_write(pointer, 8).is_err() {
                    return space.fail(cpu.gs_base, ERROR_NOACCESS, 0);
                }
                memory
                    .write_u64(pointer, gig)
                    .map_err(ExitReason::MemoryFault)?;
            }
            if args.rdx == 0 && args.r8 == 0 && args.r9 == 0 {
                return space.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            Ok(1)
        });
    }

    let info = Arc::clone(state);
    registry.register(KERNEL32, "SetHandleInformation", move |args, cpu, _| {
        // The inheritance and protect-from-close flags are accepted and not
        // stored: there is no child process to inherit into, and closing is
        // the guest's own choice. What the call can still do is refuse an
        // unknown handle, as documented.
        let objects = info.objects.lock().expect("guest object state");
        if objects.handles.contains_key(&args.rcx) {
            Ok(1)
        } else {
            info.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0)
        }
    });

    let size = Arc::clone(state);
    registry.register(KERNEL32, "GetFileSize", move |args, cpu, memory| {
        let objects = size.objects.lock().expect("guest object state");
        let Some(GuestObject::File(file)) = objects.handles.get(&args.rcx) else {
            // The documented failure value is 0xFFFFFFFF, like a 4 GiB low
            // word: the last error tells the two apart.
            return size.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0xFFFF_FFFF);
        };
        let length = objects
            .files
            .get(&file.path)
            .map(Vec::len)
            .unwrap_or_default() as u64;
        if args.rdx != 0 {
            if memory.check_write(args.rdx, 4).is_err() {
                return size.fail(cpu.gs_base, ERROR_NOACCESS, 0xFFFF_FFFF);
            }
            memory
                .write_u32(args.rdx, (length >> 32) as u32)
                .map_err(ExitReason::MemoryFault)?;
        }
        Ok(length & 0xFFFF_FFFF)
    });

    let compressed = Arc::clone(state);
    registry.register(
        KERNEL32,
        "GetCompressedFileSizeA",
        move |args, cpu, memory| {
            // Nothing on the drive is compressed: the compressed size is the
            // size, and the high word of a memory drive's file is always zero.
            let Some(path) = guest_path_a(memory, args.rcx).map_err(ExitReason::MemoryFault)?
            else {
                return compressed.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            let objects = compressed.objects.lock().expect("guest object state");
            let Some(data) = objects.files.get(&path) else {
                return compressed.fail(cpu.gs_base, FILE_NOT_FOUND, 0xFFFF_FFFF);
            };
            let length = data.len() as u64;
            if args.rdx != 0 {
                if memory.check_write(args.rdx, 4).is_err() {
                    return compressed.fail(cpu.gs_base, ERROR_NOACCESS, 0xFFFF_FFFF);
                }
                memory
                    .write_u32(args.rdx, (length >> 32) as u32)
                    .map_err(ExitReason::MemoryFault)?;
            }
            Ok(length & 0xFFFF_FFFF)
        },
    );

    let flush = Arc::clone(state);
    registry.register(KERNEL32, "FlushFileBuffers", move |args, cpu, _| {
        let objects = flush.objects.lock().expect("guest object state");
        let file = match objects.handles.get(&args.rcx) {
            Some(GuestObject::File(file)) => file,
            _ => return flush.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
        };
        if file.access & WRITE == 0 {
            return flush.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
        }
        // The drive is memory: a write has nowhere further to be flushed to.
        Ok(1)
    });

    let types = Arc::clone(state);
    registry.register(KERNEL32, "GetFileType", move |args, cpu, _| {
        // The console handles answer FILE_TYPE_CHAR whether or not a mode was
        // ever queried, as a real console does.
        if matches!(args.rcx, 0x101..=0x103) {
            return Ok(2); // FILE_TYPE_CHAR
        }
        let objects = types.objects.lock().expect("guest object state");
        match objects.handles.get(&args.rcx) {
            Some(GuestObject::File(file)) if is_nul_path(&file.path) => Ok(2), // FILE_TYPE_CHAR
            Some(GuestObject::File(_)) => Ok(1),                               // FILE_TYPE_DISK
            Some(GuestObject::Pipe { .. }) => Ok(3),                           // FILE_TYPE_PIPE
            Some(_) => {
                // A handle that is not a file has no type the file API knows.
                Ok(0) // FILE_TYPE_UNKNOWN
            }
            None => types
                .fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0u32)
                .map(|_: u32| 0),
        }
    });

    // GetFileAttributesEx packs the attributes with the times and size.
    // The drive tracks no times: they answer the Unix epoch, a fixed valid
    // time rather than an invented one.
    for (symbol, narrow) in [
        ("GetFileAttributesExW", false),
        ("GetFileAttributesExA", true),
    ] {
        let attributes_ex = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, memory| {
            // Only GetFileExInfoStandard (0) exists.
            if args.rdx != 0 {
                return attributes_ex.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
            }
            let reader = if narrow {
                read_guest_path_a
            } else {
                read_guest_path
            };
            let Some(raw) = reader(memory, args.rcx).map_err(ExitReason::MemoryFault)? else {
                return attributes_ex.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            let Some(path) = resolve_bare_path(&attributes_ex, &raw) else {
                return attributes_ex.fail(cpu.gs_base, INVALID_NAME, 0);
            };
            if args.r8 == 0 {
                return attributes_ex.fail(cpu.gs_base, ERROR_NOACCESS, 0);
            }
            let objects = attributes_ex.objects.lock().expect("guest object state");
            let (attributes, size) = if path.is_empty() || objects.directories.contains(&path) {
                // The empty key is the volume root, which always is a directory.
                (0x10u32, 0u64)
            } else if let Some(content) = objects.files.get(&path) {
                (0x80u32, content.len() as u64)
            } else {
                let parent = parent(&path);
                let error = if parent.is_empty() || objects.directories.contains(parent) {
                    FILE_NOT_FOUND
                } else {
                    PATH_NOT_FOUND
                };
                return attributes_ex.fail(cpu.gs_base, error, 0);
            };
            memory
                .write_u32(args.r8, attributes)
                .map_err(ExitReason::MemoryFault)?;
            // Three FILETIMEs - creation, access, write - the times the
            // drive tracks for the file, or the fixed Unix epoch for one it
            // does not know.
            let times = objects
                .file_times
                .get(&path)
                .copied()
                .unwrap_or(EPOCH_FILETIME3);
            for (slot, offset) in [4u64, 12, 20].into_iter().enumerate() {
                memory
                    .write_u64(args.r8 + offset, times[slot])
                    .map_err(ExitReason::MemoryFault)?;
            }
            memory
                .write_u32(args.r8 + 28, (size >> 32) as u32)
                .map_err(ExitReason::MemoryFault)?;
            memory
                .write_u32(args.r8 + 32, size as u32)
                .map_err(ExitReason::MemoryFault)?;
            Ok(1)
        });
    }

    // IsDBCSLeadByteEx: every code page the machine serves - UTF-8 and the
    // documented Western pages 1252/437 - is either single-byte or UTF-8,
    // neither of which has DBCS lead bytes. False is the correct answer for
    // every byte, not a stub.
    let lead_byte = Arc::clone(state);
    registry.register(KERNEL32, "IsDBCSLeadByteEx", move |args, cpu, memory| {
        let _ = memory;
        let _ = args;
        let _ = cpu;
        let _ = &lead_byte;
        Ok(0)
    });

    // SetFileTime writes the times the drive now tracks: each non-null
    // FILETIME pointer replaces its slot of the file's creation, access and
    // write times, exactly as Windows does. SetSystemTime would move the
    // injected clock for the one process, machinery the machine does not
    // have.
    let set_file_time = Arc::clone(state);
    registry.register(KERNEL32, "SetFileTime", move |args, cpu, memory| {
        let mut objects = set_file_time.objects.lock().expect("guest object state");
        let Some(GuestObject::File(file)) = objects.handles.get(&args.rcx) else {
            return set_file_time.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
        };
        if file.open_access & (WRITE | WRITE_ATTRIBUTES) == 0 {
            return set_file_time.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
        }
        let path = file.path.clone();
        let mut times = objects
            .file_times
            .get(&path)
            .copied()
            .unwrap_or(EPOCH_FILETIME3);
        let mut read_error = false;
        for (index, pointer) in [args.rdx, args.r8, args.r9].into_iter().enumerate() {
            if pointer == 0 {
                continue;
            }
            match memory.read_u64(pointer) {
                Ok(value) => times[index] = value,
                Err(_) => read_error = true,
            }
        }
        if read_error {
            return set_file_time.fail(cpu.gs_base, ERROR_NOACCESS, 0);
        }
        objects.file_times.insert(path, times);
        drop(objects);
        Ok(1)
    });
    let set_system_time = Arc::clone(state);
    registry.register(KERNEL32, "SetSystemTime", move |args, cpu, memory| {
        let _ = (args, memory);
        set_system_time.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0)
    });

    // DeviceIoControl needs device drivers the machine does not have. The
    // handle validates - a bad handle is a bad handle - and every control
    // code is honestly unsupported rather than silently ignored.
    let device_control = Arc::clone(state);
    registry.register(KERNEL32, "DeviceIoControl", move |args, cpu, memory| {
        let _ = memory;
        {
            let objects = device_control.objects.lock().expect("guest object state");
            if !objects.handles.contains_key(&args.rcx) {
                return device_control.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0);
            }
        }
        device_control.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0)
    });

    for symbol in [
        "CreateFileW",
        "GetFileSizeEx",
        "ReadFile",
        "WriteFile",
        "SetFilePointerEx",
        "SetEndOfFile",
        "CreateDirectoryW",
        "RemoveDirectoryW",
        "DeleteFileW",
        "GetFileAttributesW",
        "MoveFileW",
        "FindFirstFileW",
        "FindNextFileW",
        "FindClose",
        "CreateDirectoryA",
        "RemoveDirectoryA",
        "MoveFileA",
        "CopyFileW",
        "CopyFileA",
        "FindFirstFileA",
        "FindNextFileA",
        "GetFullPathNameW",
        "GetFullPathNameA",
        "GetFileInformationByHandle",
        "SetFileAttributesW",
        "SetFilePointer",
        "GetTempFileNameA",
        "AreFileApisANSI",
        "SetFileApisToANSI",
        "SetFileApisToOEM",
        "GetDiskFreeSpaceA",
        "GetDiskFreeSpaceW",
        "LockFile",
        "UnlockFile",
        "LockFileEx",
        "UnlockFileEx",
        "FlushFileBuffers",
        "GetFileType",
        "FindFirstVolumeW",
        "FindFirstVolumeA",
        "FindNextVolumeW",
        "FindNextVolumeA",
        "FindVolumeClose",
        "GetVolumeInformationW",
        "GetVolumeInformationA",
        "GetVolumeNameForVolumeMountPointW",
        "GetVolumeNameForVolumeMountPointA",
        "GetVolumePathNamesForVolumeNameW",
        "GetVolumePathNamesForVolumeNameA",
        "GetFileAttributesExW",
        "GetFileAttributesExA",
        "UnlockFile",
        "IsDBCSLeadByteEx",
        "SetFileTime",
        "SetSystemTime",
        "DeviceIoControl",
    ] {
        registry.alias(FILE_API, KERNEL32, symbol);
        registry.set_status(KERNEL32, symbol, ServiceStatus::Partial);
    }
}

/// The shared state of one anonymous pipe: the bytes written and not yet read,
/// plus which ends are still open, so a read can tell a temporary empty pipe
/// from the end of the stream. The buffer is bounded like every guest object.
#[derive(Default)]
pub(super) struct PipeState {
    pub buffer: std::collections::VecDeque<u8>,
    pub write_open: bool,
    /// The mirror of `write_open` on the read side: once the last reference
    /// to the read end closes anywhere, writes fail broken instead of
    /// buffering forever, exactly as ERROR_BROKEN_PIPE reaches a Windows
    /// writer whose reader is gone.
    pub read_open: bool,
}

/// What a path names on the drive, for the C runtime's file streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DriveEntry {
    File,
    Directory,
    /// Nothing has this name. `parent` says whether its directory exists.
    Missing {
        parent: bool,
    },
}

/// The drive as the C runtime's file streams (`crt_files.rs`) use it. They read
/// and write the same files as the handle services above. A stream is not a
/// handle: it takes no part in sharing, and a file it has open can be deleted
/// or moved, after which its operations fail.
impl super::ObjectState {
    /// A narrow file name as the drive stores it: ASCII, either slash, any
    /// case, with or without `C:\`. `None` for a name the drive rejects.
    pub(super) fn drive_path(name: &[u8]) -> Option<String> {
        if !name.is_ascii() {
            return None;
        }
        let path = String::from_utf8_lossy(name)
            .replace('/', "\\")
            .to_ascii_lowercase();
        let path = path.strip_prefix("c:\\").unwrap_or(&path);
        // The empty string is no path at all, while a path of dot components
        // - or the root anchor itself - resolves to the root, which is valid.
        if path.is_empty() {
            return None;
        }
        let path = resolve_dots(strip_root_anchor(path));
        // A trailing separator is the directory marker of the Windows path
        // grammar: `dir\` names `dir`, as mkdir -p and a hundred shell
        // idioms depend on. The empty components it leaves are not part of
        // the key. The file edge - a trailing separator on a file stays
        // acceptable here where Windows refuses it - is documented rather
        // than modeled, as no caller depends on the refusal.
        let path = path.trim_end_matches('\\').to_owned();
        valid_key(&path).then_some(path)
    }

    pub(super) fn drive_entry(&self, path: &str) -> DriveEntry {
        if self.files.contains_key(path) {
            DriveEntry::File
        } else if path.is_empty() || self.directories.contains(path) {
            // The empty key is the root, which always exists.
            DriveEntry::Directory
        } else {
            let parent = parent(path);
            DriveEntry::Missing {
                parent: parent.is_empty() || self.directories.contains(parent),
            }
        }
    }

    /// Create a directory, as `_mkdir` does: the parent has to exist, the
    /// name has to be free, and the drive holds at most its many. The errno
    /// is the caller's mapping of the false.
    pub(super) fn drive_mkdir(&mut self, path: &str) -> Result<(), u32> {
        let parent = parent(path);
        if !parent.is_empty() && !self.directories.contains(parent) {
            return Err(ENOENT);
        }
        if self.directories.contains(path) || self.files.contains_key(path) {
            return Err(EEXIST);
        }
        if self.directories.len() >= MAX_DIRECTORIES {
            return Err(ENOSPC);
        }
        self.directories.insert(path.to_owned());
        Ok(())
    }

    /// Remove an empty directory, as `_rmdir` does: nothing it holds may
    /// remain, file or directory.
    pub(super) fn drive_rmdir(&mut self, path: &str) -> Result<(), u32> {
        if !self.directories.contains(path) {
            return Err(ENOENT);
        }
        if self.directories.iter().any(|key| parent(key) == path)
            || self.files.keys().any(|key| parent(key) == path)
        {
            return Err(EEXIST);
        }
        self.directories.remove(path);
        Ok(())
    }

    /// Create an empty file. False when the drive already holds as many files
    /// as it can.
    pub(super) fn drive_create(&mut self, path: &str) -> bool {
        if self.files.len() >= MAX_FILES {
            return false;
        }
        self.files.insert(path.to_owned(), Vec::new());
        true
    }

    pub(super) fn drive_file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    pub(super) fn drive_is_readonly(&self, path: &str) -> bool {
        self.readonly.contains(path)
    }

    /// `_wchmod`: set or clear the read-only mark of a file the drive holds.
    pub(super) fn drive_chmod(&mut self, path: &str, readonly: bool) -> bool {
        if !self.files.contains_key(path) {
            return false;
        }
        if readonly {
            self.readonly.insert(path.to_owned());
        } else {
            self.readonly.remove(path);
        }
        true
    }

    /// Create a directory. False when the parent is missing, the name is
    /// taken or the drive holds all the directories it can.
    pub(super) fn drive_create_dir(&mut self, path: &str) -> bool {
        let parent = parent(path);
        if self.directories.len() >= MAX_DIRECTORIES
            || (!parent.is_empty() && !self.directories.contains(parent))
            || self.directories.contains(path)
            || self.files.contains_key(path)
        {
            return false;
        }
        self.directories.insert(path.to_owned());
        true
    }

    /// Delete a file. False when it does not exist. Streams that have it
    /// open keep their path, so their operations fail afterwards.
    pub(super) fn drive_remove(&mut self, path: &str) -> bool {
        if self.readonly.contains(path) {
            return false;
        }
        if self.files.remove(path).is_some() {
            self.file_times.remove(path);
            true
        } else {
            false
        }
    }

    /// Give a file a new name. The caller has checked that `from` is a file
    /// and that `to` names nothing yet in an existing directory.
    pub(super) fn drive_rename(&mut self, from: &str, to: &str) {
        if let Some(data) = self.files.remove(from) {
            self.files.insert(to.to_owned(), data);
        }
        if let Some(times) = self.file_times.remove(from) {
            self.file_times.insert(to.to_owned(), times);
        }
    }

    /// Empty a file. False when it does not exist.
    pub(super) fn drive_truncate(&mut self, path: &str) -> bool {
        if self.readonly.contains(path) {
            return false;
        }
        self.files.get_mut(path).map(Vec::clear).is_some()
    }

    /// Write `bytes` at `position`, growing the file as needed. `None` when
    /// the file does not exist; `Some(false)`, with nothing written, when the
    /// write would pass the drive's size bound.
    pub(super) fn drive_write(&mut self, path: &str, position: u64, bytes: &[u8]) -> Option<bool> {
        if self.readonly.contains(path) {
            return Some(false);
        }
        let used: usize = self.files.values().map(Vec::len).sum();
        let data = self.files.get_mut(path)?;
        let Some(end) = position
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= MAX_BYTES as u64)
        else {
            return Some(false);
        };
        let (start, end) = (position as usize, end as usize);
        let growth = end.saturating_sub(data.len());
        if growth > MAX_BYTES - used {
            return Some(false);
        }
        if growth != 0 {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(bytes);
        Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::ObjectState;
    use super::{read_guest_path, read_guest_path_a};
    use crate::memory::GuestMemory;

    fn narrow_at(memory: &mut GuestMemory, address: u64, text: &str) {
        memory.write_bytes(address, text.as_bytes()).expect("write");
        memory
            .write_u8(address + text.len() as u64, 0)
            .expect("terminator");
    }

    fn mapped_memory() -> GuestMemory {
        let mut memory = GuestMemory::new();
        memory
            .map_region(0x1000, 0x1000, crate::memory::MemoryPermissions::READ_WRITE)
            .expect("map");
        memory
    }

    /// A drive-rooted path keeps its anchor through the kernel32 path
    /// readers exactly as it does on Windows: `c:\f` is absolute, so it
    /// reads as the rooted `\f` rather than the relative `f` - which would
    /// resolve against the working directory and stop resolving the moment
    /// the process leaves its start directory. busybox-w32 stats its own
    /// executable through this very path before every spawn, and the spawn
    /// broke after `cd` because the absolute answer of GetModuleFileName
    /// lost its anchor here (#1342).
    #[test]
    fn drive_rooted_paths_keep_their_anchor_through_the_readers() {
        let mut memory = mapped_memory();
        narrow_at(&mut memory, 0x1000, "c:\\d\\f");
        assert_eq!(
            read_guest_path_a(&memory, 0x1000).expect("read"),
            Some("\\d\\f".to_owned())
        );
        narrow_at(&mut memory, 0x1100, "C:/d/f");
        assert_eq!(
            read_guest_path_a(&memory, 0x1100).expect("read"),
            Some("\\d\\f".to_owned())
        );
        // A relative name keeps no anchor, so the working directory still
        // reaches it.
        narrow_at(&mut memory, 0x1200, "d\\f");
        assert_eq!(
            read_guest_path_a(&memory, 0x1200).expect("read"),
            Some("d\\f".to_owned())
        );
        // An already-rooted name is unchanged, as is a drive-relative one.
        narrow_at(&mut memory, 0x1300, "\\d\\f");
        assert_eq!(
            read_guest_path_a(&memory, 0x1300).expect("read"),
            Some("\\d\\f".to_owned())
        );
        // The wide reader canonicalises the same way.
        let wide: Vec<u16> = "c:\\d\\f".encode_utf16().collect();
        for (index, unit) in wide.iter().enumerate() {
            memory
                .write_u16(0x1400 + index as u64 * 2, *unit)
                .expect("write");
        }
        memory
            .write_u16(0x1400 + wide.len() as u64 * 2, 0)
            .expect("terminator");
        assert_eq!(
            read_guest_path(&memory, 0x1400).expect("read"),
            Some("\\d\\f".to_owned())
        );
    }

    /// The trailing separator of the Windows path grammar: `dir/` names
    /// `dir`, as the shell's mkdir -p idiom depends on when it creates
    /// parents through the slashed form (#1270).
    #[test]
    fn drive_path_collapses_trailing_separators_to_the_directory_key() {
        assert_eq!(
            ObjectState::drive_path(b"u/").as_deref(),
            ObjectState::drive_path(b"u").as_deref()
        );
        assert_eq!(
            ObjectState::drive_path(b"a/b/").as_deref(),
            ObjectState::drive_path(b"a\\b").as_deref()
        );
        // A bare separator resolves to the root rather than vanishing into
        // an invalid key.
        assert_eq!(ObjectState::drive_path(b"/").as_deref(), Some(""));
    }

    /// mkdir of an existing directory is EEXIST, as the CRT contract busybox
    /// keys its -p continuation on (#1270).
    #[test]
    fn drive_mkdir_of_an_existing_directory_is_eexist() {
        let mut drive = ObjectState::default();
        drive.drive_mkdir("u").expect("first mkdir");
        assert_eq!(drive.drive_mkdir("u"), Err(super::super::crt_files::EEXIST));
    }
}
