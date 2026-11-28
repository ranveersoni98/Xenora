// SPDX-License-Identifier: GPL-3.0-or-later

//! Guest virtual memory model for Xenora's x86-64 execution bootstrap.
//!
//! Provides isolated, page-aligned guest virtual memory with permission checking
//! (Read, Write, Execute) and bounds enforcement without host OS mapping tricks.

use std::{fmt, ops::Range};

pub(crate) const ALLOCATION_GRANULARITY: u64 = 65_536;

/// Permission flags for a mapped memory region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryPermissions {
    pub const NO_ACCESS: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const READ_WRITE_EXECUTE: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

/// Errors occurring during guest memory operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryError {
    UnmappedAddress(u64),
    PermissionViolation {
        address: u64,
        required: &'static str,
    },
    OverlappingRegion {
        base: u64,
        size: u64,
    },
    Overflow,
    AllocationFailed,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmappedAddress(addr) => write!(f, "unmapped guest address 0x{addr:016x}"),
            Self::PermissionViolation { address, required } => {
                write!(
                    f,
                    "permission violation at guest address 0x{address:016x}: requires {required}"
                )
            }
            Self::OverlappingRegion { base, size } => {
                write!(
                    f,
                    "overlapping memory region: base 0x{base:016x}, size 0x{size:x}"
                )
            }
            Self::Overflow => write!(f, "guest memory address calculation overflow"),
            Self::AllocationFailed => write!(f, "guest memory allocation exceeds allowed limit"),
        }
    }
}

impl std::error::Error for MemoryError {}

pub(crate) const PROCESS_HEAP: u64 = u64::MAX - 2;

/// Page-granular commit size for a heap allocation of `size` requested
/// bytes. A zero request stays a zero-length marker, as before: no byte of
/// it is ever legimiately accessible, so the arena slack means nothing to
/// it, and the empty-marker layouts the memory model supports stay
/// representable.
fn heap_commit(size: usize) -> usize {
    if size == 0 {
        return 0;
    }
    size.checked_add(4095)
        .map(|padded| padded / 4096 * 4096)
        .unwrap_or(size)
}
const MAX_DYNAMIC_BYTES: usize = 64 * 1024 * 1024;
/// Host storage bound for each dynamic allocation kind.
pub(crate) const DYNAMIC_BUDGET: u64 = MAX_DYNAMIC_BYTES as u64;
/// How many regions at the front of the table a lookup checks in order before
/// it searches: a program's image and the first mappings are usually there,
/// and a short scan is faster than a search over a small table. Four was the
/// fastest of 0, 4 and 8 in `region_lookup_timing` on an Apple M1 Max (#102).
const FRONT_SCAN: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AllocationKind {
    ImageOrStatic,
    Virtual,
    /// Memory returned by `xmem.dll!XMemAlloc`; it shares the virtual-memory
    /// budget but has a distinct ownership domain from `VirtualAlloc`.
    Xmem,
    Heap(u64),
    /// Stack, guard or TEB of a guest thread; only the scheduler frees it.
    Thread,
}

#[derive(Clone)]
struct MappedRegion {
    base: u64,
    data: Vec<u8>,
    permissions: MemoryPermissions,
    allocation: AllocationKind,
    /// Base of the initial allocation this region came from. Splitting a
    /// region for `VirtualProtect` preserves it, so adjacent but independent
    /// allocations remain distinct ownership domains.
    allocation_base: u64,
}

/// Why a requested protection change was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtectionError {
    Overflow,
    Unmapped(u64),
    CrossesAllocations,
    UnsupportedAllocation,
}

/// Committed-memory attributes exposed to the virtual-memory services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedRegionInfo {
    pub(crate) base: u64,
    pub(crate) end: u64,
    pub(crate) allocation_base: u64,
    pub(crate) permissions: MemoryPermissions,
    pub(crate) image: bool,
}

impl MappedRegion {
    fn contains(&self, address: u64, size: usize) -> bool {
        let size_u64 = size as u64;
        let Some(end) = address.checked_add(size_u64) else {
            return false;
        };
        let region_end = self.base + self.data.len() as u64;
        address >= self.base && end <= region_end
    }
}

/// Where the program's own image is: its handle, size and entry point.
#[derive(Clone, Copy)]
pub(crate) struct MainImage {
    pub(crate) base: u64,
    pub(crate) size: u32,
    pub(crate) entry_point: u64,
}

/// Guest virtual memory address space.
#[derive(Default, Clone)]
pub struct GuestMemory {
    regions: Vec<MappedRegion>,
    /// Exact requested size of each live heap allocation, keyed by its base.
    /// Heap commits are page granular (see `map_heap_allocation`), so the
    /// region length is the commit, not the size the guest asked for; the
    /// Win32 heap APIs report the requested size.
    heap_exact_bytes: std::collections::HashMap<u64, usize>,
    /// Complete `[base, end)` spans retained for explicit module images. The
    /// committed headers and sections remain ordinary regions inside these
    /// spans; the records themselves cost no per-byte backing and exist so
    /// later allocations cannot reuse the uncommitted holes.
    module_reservations: Vec<(u64, u64)>,
    private_heaps: std::collections::BTreeSet<u64>,
    private_heap_serial: u64,
    // Stable errno pointers indexed by the guest thread's TEB address.
    crt_errno: std::collections::BTreeMap<u64, u64>,
    pub(crate) callback_frames:
        std::collections::BTreeMap<(u64, u64), crate::imports::CallbackFrame>,
    /// The program's image, for module services.
    pub(crate) main_image: Option<MainImage>,
    /// Function tables of the mapped images, for exception dispatch.
    pub(crate) function_tables: Vec<crate::exceptions::FunctionTable>,
    /// Exception dispatches waiting for a guest handler, by TEB and stack slot.
    pub(crate) exception_frames:
        std::collections::BTreeMap<(u64, u64), crate::exceptions::Dispatch>,
    /// `__C_specific_handler` calls waiting for a guest filter or termination
    /// handler, by TEB and stack slot.
    pub(crate) scope_frames: std::collections::BTreeMap<(u64, u64), crate::exceptions::ScopeWalk>,
    /// The unmapped address the last failed checked write stopped at. A data
    /// fault at this address was a write, which an access-violation record
    /// reports; [`MemoryError::UnmappedAddress`] does not say.
    pub(crate) write_fault: Option<u64>,
    /// The filter `SetUnhandledExceptionFilter` stored, or 0 for none. One
    /// filter serves every guest thread of the process.
    pub(crate) unhandled_filter: u64,
    /// The guest time-stamp counter: the value the next RDTSC reads. One
    /// counter serves every guest thread of the process. It lives here, not in
    /// `CpuState`, because exception dispatch restores earlier register
    /// snapshots, which would move a per-register counter backward.
    time_stamp_counter: u64,
}

impl GuestMemory {
    /// Create a new empty guest address space.
    pub fn new() -> Self {
        Self::default()
    }

    /// The value the next RDTSC reads. It is 0 when the address space is
    /// created. Only RDTSC and [`GuestMemory::advance_time_stamp_counter_to`]
    /// change it; no host timer is read.
    pub fn time_stamp_counter(&self) -> u64 {
        self.time_stamp_counter
    }

    /// Move the guest time-stamp counter forward to `value`. A value at or
    /// below the current one changes nothing, so this never moves it backward.
    pub fn advance_time_stamp_counter_to(&mut self, value: u64) {
        self.time_stamp_counter = self.time_stamp_counter.max(value);
    }

    /// The counter for one RDTSC, which then advances it by one, modulo 2^64.
    pub(crate) fn read_time_stamp_counter(&mut self) -> u64 {
        let value = self.time_stamp_counter;
        self.time_stamp_counter = value.wrapping_add(1);
        value
    }

    /// Map a new region into guest virtual memory.
    pub fn map_region(
        &mut self,
        base: u64,
        size: usize,
        permissions: MemoryPermissions,
    ) -> Result<(), MemoryError> {
        self.map_region_with_data(base, size, permissions, &[])
    }

    /// Map a new region and initialize it with initial data, bypassing runtime write permission checks.
    pub fn map_region_with_data(
        &mut self,
        base: u64,
        size: usize,
        permissions: MemoryPermissions,
        initial_data: &[u8],
    ) -> Result<(), MemoryError> {
        self.insert_region(
            base,
            size,
            permissions,
            initial_data,
            AllocationKind::ImageOrStatic,
        )
    }

    fn insert_region(
        &mut self,
        base: u64,
        size: usize,
        permissions: MemoryPermissions,
        initial_data: &[u8],
        allocation: AllocationKind,
    ) -> Result<(), MemoryError> {
        let size_u64 = size as u64;
        let end = base.checked_add(size_u64).ok_or(MemoryError::Overflow)?;
        for r in &self.regions {
            let r_end = r.base + r.data.len() as u64;
            if base < r_end && r.base < end {
                return Err(MemoryError::OverlappingRegion {
                    base,
                    size: size_u64,
                });
            }
        }
        let empty_in_reservation = size_u64 == 0
            && self
                .module_reservations
                .iter()
                .any(|&(reservation_base, reservation_end)| {
                    reservation_base <= base && base < reservation_end
                });
        if self.reservation_overlaps(base, end) || empty_in_reservation {
            return Err(MemoryError::OverlappingRegion {
                base,
                size: size_u64,
            });
        }

        let mut data = Vec::new();
        data.try_reserve_exact(size)
            .map_err(|_| MemoryError::AllocationFailed)?;
        data.resize(size, 0);
        let copy_len = size.min(initial_data.len());
        data[..copy_len].copy_from_slice(&initial_data[..copy_len]);

        // The table is already sorted. Insert at the sorted position instead
        // of pushing and sorting the whole table again; use the end of any
        // equal-base empty markers to preserve the stable ordering the sort
        // provided.
        let position = self.regions.partition_point(|region| region.base <= base);
        self.regions.insert(
            position,
            MappedRegion {
                base,
                data,
                permissions,
                allocation,
                allocation_base: base,
            },
        );
        Ok(())
    }

    /// The first committed region intersecting `[base, end)`. An empty region
    /// inside the span counts because it can later be grown in place.
    pub(crate) fn first_region_overlap(&self, base: u64, end: u64) -> Option<(u64, u64)> {
        self.regions
            .iter()
            .map(|region| (region.base, region.base + region.data.len() as u64))
            .find(|&(region_base, region_end)| {
                (base < region_end && region_base < end)
                    || (region_base == region_end && base <= region_base && region_base < end)
            })
    }

    fn reservation_overlaps(&self, base: u64, end: u64) -> bool {
        self.module_reservations
            .iter()
            .any(|&(reservation_base, reservation_end)| {
                base < reservation_end && reservation_base < end
            })
    }

    /// Retain a complete explicit-module image span without committing its
    /// holes. Module batch mapping calls this only after the image's own
    /// headers and sections have been inserted, so those committed regions are
    /// deliberately allowed to lie inside the retained span.
    pub(crate) fn reserve_module_image_span(
        &mut self,
        base: u64,
        end: u64,
    ) -> Result<(), MemoryError> {
        if end <= base {
            return Err(MemoryError::Overflow);
        }
        if self.reservation_overlaps(base, end) {
            return Err(MemoryError::OverlappingRegion {
                base,
                size: end - base,
            });
        }
        self.module_reservations.push((base, end));
        self.module_reservations.sort_unstable();
        Ok(())
    }

    pub(crate) fn map_virtual_allocation(
        &mut self,
        requested_base: u64,
        size: usize,
        permissions: MemoryPermissions,
    ) -> Result<u64, MemoryError> {
        self.map_dynamic_allocation(requested_base, size, permissions, AllocationKind::Virtual)
    }

    pub(crate) fn map_xmem_allocation(
        &mut self,
        requested_base: u64,
        size: usize,
        permissions: MemoryPermissions,
    ) -> Result<u64, MemoryError> {
        self.map_dynamic_allocation(requested_base, size, permissions, AllocationKind::Xmem)
    }

    /// Bytes mapped in total, held by virtual allocations, and held by heap
    /// blocks. Each of the last two kinds is bounded by [`DYNAMIC_BUDGET`].
    pub(crate) fn usage(&self) -> (u64, u64, u64) {
        let mapped = self
            .regions
            .iter()
            .map(|region| region.data.len())
            .sum::<usize>();
        let virtual_bytes = self.dynamic_bytes(AllocationKind::Virtual);
        let heap_bytes = self.dynamic_bytes(AllocationKind::Heap(PROCESS_HEAP));
        (mapped as u64, virtual_bytes as u64, heap_bytes as u64)
    }

    pub(crate) fn crt_errno_address(&mut self, teb: u64) -> Result<u64, MemoryError> {
        if let Some(&address) = self.crt_errno.get(&teb) {
            return Ok(address);
        }
        if self.crt_errno.len() >= 1024 {
            return Err(MemoryError::AllocationFailed);
        }
        let address = self.find_dynamic_base(4)?;
        self.map_region(address, 4, MemoryPermissions::READ_WRITE)?;
        self.crt_errno.insert(teb, address);
        Ok(address)
    }

    pub(crate) fn create_private_heap(&mut self, initial: u64) -> Option<u64> {
        if initial > MAX_DYNAMIC_BYTES as u64
            || self.private_heaps.len() >= 256
            || self.private_heap_serial >= i64::MAX as u64 - 3
        {
            return None;
        }
        self.private_heap_serial += 1;
        let heap = PROCESS_HEAP - self.private_heap_serial;
        self.private_heaps.insert(heap);
        Some(heap)
    }

    pub(crate) fn has_heap(&self, heap: u64) -> bool {
        heap == PROCESS_HEAP || self.private_heaps.contains(&heap)
    }

    pub(crate) fn destroy_private_heap(&mut self, heap: u64) -> bool {
        if !self.private_heaps.remove(&heap) {
            return false;
        }
        self.regions
            .retain(|region| region.allocation != AllocationKind::Heap(heap));
        true
    }

    /// Heap commits are page granular, reproducing the Windows CRT heap,
    /// which carves allocations out of page-committed arenas: bytes just
    /// past a small block stay committed, and guest code that strays a few
    /// bytes past the exact size - the mingw CRT stdio macros do - completes
    /// instead of faulting. The exact requested size is tracked separately
    /// so `heap_allocation_size` keeps answering what the guest asked for.
    pub(crate) fn map_heap_allocation(
        &mut self,
        heap: u64,
        size: usize,
    ) -> Result<u64, MemoryError> {
        self.map_heap_allocation_aligned(heap, size, ALLOCATION_GRANULARITY)
    }

    pub(crate) fn map_heap_allocation_aligned(
        &mut self,
        heap: u64,
        size: usize,
        alignment: u64,
    ) -> Result<u64, MemoryError> {
        if !self.has_heap(heap) || alignment == 0 || !alignment.is_power_of_two() {
            return Err(MemoryError::AllocationFailed);
        }
        let commit = heap_commit(size);
        let base = self.map_dynamic_allocation_aligned(
            0,
            commit,
            MemoryPermissions::READ_WRITE,
            AllocationKind::Heap(heap),
            alignment,
        )?;
        self.heap_exact_bytes.insert(base, size);
        Ok(base)
    }

    fn map_dynamic_allocation(
        &mut self,
        requested_base: u64,
        size: usize,
        permissions: MemoryPermissions,
        allocation: AllocationKind,
    ) -> Result<u64, MemoryError> {
        self.map_dynamic_allocation_aligned(
            requested_base,
            size,
            permissions,
            allocation,
            ALLOCATION_GRANULARITY,
        )
    }

    fn map_dynamic_allocation_aligned(
        &mut self,
        requested_base: u64,
        size: usize,
        permissions: MemoryPermissions,
        allocation: AllocationKind,
        alignment: u64,
    ) -> Result<u64, MemoryError> {
        // Bound retained host storage independently for each allocation kind.
        let allocated = self.dynamic_bytes(allocation);
        if size > MAX_DYNAMIC_BYTES - allocated
            || (matches!(allocation, AllocationKind::Heap(_))
                && self
                    .regions
                    .iter()
                    .filter(|r| matches!(r.allocation, AllocationKind::Heap(_)))
                    .count()
                    >= 4096)
        {
            return Err(MemoryError::AllocationFailed);
        }

        let base = if requested_base == 0 {
            self.find_dynamic_base_aligned(size, alignment)?
        } else {
            requested_base
        };
        self.insert_region(base, size, permissions, &[], allocation)?;
        Ok(base)
    }

    fn dynamic_bytes(&self, allocation: AllocationKind) -> usize {
        self.regions
            .iter()
            .filter(|region| match allocation {
                AllocationKind::Heap(_) => matches!(region.allocation, AllocationKind::Heap(_)),
                AllocationKind::Virtual | AllocationKind::Xmem => matches!(
                    region.allocation,
                    AllocationKind::Virtual | AllocationKind::Xmem
                ),
                _ => region.allocation == allocation,
            })
            .map(|region| region.data.len())
            .sum()
    }

    fn find_dynamic_base(&self, size: usize) -> Result<u64, MemoryError> {
        self.find_dynamic_base_aligned(size, ALLOCATION_GRANULARITY)
    }

    fn find_dynamic_base_aligned(&self, size: usize, alignment: u64) -> Result<u64, MemoryError> {
        let granularity = ALLOCATION_GRANULARITY.max(alignment);
        let mut base = 0x0000_0003_0000_0000u64
            .checked_next_multiple_of(granularity)
            .ok_or(MemoryError::Overflow)?;
        let mut region_index = 0;
        let mut reservation_index = 0;
        loop {
            let region = self
                .regions
                .get(region_index)
                .map(|region| (region.base, region.base + region.data.len() as u64));
            let reservation = self.module_reservations.get(reservation_index).copied();
            let Some((interval_base, interval_end)) = (match (region, reservation) {
                (Some(region), Some(reservation)) => Some(if region.0 <= reservation.0 {
                    region
                } else {
                    reservation
                }),
                (Some(region), None) => Some(region),
                (None, Some(reservation)) => Some(reservation),
                (None, None) => None,
            }) else {
                break;
            };
            let end = base.checked_add(size as u64).ok_or(MemoryError::Overflow)?;
            if end <= interval_base {
                return Ok(base);
            }
            if base < interval_end {
                base = interval_end
                    .checked_next_multiple_of(granularity)
                    .ok_or(MemoryError::Overflow)?;
            }
            if region.is_some_and(|region| region == (interval_base, interval_end)) {
                region_index += 1;
            }
            if reservation.is_some_and(|reservation| reservation == (interval_base, interval_end)) {
                reservation_index += 1;
            }
        }
        base.checked_add(size as u64).ok_or(MemoryError::Overflow)?;
        Ok(base)
    }

    pub(crate) fn resize_heap_allocation(
        &mut self,
        heap: u64,
        base: u64,
        size: usize,
        in_place_only: bool,
    ) -> Result<u64, MemoryError> {
        let index = self
            .regions
            .iter()
            .position(|region| {
                region.base == base && region.allocation == AllocationKind::Heap(heap)
            })
            .ok_or(MemoryError::UnmappedAddress(base))?;
        let previous = self.regions[index].data.len();
        let commit = heap_commit(size);
        let other_bytes = self.dynamic_bytes(AllocationKind::Heap(heap)) - previous;
        if commit > MAX_DYNAMIC_BYTES - other_bytes {
            return Err(MemoryError::AllocationFailed);
        }

        if commit == previous {
            // Growth or shrink inside the same committed page needs no memory
            // operation at all: the slack stays committed, exactly as the
            // Windows heap keeps the arena page committed. Only the exact
            // requested size tracked for the heap APIs changes.
            self.heap_exact_bytes.insert(base, size);
            return Ok(base);
        }

        let region_boundary = self
            .regions
            .get(index + 1)
            .map_or(u64::MAX, |next| next.base);
        let reservation_boundary = self
            .module_reservations
            .iter()
            .filter_map(|&(reservation_base, reservation_end)| {
                if reservation_base <= base && base < reservation_end {
                    Some(base)
                } else {
                    (reservation_base > base).then_some(reservation_base)
                }
            })
            .min()
            .unwrap_or(u64::MAX);
        let boundary = region_boundary.min(reservation_boundary);
        let destination = if (commit as u64) <= boundary - base {
            base
        } else if in_place_only {
            return Err(MemoryError::AllocationFailed);
        } else {
            self.find_dynamic_base(commit)?
        };

        let region = &mut self.regions[index];
        region
            .data
            .try_reserve_exact(commit.saturating_sub(previous))
            .map_err(|_| MemoryError::AllocationFailed)?;
        region.data.resize(commit, 0);
        if commit < previous {
            region.data.shrink_to_fit();
        }
        if destination != base {
            region.base = destination;
            self.regions.sort_by_key(|region| region.base);
        }
        self.heap_exact_bytes.remove(&base);
        self.heap_exact_bytes.insert(destination, size);
        Ok(destination)
    }

    pub(crate) fn map_thread_region(
        &mut self,
        base: u64,
        size: usize,
        permissions: MemoryPermissions,
    ) -> Result<u64, MemoryError> {
        self.map_dynamic_allocation(base, size, permissions, AllocationKind::Thread)
    }

    pub(crate) fn release_thread_region(&mut self, base: u64) -> bool {
        self.release_dynamic_allocation(base, AllocationKind::Thread)
    }

    pub(crate) fn release_virtual_allocation(&mut self, base: u64) -> bool {
        self.release_dynamic_allocation(base, AllocationKind::Virtual)
    }

    pub(crate) fn release_xmem_allocation(&mut self, base: u64) -> bool {
        self.release_dynamic_allocation(base, AllocationKind::Xmem)
    }

    pub(crate) fn release_heap_allocation(&mut self, heap: u64, base: u64) -> bool {
        self.release_dynamic_allocation(base, AllocationKind::Heap(heap))
    }

    /// Base of the image allocation a region belongs to, when Xenora knows
    /// it as part of the main image or of an explicit module reservation.
    fn image_allocation_base(&self, region: &MappedRegion) -> Option<u64> {
        if region.allocation != AllocationKind::ImageOrStatic {
            return None;
        }
        if let Some(image) = self.main_image {
            let image_end = image.base.checked_add(u64::from(image.size))?;
            if image.base <= region.base && region.base < image_end {
                return Some(image.base);
            }
        }
        self.module_reservations
            .iter()
            .find(|&&(base, end)| base <= region.base && region.base < end)
            .map(|&(base, _)| base)
    }

    fn allocation_identity(&self, region: &MappedRegion) -> u64 {
        self.image_allocation_base(region)
            .unwrap_or(region.allocation_base)
    }

    /// Describe the committed region containing `address`. Holes in retained
    /// module reservations are not committed memory and therefore return none.
    pub(crate) fn committed_region_info(&self, address: u64) -> Option<CommittedRegionInfo> {
        let (_, region) = self.first_ending_after(address)?;
        if region.base > address || region.data.is_empty() {
            return None;
        }
        let end = region.base.checked_add(region.data.len() as u64)?;
        Some(CommittedRegionInfo {
            base: region.base,
            end,
            allocation_base: self.allocation_identity(region),
            permissions: region.permissions,
            image: self.image_allocation_base(region).is_some(),
        })
    }

    /// Validate the already page-rounded `[start, end)` span for a protection
    /// change and return the first page's current permissions. No mutation is
    /// made, so a service can validate its output pointer before committing.
    pub(crate) fn validate_committed_protection_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<MemoryPermissions, ProtectionError> {
        if end <= start {
            return Err(ProtectionError::Overflow);
        }
        let len = usize::try_from(end - start).map_err(|_| ProtectionError::Overflow)?;
        let pieces = self
            .resolve(start, len, None)
            .map_err(|error| match error {
                MemoryError::UnmappedAddress(address) => ProtectionError::Unmapped(address),
                _ => ProtectionError::Overflow,
            })?;
        let first = pieces
            .first()
            .and_then(|&(index, _, _)| self.regions.get(index))
            .ok_or(ProtectionError::Unmapped(start))?;
        let old = first.permissions;
        if !matches!(
            first.allocation,
            AllocationKind::ImageOrStatic | AllocationKind::Virtual
        ) {
            return Err(ProtectionError::UnsupportedAllocation);
        }
        let identity = (first.allocation, self.allocation_identity(first));
        for &(index, _, _) in &pieces {
            let region = &self.regions[index];
            if (region.allocation, self.allocation_identity(region)) != identity {
                return Err(ProtectionError::CrossesAllocations);
            }
        }
        Ok(old)
    }

    /// Change permissions over the already page-rounded `[start, end)` span.
    /// The caller has validated the public arguments. Complete committed
    /// coverage and one allocation ownership domain are checked before
    /// mutating, so an invalid span leaves every region unchanged.
    pub(crate) fn protect_committed_range(
        &mut self,
        start: u64,
        end: u64,
        permissions: MemoryPermissions,
    ) -> Result<MemoryPermissions, ProtectionError> {
        let len = usize::try_from(end - start).map_err(|_| ProtectionError::Overflow)?;
        let pieces = self
            .resolve(start, len, None)
            .map_err(|error| match error {
                MemoryError::UnmappedAddress(address) => ProtectionError::Unmapped(address),
                _ => ProtectionError::Overflow,
            })?;
        let old = self.validate_committed_protection_range(start, end)?;

        let regions = std::mem::take(&mut self.regions);
        let mut rebuilt = Vec::with_capacity(regions.len() + pieces.len() * 2);
        for mut region in regions {
            let region_end = region.base + region.data.len() as u64;
            if region.data.is_empty() || end <= region.base || region_end <= start {
                rebuilt.push(region);
                continue;
            }
            if start <= region.base && region_end <= end {
                region.permissions = permissions;
                rebuilt.push(region);
                continue;
            }

            let middle_start = start.max(region.base);
            let middle_end = end.min(region_end);
            let base = region.base;
            let allocation = region.allocation;
            let allocation_base = region.allocation_base;
            let old_permissions = region.permissions;
            let data = region.data;
            let mut push_piece = |piece_base: u64, offset: usize, len: usize, piece_permissions| {
                if len != 0 {
                    rebuilt.push(MappedRegion {
                        base: piece_base,
                        data: data[offset..offset + len].to_vec(),
                        permissions: piece_permissions,
                        allocation,
                        allocation_base,
                    });
                }
            };
            let prefix_len = (middle_start - base) as usize;
            push_piece(base, 0, prefix_len, old_permissions);
            let middle_offset = prefix_len;
            let middle_len = (middle_end - middle_start) as usize;
            push_piece(middle_start, middle_offset, middle_len, permissions);
            let suffix_offset = middle_offset + middle_len;
            let suffix_len = (region_end - middle_end) as usize;
            push_piece(middle_end, suffix_offset, suffix_len, old_permissions);
        }
        self.regions = rebuilt;
        Ok(old)
    }

    pub(crate) fn heap_allocation_size(&self, heap: u64, base: u64) -> Option<usize> {
        self.regions.iter().find(|region| {
            region.base == base && region.allocation == AllocationKind::Heap(heap)
        })?;
        self.heap_exact_bytes.get(&base).copied()
    }

    fn release_dynamic_allocation(&mut self, base: u64, allocation: AllocationKind) -> bool {
        self.heap_exact_bytes.remove(&base);
        if allocation == AllocationKind::Virtual {
            let before = self.regions.len();
            // VirtualProtect may split one virtual allocation into adjacent
            // regions. Its original allocation base, not the current piece
            // base, is the ownership key. Other allocation kinds cannot be
            // split by the supported protection surface, and heap allocations
            // may share a base while empty, so they keep exact-base removal.
            self.regions.retain(|region| {
                !(region.allocation == allocation && region.allocation_base == base)
            });
            return self.regions.len() != before;
        }
        // Equal-base empty heap markers can form a small cluster, but the
        // sorted table lets the search skip every unrelated region.
        let first = self.regions.partition_point(|region| region.base < base);
        let end = self.regions.partition_point(|region| region.base <= base);
        let Some(index) = self.regions[first..end]
            .iter()
            .position(|region| region.allocation == allocation)
            .map(|index| first + index)
        else {
            return false;
        };
        self.regions.remove(index);
        true
    }

    /// The first region, in table order, that ends after `address`: where
    /// every data access and the resolver start (#102). It is the region a
    /// scan from the front would find. The first [`FRONT_SCAN`] regions are checked in order, as
    /// that scan would; past them, the region is located by binary search.
    ///
    /// The table is sorted by base, and no region's base lies strictly
    /// inside another region. Every way the table changes keeps that true:
    /// `insert_region` refuses an overlap, which includes a base strictly
    /// inside a non-empty region; a dynamic base is placed outside every
    /// region, and only an empty allocation may share a base; a block grows
    /// in place only up to the base of the next region in the table; and
    /// removal keeps the order. Mappings may still overlap, but only when
    /// they share a base, which is what an empty heap block grown in place
    /// over the mapping at its base does.
    ///
    /// Let `b` be the largest base at or below `address`. A region with a
    /// smaller base cannot reach past `address`: it would then contain `b`.
    /// So the region found is the first of those based at `b` that ends
    /// after `address`, if there is one, or else the next region in the
    /// table, which starts above `address`.
    #[inline]
    fn first_ending_after(&self, address: u64) -> Option<(usize, &MappedRegion)> {
        let regions = &self.regions;
        let front = regions.len().min(FRONT_SCAN);
        let found = regions[..front]
            .iter()
            .enumerate()
            .find(|(_, region)| region.base + region.data.len() as u64 > address);
        if found.is_some() || regions.len() <= FRONT_SCAN {
            // Found, or the scan has seen every region.
            return found;
        }
        let index = self.search_ending_after(address)?;
        Some((index, &regions[index]))
    }

    /// [`Self::first_ending_after`] past the front of the table, kept out of
    /// line so that the front scan inlines into every access.
    #[inline(never)]
    fn search_ending_after(&self, address: u64) -> Option<usize> {
        let regions = &self.regions;
        let ends_after = |region: &MappedRegion| region.base + region.data.len() as u64 > address;
        let above = regions.partition_point(|region| region.base <= address);
        if let Some(last) = above.checked_sub(1) {
            // The regions based at `b` end at `above`; they are usually one.
            let base = regions[last].base;
            let mut group = last;
            while group > 0 && regions[group - 1].base == base {
                group -= 1;
            }
            if let Some(offset) = regions[group..above].iter().position(ends_after) {
                return Some(group + offset);
            }
        }
        (above < regions.len()).then_some(above)
    }

    pub(crate) fn check_write(&self, address: u64, size: usize) -> Result<(), MemoryError> {
        self.resolve(address, size, Some("write")).map(|_| ())
    }

    /// Resolve `[address, address + len)` to `(region index, offset, length)` pieces.
    ///
    /// An access may span adjacent regions, as it would span adjacent pages, but every
    /// byte must be mapped and every region must grant `required` (`None` bypasses
    /// permission checks for the loader). The whole range is checked before any byte
    /// is copied, so a failed access never partially reads or writes.
    ///
    /// A failed access reports the lowest address it may not touch, which is the
    /// start of the access only when its first byte fails. An access that begins in
    /// a mapped page and runs into an unmapped or forbidden one therefore reports
    /// the first byte of that page, as an x86 page fault reports the linear address
    /// that could not be translated or accessed.
    fn resolve(
        &self,
        address: u64,
        len: usize,
        required: Option<&'static str>,
    ) -> Result<Vec<(usize, usize, usize)>, MemoryError> {
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::Overflow)?;
        if len == 0 {
            return if self.regions.iter().any(|r| r.contains(address, 0)) {
                Ok(Vec::new())
            } else {
                Err(MemoryError::UnmappedAddress(address))
            };
        }
        let mut pieces = Vec::new();
        let mut cursor = address;
        // Every region before this one ends at or before `address`, so the
        // loop below would skip it.
        let start = self
            .first_ending_after(address)
            .map_or(self.regions.len(), |(index, _)| index);
        for (index, region) in self.regions.iter().enumerate().skip(start) {
            let region_end = region.base + region.data.len() as u64;
            if region_end <= cursor {
                continue;
            }
            if region.base > cursor {
                break;
            }
            let permitted = match required {
                None => true,
                Some("read") => region.permissions.read,
                Some("write") => region.permissions.write,
                Some(_) => region.permissions.execute,
            };
            if let (false, Some(required)) = (permitted, required) {
                return Err(MemoryError::PermissionViolation {
                    address: cursor,
                    required,
                });
            }
            let take = (end.min(region_end) - cursor) as usize;
            pieces.push((index, (cursor - region.base) as usize, take));
            cursor += take as u64;
            if cursor == end {
                return Ok(pieces);
            }
        }
        Err(MemoryError::UnmappedAddress(cursor))
    }

    fn read_checked(
        &self,
        address: u64,
        dst: &mut [u8],
        required: Option<&'static str>,
    ) -> Result<(), MemoryError> {
        let mut done = 0;
        for (index, offset, take) in self.resolve(address, dst.len(), required)? {
            dst[done..done + take]
                .copy_from_slice(&self.regions[index].data[offset..offset + take]);
            done += take;
        }
        Ok(())
    }

    fn write_checked(
        &mut self,
        address: u64,
        src: &[u8],
        required: Option<&'static str>,
    ) -> Result<(), MemoryError> {
        let mut done = 0;
        for (index, offset, take) in self.resolve(address, src.len(), required)? {
            self.regions[index].data[offset..offset + take]
                .copy_from_slice(&src[done..done + take]);
            done += take;
        }
        Ok(())
    }

    /// Write raw bytes into guest memory at the specified address, checking permissions.
    pub fn write_bytes(&mut self, address: u64, src: &[u8]) -> Result<(), MemoryError> {
        if let Some((index, range)) = self.contiguous_region(address, src.len())
            && self.regions[index].permissions.write
        {
            self.regions[index].data[range].copy_from_slice(src);
            return Ok(());
        }
        let result = self.write_checked(address, src, Some("write"));
        if let Err(MemoryError::UnmappedAddress(at)) = result {
            self.write_fault = Some(at);
        }
        result
    }

    /// Return whether the complete span is writable without mutating it.
    pub(crate) fn can_write(&self, address: u64, len: usize) -> bool {
        self.resolve(address, len, Some("write")).is_ok()
    }

    /// Return whether the complete span is readable without mutating it.
    pub(crate) fn can_read(&self, address: u64, len: usize) -> bool {
        self.resolve(address, len, Some("read")).is_ok()
    }

    /// Read raw bytes from guest memory at the specified address, checking permissions.
    pub fn read_bytes(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        if let Some((index, range)) = self.contiguous_region(address, dst.len())
            && self.regions[index].permissions.read
        {
            dst.copy_from_slice(&self.regions[index].data[range]);
            return Ok(());
        }
        self.read_checked(address, dst, Some("read"))
    }

    // Only the first eligible mapping may supply the whole span. Otherwise
    // the checked resolver must preserve split-access and overlap priority.
    fn contiguous_region(&self, address: u64, len: usize) -> Option<(usize, Range<usize>)> {
        let (index, region) = self.first_ending_after(address)?;
        let offset = usize::try_from(address.checked_sub(region.base)?).ok()?;
        let end = offset.checked_add(len)?;
        (end <= region.data.len()).then_some((index, offset..end))
    }

    /// Read an instruction byte from guest memory, verifying execute permission.
    pub fn fetch_instruction_byte(&self, address: u64) -> Result<u8, MemoryError> {
        address.checked_add(1).ok_or(MemoryError::Overflow)?;
        // Instruction fetch keeps the scan from the front (#102). Every form
        // of the search tried here made the translator's decoding 7-10 %
        // slower in `dbt_bench`, where the table has three regions; a
        // program's code is usually in its image, near the front.
        let region = self
            .regions
            .iter()
            .find(|region| region.base + region.data.len() as u64 > address)
            .filter(|region| region.base <= address)
            .ok_or(MemoryError::UnmappedAddress(address))?;
        if !region.permissions.execute {
            return Err(MemoryError::PermissionViolation {
                address,
                required: "execute",
            });
        }
        Ok(region.data[(address - region.base) as usize])
    }

    /// Read a 64-bit integer (little endian) from guest memory.
    pub fn read_u64(&self, address: u64) -> Result<u64, MemoryError> {
        let mut buf = [0u8; 8];
        self.read_bytes(address, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a 64-bit integer ignoring region read permissions (e.g. loader/relocation phase).
    pub fn read_u64_bypass(&self, address: u64) -> Result<u64, MemoryError> {
        let mut buf = [0u8; 8];
        self.read_checked(address, &mut buf, None)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Write a 64-bit integer (little endian) to guest memory.
    pub fn write_u64(&mut self, address: u64, value: u64) -> Result<(), MemoryError> {
        self.write_bytes(address, &value.to_le_bytes())
    }

    /// Write a 64-bit integer ignoring region write permissions (e.g. loader/relocation phase).
    pub fn write_u64_bypass(&mut self, address: u64, value: u64) -> Result<(), MemoryError> {
        self.write_checked(address, &value.to_le_bytes(), None)
    }

    /// Read a 32-bit integer (little endian) from guest memory.
    pub fn read_u32(&self, address: u64) -> Result<u32, MemoryError> {
        let mut buf = [0u8; 4];
        self.read_bytes(address, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Write a 32-bit integer (little endian) to guest memory.
    pub fn write_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryError> {
        self.write_bytes(address, &value.to_le_bytes())
    }

    /// Write a 32-bit integer ignoring region write permissions (e.g. loader/relocation phase).
    pub fn write_u32_bypass(&mut self, address: u64, value: u32) -> Result<(), MemoryError> {
        self.write_checked(address, &value.to_le_bytes(), None)
    }

    /// Read a single byte from guest memory.
    pub fn read_u8(&self, address: u64) -> Result<u8, MemoryError> {
        let mut buf = [0u8; 1];
        self.read_bytes(address, &mut buf)?;
        Ok(buf[0])
    }

    /// Write a single byte to guest memory.
    pub fn write_u8(&mut self, address: u64, value: u8) -> Result<(), MemoryError> {
        self.write_bytes(address, &[value])
    }

    /// Read a 16-bit little-endian integer from guest memory.
    pub fn read_u16(&self, address: u64) -> Result<u16, MemoryError> {
        let mut buf = [0u8; 2];
        self.read_bytes(address, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Write a 16-bit little-endian integer to guest memory.
    pub fn write_u16(&mut self, address: u64, value: u16) -> Result<(), MemoryError> {
        self.write_bytes(address, &value.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_heap_destruction_reclaims_only_owned_regions() {
        let mut memory = GuestMemory::new();
        let private = memory.create_private_heap(0).unwrap();
        let peer = memory.create_private_heap(0).unwrap();
        let address = memory.map_heap_allocation(private, 16).unwrap();
        let retained = memory.map_heap_allocation(peer, 16).unwrap();
        assert!(!memory.release_heap_allocation(peer, address));
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, address), None);
        assert!(!memory.destroy_private_heap(PROCESS_HEAP));
        assert!(memory.destroy_private_heap(private));
        assert!(!memory.destroy_private_heap(private));
        assert!(memory.map_heap_allocation(private, 16).is_err());
        assert!(memory.read_u8(address).is_err());
        assert_eq!(memory.read_u8(retained), Ok(0));
        assert_ne!(memory.create_private_heap(0).unwrap(), private);
    }

    #[test]
    fn protection_rejects_unsupported_allocation_ownership() {
        let mut memory = GuestMemory::new();
        let heap = memory.map_heap_allocation(PROCESS_HEAP, 0x1000).unwrap();
        let xmem = memory
            .map_xmem_allocation(0, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        for base in [heap, xmem] {
            assert_eq!(
                memory.validate_committed_protection_range(base, base + 0x1000),
                Err(ProtectionError::UnsupportedAllocation)
            );
            memory.write_u8(base, 0x5a).unwrap();
        }
    }

    #[test]
    fn xmem_allocations_have_a_distinct_owner_and_share_the_virtual_budget() {
        let mut memory = GuestMemory::new();
        let before = memory.usage().1;
        let virtual_base = memory
            .map_virtual_allocation(0, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        let xmem_base = memory
            .map_xmem_allocation(0, 0x2000, MemoryPermissions::READ_WRITE)
            .unwrap();
        assert_ne!(virtual_base, xmem_base);
        assert_eq!(memory.usage().1, before + 0x3000);

        assert!(!memory.release_virtual_allocation(xmem_base));
        assert!(!memory.release_xmem_allocation(virtual_base));
        assert_eq!(memory.read_u8(xmem_base), Ok(0));
        assert_eq!(memory.read_u8(virtual_base), Ok(0));

        assert!(memory.release_xmem_allocation(xmem_base));
        assert!(memory.release_virtual_allocation(virtual_base));
        assert_eq!(memory.usage().1, before);
    }

    #[test]
    fn heap_allocations_commit_page_slack_but_report_exact_sizes() {
        // The Windows CRT heap carves blocks out of page-committed arenas, so
        // the bytes just past a small allocation are committed zeroes rather
        // than a fault (#1421). The heap APIs keep reporting the exact
        // requested size regardless.
        let mut memory = GuestMemory::new();
        let base = memory.map_heap_allocation(PROCESS_HEAP, 8).unwrap();
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, base), Some(8));
        for at in [base, base + 8, base + 4095] {
            assert_eq!(memory.read_u8(at), Ok(0));
            assert_eq!(memory.write_u8(at, 0xaa), Ok(()));
        }
        assert_eq!(
            memory.read_u8(base + 4096),
            Err(MemoryError::UnmappedAddress(base + 4096))
        );
        // A zero-length request stays a zero-length marker: no byte of it is
        // committed, and it can share its base with other empty markers.
        let empty = memory.map_heap_allocation(PROCESS_HEAP, 0).unwrap();
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, empty), Some(0));
        // Growth inside the committed page is a pure in-place size change:
        // the base cannot move, even when a move is allowed.
        let grown = memory
            .resize_heap_allocation(PROCESS_HEAP, base, 4000, false)
            .unwrap();
        assert_eq!(grown, base);
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, base), Some(4000));
        assert_eq!(memory.read_u8(base), Ok(0xaa));
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, base, 0, true),
            Ok(base)
        );
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, base), Some(0));
    }

    #[test]
    fn heap_resize_moves_only_when_allowed_and_preserves_bytes() {
        let mut memory = GuestMemory::new();
        let base = memory.map_heap_allocation(PROCESS_HEAP, 19).unwrap();
        let neighbor = memory.map_heap_allocation(PROCESS_HEAP, 1).unwrap();
        memory.write_u8(base, 0xab).unwrap();
        memory.write_u8(neighbor, 0xcd).unwrap();
        let growth = (neighbor - base) as usize + 1;
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, base, growth, true),
            Err(MemoryError::AllocationFailed)
        );
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, base), Some(19));
        let moved = memory
            .resize_heap_allocation(PROCESS_HEAP, base, growth, false)
            .unwrap();
        assert_ne!(moved, base);
        assert_eq!(memory.read_u8(moved), Ok(0xab));
        assert_eq!(memory.read_u8(neighbor), Ok(0xcd));
        assert_eq!(memory.read_u8(moved + growth as u64 - 1), Ok(0));
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, base), None);
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, moved, 1, true),
            Ok(moved)
        );
        assert_eq!(memory.heap_allocation_size(PROCESS_HEAP, moved), Some(1));
    }

    #[test]
    fn module_reservations_reject_reused_holes_and_guide_dynamic_bases() {
        const BASE: u64 = 0x0000_0003_0000_0000;
        let mut memory = GuestMemory::new();
        memory
            .reserve_module_image_span(BASE + 0x1000, BASE + 0x20000)
            .unwrap();

        for (base, size) in [
            (BASE + 0x1800, 0x100),
            (BASE + 0x2800, 0x1000),
            (BASE + 0x1800, 0),
        ] {
            assert_eq!(
                memory.map_region(base, size, MemoryPermissions::READ_WRITE),
                Err(MemoryError::OverlappingRegion {
                    base,
                    size: size as u64,
                })
            );
            assert_eq!(
                memory.map_virtual_allocation(base, size, MemoryPermissions::READ_WRITE),
                Err(MemoryError::OverlappingRegion {
                    base,
                    size: size as u64,
                })
            );
        }

        let allocated = memory
            .map_virtual_allocation(0, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        assert_eq!(allocated, BASE);
        let after = memory
            .map_virtual_allocation(0, 0x1000, MemoryPermissions::READ_WRITE)
            .unwrap();
        assert_eq!(after, BASE + 0x20000);
    }

    #[test]
    fn module_reservations_bound_heap_growth_and_adjacency() {
        const BASE: u64 = 0x0000_0003_0000_0000;
        let mut memory = GuestMemory::new();
        memory
            .reserve_module_image_span(BASE + 0x1000, BASE + 0x20000)
            .unwrap();
        memory
            .reserve_module_image_span(BASE + 0x20000, BASE + 0x30000)
            .unwrap();
        assert_eq!(
            memory.reserve_module_image_span(BASE + 0x1800, BASE + 0x28000),
            Err(MemoryError::OverlappingRegion {
                base: BASE + 0x1800,
                size: 0x26800,
            })
        );

        let heap = memory.map_heap_allocation(PROCESS_HEAP, 1).unwrap();
        assert_eq!(heap, BASE);
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, heap, 0x1000, true),
            Ok(heap)
        );
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, heap, 0x1001, true),
            Err(MemoryError::AllocationFailed)
        );
        let moved = memory
            .resize_heap_allocation(PROCESS_HEAP, heap, 0x1001, false)
            .unwrap();
        assert_eq!(moved, BASE + 0x30000);
    }
}

#[cfg(test)]
mod instruction_fetch_tests {
    use super::{MemoryPermissions as P, *};

    fn denied(address: u64) -> Result<u8, MemoryError> {
        Err(MemoryError::PermissionViolation {
            address,
            required: "execute",
        })
    }
    fn missing(address: u64) -> Result<u8, MemoryError> {
        Err(MemoryError::UnmappedAddress(address))
    }

    #[test]
    fn fetch_reports_overflow_before_lookup() {
        let m = GuestMemory::new();
        for at in [0, 1, 0x1000, u64::MAX - 1] {
            assert_eq!(m.fetch_instruction_byte(at), missing(at));
        }
        assert_eq!(
            m.fetch_instruction_byte(u64::MAX),
            Err(MemoryError::Overflow)
        );
        let mut m = GuestMemory::new();
        m.map_region(u64::MAX, 0, P::NO_ACCESS).unwrap();
        assert_eq!(
            m.fetch_instruction_byte(u64::MAX),
            Err(MemoryError::Overflow)
        );
    }

    #[test]
    fn fetch_checks_execute_permission_for_every_byte_value() {
        let bytes: Vec<u8> = (0..=255).collect();
        for flags in 0..8 {
            let permission = P {
                read: flags & 1 != 0,
                write: flags & 2 != 0,
                execute: flags & 4 != 0,
            };
            let mut m = GuestMemory::new();
            m.map_region_with_data(0x1000, bytes.len(), permission, &bytes)
                .unwrap();
            for (offset, byte) in bytes.iter().enumerate() {
                let at = 0x1000 + offset as u64;
                assert_eq!(
                    m.fetch_instruction_byte(at),
                    if flags & 4 != 0 {
                        Ok(*byte)
                    } else {
                        denied(at)
                    },
                    "flags={flags}, at={at:x}"
                );
            }
        }
    }

    #[test]
    fn fetch_handles_sparse_and_out_of_order_mappings() {
        let mut m = GuestMemory::new();
        m.map_region_with_data(0x3000, 2, P::READ_EXECUTE, &[0xc1, 0xc2])
            .unwrap();
        m.map_region_with_data(0, 2, P::READ_EXECUTE, &[0x01, 0x02])
            .unwrap();
        m.map_region_with_data(0x2000, 1, P::READ_ONLY, &[0xb1])
            .unwrap();
        m.map_region_with_data(0x1000, 2, P::READ_EXECUTE, &[0xa1, 0xa2])
            .unwrap();
        for (at, byte) in [
            (0, 1),
            (1, 2),
            (0x1000, 0xa1),
            (0x1001, 0xa2),
            (0x3000, 0xc1),
            (0x3001, 0xc2),
        ] {
            assert_eq!(m.fetch_instruction_byte(at), Ok(byte));
        }
        assert_eq!(m.fetch_instruction_byte(0x2000), denied(0x2000));
        for at in [2, 0xfff, 0x1002, 0x2001, 0x2fff, 0x3002] {
            assert_eq!(m.fetch_instruction_byte(at), missing(at));
        }
    }

    #[test]
    fn fetch_ignores_empty_mappings_at_shared_boundaries() {
        for zero_first in [false, true] {
            for execute in [false, true] {
                let mut m = GuestMemory::new();
                let permission = P {
                    read: false,
                    write: false,
                    execute,
                };
                if zero_first {
                    for _ in 0..7 {
                        m.map_region(0x1000, 0, P::READ_WRITE_EXECUTE).unwrap();
                    }
                }
                m.map_region_with_data(0x1000, 2, permission, &[0x34, 0x56])
                    .unwrap();
                for _ in 0..7 {
                    m.map_region(0x1000, 0, P::NO_ACCESS).unwrap();
                }
                for _ in 0..7 {
                    m.map_region(0x1002, 0, P::READ_WRITE_EXECUTE).unwrap();
                }
                for (at, byte) in [(0x1000, 0x34), (0x1001, 0x56)] {
                    assert_eq!(
                        m.fetch_instruction_byte(at),
                        if execute { Ok(byte) } else { denied(at) }
                    );
                }
                assert_eq!(m.fetch_instruction_byte(0x1002), missing(0x1002));
            }
        }
        let mut m = GuestMemory::new();
        for at in [1, 1, 2, 0x1000] {
            m.map_region(at, 0, P::READ_WRITE_EXECUTE).unwrap();
        }
        for at in [0, 1, 2, 3, 0x1000] {
            assert_eq!(m.fetch_instruction_byte(at), missing(at));
        }
    }

    #[test]
    fn fetch_checks_adjacent_mapping_permissions() {
        let mut m = GuestMemory::new();
        m.map_region_with_data(0x1000, 1, P::READ_EXECUTE, &[0xa5])
            .unwrap();
        m.map_region_with_data(0x1001, 1, P::READ_WRITE, &[0x5a])
            .unwrap();
        m.map_region(0x1001, 0, P::READ_EXECUTE).unwrap();
        m.map_region_with_data(0x1002, 1, P::READ_EXECUTE, &[0xc3])
            .unwrap();
        assert_eq!(m.fetch_instruction_byte(0x1000), Ok(0xa5));
        assert_eq!(m.fetch_instruction_byte(0x1001), denied(0x1001));
        assert_eq!(m.fetch_instruction_byte(0x1002), Ok(0xc3));
        assert_eq!(m.fetch_instruction_byte(0x1003), missing(0x1003));
    }

    #[test]
    fn fetch_handles_the_highest_region_end() {
        let mut m = GuestMemory::new();
        m.map_region_with_data(u64::MAX - 2, 2, P::READ_EXECUTE, &[0x12, 0x34])
            .unwrap();
        m.map_region(u64::MAX, 0, P::READ_EXECUTE).unwrap();
        assert_eq!(
            m.fetch_instruction_byte(u64::MAX - 3),
            missing(u64::MAX - 3)
        );
        assert_eq!(m.fetch_instruction_byte(u64::MAX - 2), Ok(0x12));
        assert_eq!(m.fetch_instruction_byte(u64::MAX - 1), Ok(0x34));
        assert_eq!(
            m.fetch_instruction_byte(u64::MAX),
            Err(MemoryError::Overflow)
        );
    }

    #[test]
    fn fetch_observes_writes_clones_and_mapping_changes() {
        let mut m = GuestMemory::new();
        m.map_region_with_data(0x1000, 1, P::READ_WRITE_EXECUTE, &[0x11])
            .unwrap();
        let mut clone = m.clone();
        m.write_u8(0x1000, 0x22).unwrap();
        clone.write_u8(0x1000, 0x33).unwrap();
        assert_eq!(m.fetch_instruction_byte(0x1000), Ok(0x22));
        assert_eq!(clone.fetch_instruction_byte(0x1000), Ok(0x33));
        let base = m
            .map_virtual_allocation(0x4000, 1, P::READ_WRITE_EXECUTE)
            .unwrap();
        m.write_u8(base, 0x44).unwrap();
        assert_eq!(m.fetch_instruction_byte(base), Ok(0x44));
        assert!(m.release_virtual_allocation(base));
        assert_eq!(m.fetch_instruction_byte(base), missing(base));
        m.map_region_with_data(base, 1, P::READ_ONLY, &[0x55])
            .unwrap();
        assert_eq!(m.fetch_instruction_byte(base), denied(base));
        assert_eq!(clone.fetch_instruction_byte(base), missing(base));
    }

    #[test]
    fn fetch_keeps_first_mapping_priority_after_empty_heap_growth() {
        // Existing private allocation methods can grow a zero allocation onto an
        // earlier mapping at its base. The fetch-only patch must preserve the
        // original mapping's priority even for this already-representable state.
        let mut m = GuestMemory::new();
        m.map_region_with_data(0x1000, 1, P::READ_EXECUTE, &[0x90])
            .unwrap();
        const BASE: u64 = 0x0000_0003_0000_0000;
        m.map_region_with_data(BASE, 4, P::READ_EXECUTE, &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        let empty = m.map_heap_allocation(PROCESS_HEAP, 0).unwrap();
        assert_eq!(empty, BASE);
        assert_eq!(
            m.resize_heap_allocation(PROCESS_HEAP, empty, 2, true),
            Ok(BASE)
        );
        assert_eq!(m.fetch_instruction_byte(BASE), Ok(0x11));
        assert_eq!(m.fetch_instruction_byte(BASE + 1), Ok(0x22));
        assert_eq!(m.fetch_instruction_byte(BASE + 3), Ok(0x44));
    }
}

#[cfg(test)]
mod data_access_contract_tests {
    use super::{MemoryPermissions as P, *};
    const A: u64 = 0x10_0000;

    #[test]
    fn data_permissions_are_independent_and_failed_reads_leave_output_untouched() {
        for bits in 0..8 {
            let p = P {
                read: bits & 1 != 0,
                write: bits & 2 != 0,
                execute: bits & 4 != 0,
            };
            let mut m = GuestMemory::new();
            m.map_region_with_data(A, 4, p, &[1, 2, 3, 4]).unwrap();
            let mut out = [0xee; 2];
            let read = m.read_bytes(A + 1, &mut out);
            assert_eq!(
                read,
                if p.read {
                    Ok(())
                } else {
                    Err(MemoryError::PermissionViolation {
                        address: A + 1,
                        required: "read",
                    })
                }
            );
            assert_eq!(out, if p.read { [2, 3] } else { [0xee; 2] });
            let write = m.write_bytes(A + 1, &[0x55, 0x66]);
            assert_eq!(
                write,
                if p.write {
                    Ok(())
                } else {
                    Err(MemoryError::PermissionViolation {
                        address: A + 1,
                        required: "write",
                    })
                }
            );
            let mut stored = [0; 4];
            m.read_checked(A, &mut stored, None).unwrap();
            assert_eq!(
                stored,
                if p.write {
                    [1, 0x55, 0x66, 4]
                } else {
                    [1, 2, 3, 4]
                }
            );
        }
    }

    #[test]
    fn empty_data_spans_keep_inclusive_ends_and_ignore_permissions() {
        let mut m = GuestMemory::new();
        m.map_region(A, 0, P::NO_ACCESS).unwrap();
        m.map_region(A + 16, 3, P::NO_ACCESS).unwrap();
        m.map_region(u64::MAX, 0, P::NO_ACCESS).unwrap();
        for at in [A, A + 16, A + 17, A + 19, u64::MAX] {
            assert_eq!(m.read_bytes(at, &mut []), Ok(()));
            assert_eq!(m.write_bytes(at, &[]), Ok(()));
        }
        for at in [A - 1, A + 1, A + 15, A + 20] {
            assert_eq!(
                m.read_bytes(at, &mut []),
                Err(MemoryError::UnmappedAddress(at))
            );
            assert_eq!(
                m.write_bytes(at, &[]),
                Err(MemoryError::UnmappedAddress(at))
            );
        }
    }

    #[test]
    fn data_address_overflow_precedes_permissions_and_preserves_output() {
        let mut m = GuestMemory::new();
        m.map_region(u64::MAX - 3, 3, P::NO_ACCESS).unwrap();
        let mut out = [0xee; 2];
        assert_eq!(
            m.read_bytes(u64::MAX - 1, &mut out),
            Err(MemoryError::Overflow)
        );
        assert_eq!(out, [0xee; 2]);
        assert_eq!(
            m.write_bytes(u64::MAX - 1, &[1, 2]),
            Err(MemoryError::Overflow)
        );
        assert_eq!(
            m.read_bytes(u64::MAX, &mut out[..1]),
            Err(MemoryError::Overflow)
        );
        assert_eq!(m.write_bytes(u64::MAX, &[1]), Err(MemoryError::Overflow));
        assert_eq!(m.read_u16(u64::MAX - 1), Err(MemoryError::Overflow));
    }

    #[test]
    fn split_data_accesses_keep_exact_fallback_errors_and_atomicity() {
        for (gap, right) in [
            (0, P::READ_WRITE),
            (0, P::READ_ONLY),
            (0, P::NO_ACCESS),
            (
                0,
                P {
                    read: false,
                    write: true,
                    execute: false,
                },
            ),
            (1, P::READ_WRITE),
        ] {
            let mut m = GuestMemory::new();
            m.map_region_with_data(A, 8, P::READ_WRITE, &[0, 1, 2, 3, 4, 5, 6, 7])
                .unwrap();
            let b = A + 8 + gap;
            m.map_region_with_data(b, 8, right, &[8, 9, 10, 11, 12, 13, 14, 15])
                .unwrap();
            let mut expected = m.clone();
            let mut actual_out = [0xee; 4];
            let mut expected_out = [0xee; 4];
            assert_eq!(
                m.read_bytes(A + 6, &mut actual_out),
                expected.read_checked(A + 6, &mut expected_out, Some("read"))
            );
            assert_eq!(actual_out, expected_out);
            assert_eq!(
                actual_out,
                if gap == 0 && right.read {
                    [6, 7, 8, 9]
                } else {
                    [0xee; 4]
                }
            );
            let bytes = [0xa0, 0xa1, 0xa2, 0xa3];
            assert_eq!(
                m.write_bytes(A + 6, &bytes),
                expected.write_checked(A + 6, &bytes, Some("write"))
            );
            let written = gap == 0 && right.write;
            assert_eq!(
                m.read_u64_bypass(A).unwrap().to_le_bytes(),
                if written {
                    [0, 1, 2, 3, 4, 5, 0xa0, 0xa1]
                } else {
                    [0, 1, 2, 3, 4, 5, 6, 7]
                }
            );
            assert_eq!(
                m.read_u64_bypass(b).unwrap().to_le_bytes(),
                if written {
                    [0xa2, 0xa3, 10, 11, 12, 13, 14, 15]
                } else {
                    [8, 9, 10, 11, 12, 13, 14, 15]
                }
            );
        }
    }

    #[test]
    fn data_accesses_keep_first_mapping_priority_for_partial_overlaps() {
        const BASE: u64 = 0x0000_0003_0000_0000;
        for first in [P::READ_WRITE, P::READ_ONLY] {
            let mut m = GuestMemory::new();
            m.map_region(0x1000, 1, P::NO_ACCESS).unwrap();
            m.map_region_with_data(BASE, 4, first, &[1, 2, 3, 4])
                .unwrap();
            let empty = m.map_heap_allocation(PROCESS_HEAP, 0).unwrap();
            assert_eq!(empty, BASE);
            assert_eq!(
                m.resize_heap_allocation(PROCESS_HEAP, empty, 8, true),
                Ok(BASE)
            );
            let mut out = [0xee; 8];
            assert_eq!(m.read_bytes(BASE, &mut out), Ok(()));
            assert_eq!(out, [1, 2, 3, 4, 0, 0, 0, 0]);
            assert_eq!(m.read_u16(BASE), Ok(0x0201));
            let bytes = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
            let mut expected = m.clone();
            assert_eq!(
                m.write_bytes(BASE, &bytes),
                expected.write_checked(BASE, &bytes, Some("write"))
            );
            m.read_bytes(BASE, &mut out).unwrap();
            assert_eq!(
                out,
                if first.write {
                    bytes
                } else {
                    [1, 2, 3, 4, 0, 0, 0, 0]
                }
            );
        }
    }

    #[test]
    fn data_accesses_observe_writes_clones_release_and_remap() {
        let mut m = GuestMemory::new();
        m.map_region_with_data(A, 8, P::READ_WRITE, &[1; 8])
            .unwrap();
        let mut clone = m.clone();
        m.write_u64(A, 0x1122_3344_5566_7788).unwrap();
        clone.write_u32(A, 0xaabb_ccdd).unwrap();
        assert_eq!(m.read_u64(A), Ok(0x1122_3344_5566_7788));
        assert_eq!(clone.read_u64(A), Ok(0x0101_0101_aabb_ccdd));
        let b = m.map_virtual_allocation(0x4000, 2, P::READ_WRITE).unwrap();
        m.write_u16(b, 0x1234).unwrap();
        assert_eq!(m.read_u16(b), Ok(0x1234));
        assert!(m.release_virtual_allocation(b));
        assert_eq!(m.read_u16(b), Err(MemoryError::UnmappedAddress(b)));
        m.map_region_with_data(b, 2, P::READ_ONLY, &[0x56, 0x78])
            .unwrap();
        assert_eq!(m.read_u16(b), Ok(0x7856));
        assert_eq!(
            m.write_u8(b, 0),
            Err(MemoryError::PermissionViolation {
                address: b,
                required: "write"
            })
        );
        assert_eq!(clone.read_u16(b), Err(MemoryError::UnmappedAddress(b)));
    }
}

#[cfg(test)]
mod data_memory_bench {
    use super::{MemoryPermissions as P, *};
    use crate::{CpuState, DbtEngine, ExitReason, Register};
    use std::{hint::black_box, time::Instant};

    const CODE: u64 = 0x1000;
    const VALUE: u64 = 0xffff_ff00;
    #[derive(Clone, Copy)]
    enum Kind {
        Registers,
        Counter,
        Sequential,
        Split,
    }

    fn setting(name: &str, default: usize, maximum: usize) -> usize {
        let value = std::env::var(name).map_or(default, |s| s.parse().expect(name));
        assert!((1..=maximum).contains(&value), "invalid {name}");
        value
    }
    fn quantile(sorted: &[f64], fraction: f64) -> f64 {
        let rank = (sorted.len() - 1) as f64 * fraction;
        let lo = rank.floor() as usize;
        sorted[lo] + (sorted[rank.ceil() as usize] - sorted[lo]) * rank.fract()
    }
    fn guest(kind: Kind, iterations: usize, data: u64) -> (Vec<u8>, usize) {
        // MOV RCX, iterations; MOV RDX, VALUE (control) or RSI, data; XOR EAX,EAX.
        let registers = matches!(kind, Kind::Registers);
        let sequential = matches!(kind, Kind::Sequential);
        let mut code = vec![0x48, 0xb9];
        code.extend_from_slice(&(iterations as u64).to_le_bytes());
        code.extend_from_slice(&[0x48, if registers { 0xba } else { 0xbe }]);
        let target = if registers { VALUE } else { data };
        code.extend_from_slice(&target.to_le_bytes());
        code.extend_from_slice(&[0x31, 0xc0]);
        let per_iteration = if registers {
            // ADD RAX,RDX; ADD RDX,1; DEC RCX; JNZ -12.
            code.extend_from_slice(&[
                0x48, 0x01, 0xd0, 0x48, 0x83, 0xc2, 0x01, 0x48, 0xff, 0xc9, 0x75, 0xf4,
            ]);
            4
        } else {
            // MOV RDX,[RSI]; ADD RAX,RDX; ADD RDX,1; MOV [RSI],RDX.
            code.extend_from_slice(&[
                0x48, 0x8b, 0x16, 0x48, 0x01, 0xd0, 0x48, 0x83, 0xc2, 0x01, 0x48, 0x89, 0x16,
            ]);
            if sequential {
                code.extend_from_slice(&[0x48, 0x83, 0xc6, 0x08]); // ADD RSI,8.
            }
            // DEC RCX; JNZ -22 (sequential) or -18 (counter).
            let back = if sequential { 0xea } else { 0xee };
            code.extend_from_slice(&[0x48, 0xff, 0xc9, 0x75, back]);
            6 + usize::from(sequential)
        };
        code.push(0xf4); // HLT; three setup instructions and one halt.
        (code, iterations * per_iteration + 4)
    }

    // Run identical source on the baseline and candidate with the same release profile.
    // Allocation counting is deliberately separate: instrumentation distorts these timings.
    #[test]
    #[ignore = "manual, correctness-gated warm DBT data-memory timing"]
    fn warm_data_memory_benchmark() {
        let samples = setting("XENORA_DATA_BENCH_SAMPLES", 31, 1001);
        let counter = setting("XENORA_DATA_BENCH_ITERS", 32768, 65536);
        let sequential = setting("XENORA_DATA_BENCH_STREAM_ITERS", 16384, 65536);
        for (label, kind, regions, last) in [
            ("register-control", Kind::Registers, 4, false),
            ("counter-front", Kind::Counter, 4, false),
            ("counter-front-many", Kind::Counter, 64, false),
            ("counter-first", Kind::Counter, 4, false),
            ("counter-first-many", Kind::Counter, 64, false),
            ("counter-third-many", Kind::Counter, 64, false),
            ("counter-middle", Kind::Counter, 64, false),
            ("counter-last", Kind::Counter, 64, true),
            ("sequential-front", Kind::Sequential, 4, false),
            ("sequential-front-many", Kind::Sequential, 64, false),
            ("sequential-first", Kind::Sequential, 4, false),
            ("sequential-first-many", Kind::Sequential, 64, false),
            ("sequential-last", Kind::Sequential, 64, true),
            ("split-counter-control", Kind::Split, 4, false),
        ] {
            let iterations = if matches!(kind, Kind::Sequential) {
                sequential
            } else {
                counter
            };
            let code_address = if label.contains("-first") {
                0x8000_0000
            } else {
                CODE
            };
            let data = if last {
                0x4000_0000
            } else if label.contains("-third") {
                0x20_1000
            } else if label.contains("-middle") {
                0x23_f000
            } else {
                0x1_0000
            };
            let (code, expected_instructions) = guest(kind, iterations, data);
            let words = if matches!(kind, Kind::Sequential) {
                iterations
            } else {
                1
            };
            let initial: Vec<u8> = (0..words)
                .flat_map(|i| (VALUE + i as u64).to_le_bytes())
                .collect();
            let increment = match kind {
                Kind::Registers => 0,
                Kind::Sequential => 1,
                _ => iterations as u64,
            };
            let expected: Vec<u8> = (0..words)
                .flat_map(|i| (VALUE + i as u64 + increment).to_le_bytes())
                .collect();
            let mut memory = GuestMemory::new();
            memory
                .map_region_with_data(code_address, 4096, P::READ_EXECUTE, &code)
                .unwrap();
            let pieces = if matches!(kind, Kind::Split) {
                memory
                    .map_region_with_data(data, 4, P::READ_WRITE, &initial[..4])
                    .unwrap();
                memory
                    .map_region_with_data(data + 4, 4, P::READ_WRITE, &initial[4..])
                    .unwrap();
                2
            } else {
                memory
                    .map_region_with_data(data, initial.len(), P::READ_WRITE, &initial)
                    .unwrap();
                1
            };
            for i in 0..regions - pieces - 1 {
                memory
                    .map_region(0x20_0000 + i as u64 * 8192, 4096, P::READ_ONLY)
                    .unwrap();
            }
            let initial_cpu = CpuState::new(code_address, 0x8000_0000); // No stack instructions.
            let mut dbt = DbtEngine::new(1024 * 1024).unwrap();
            let mut readback = vec![0; initial.len()];
            let n = iterations as u64;
            let sum = n * VALUE + n * (n - 1) / 2;
            let mut timings = Vec::with_capacity(samples);
            let warmups = 5;
            for sample in 0..samples + warmups {
                memory.write_bytes(data, &initial).unwrap();
                let mut cpu = initial_cpu.clone();
                let before = dbt.metrics;
                let started = Instant::now();
                let result = black_box(dbt.run(&mut cpu, &mut memory, expected_instructions + 16));
                let elapsed = started.elapsed();
                assert_eq!(result.exit_reason, ExitReason::Halt, "{label}");
                assert_eq!(
                    result.instructions_executed, expected_instructions,
                    "{label}"
                );
                let state = (
                    cpu.get(Register::Rax),
                    cpu.get(Register::Rdx),
                    cpu.get(Register::Rcx),
                );
                assert_eq!(state, (sum, VALUE + n, 0), "{label}");
                memory.read_bytes(data, &mut readback).unwrap();
                assert_eq!(readback, expected, "{label}");
                assert_eq!(dbt.metrics.interpreter_fallbacks, 0, "{label}");
                if sample > 0 {
                    let compiled = |m: crate::DbtMetrics| {
                        (m.blocks_compiled, m.native_bytes_emitted, m.cache_misses)
                    };
                    assert_eq!(compiled(dbt.metrics), compiled(before), "{label}");
                    if sample >= warmups {
                        timings.push(elapsed.as_nanos() as f64 / n as f64);
                    }
                } else {
                    assert!(dbt.metrics.blocks_compiled > 0, "{label}");
                }
            }
            timings.sort_by(f64::total_cmp);
            println!(
                "warm-data label={label} regions={regions} iterations={iterations} samples={samples} warmups={warmups} instructions={expected_instructions} median_ns_per_iteration={:.3} p10={:.3} p90={:.3}",
                quantile(&timings, 0.5),
                quantile(&timings, 0.1),
                quantile(&timings, 0.9)
            );
        }
    }
}

#[cfg(test)]
mod mapping_group_contract_tests {
    use super::*;

    #[test]
    fn aliases_preserve_bytes_across_resize_relocation_and_release() {
        const BASE: u64 = 0x0000_0003_0000_0000;
        let mut memory = GuestMemory::new();
        memory
            .map_region(BASE - 16, 8, MemoryPermissions::READ_ONLY)
            .unwrap();
        memory
            .map_region_with_data(BASE, 4, MemoryPermissions::READ_ONLY, &[1, 2, 3, 4])
            .unwrap();
        memory
            .map_region(BASE + 0x2000, 8, MemoryPermissions::READ_ONLY)
            .unwrap();
        let heap = memory.create_private_heap(0).unwrap();
        assert_eq!(memory.map_heap_allocation(PROCESS_HEAP, 0), Ok(BASE));
        assert_eq!(memory.map_heap_allocation(heap, 0), Ok(BASE));
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, BASE, 8, true),
            Err(MemoryError::AllocationFailed)
        );
        assert_eq!(memory.resize_heap_allocation(heap, BASE, 8, true), Ok(BASE));
        memory.write_bytes(BASE + 4, &[5, 6, 7, 8]).unwrap();
        assert_eq!(memory.read_u64(BASE), Ok(0x0807_0605_0403_0201));
        // Heap commits are page granular: a growth inside the committed
        // page always stays in place, so the no-room-in-place and move cases
        // exercise with sizes that cross the page boundary.
        assert_eq!(
            memory.resize_heap_allocation(heap, BASE, 0x2001, true),
            Err(MemoryError::AllocationFailed)
        );
        let moved = memory
            .resize_heap_allocation(heap, BASE, 0x2001, false)
            .unwrap();
        assert_ne!(moved, BASE);
        let mut bytes = [0xff; 32];
        memory.read_bytes(moved, &mut bytes).unwrap();
        let mut expected = [0; 32];
        expected[4..8].copy_from_slice(&[5, 6, 7, 8]);
        assert_eq!(bytes, expected);
        let mut failed = [0xff; 8];
        assert_eq!(
            memory.read_bytes(BASE, &mut failed),
            Err(MemoryError::UnmappedAddress(BASE + 4))
        );
        assert_eq!(failed, [0xff; 8]);
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, BASE, 8, true),
            Ok(BASE)
        );
        assert_eq!(memory.read_u64(BASE), Ok(0x0403_0201));
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, BASE, 2, true),
            Ok(BASE)
        );
        assert_eq!(memory.read_u16(BASE + 2), Ok(0x0403));
        assert!(memory.release_heap_allocation(PROCESS_HEAP, BASE));
        assert_eq!(memory.read_u32(BASE), Ok(0x0403_0201));
        assert_eq!(memory.read_u64(BASE - 16), Ok(0));
        assert_eq!(memory.read_u64(BASE + 0x2000), Ok(0));
    }
}

#[cfg(test)]
mod bounds_access_contract_tests {
    use super::*;

    #[test]
    fn permitted_empty_spans_and_high_addresses_keep_exact_bounds() {
        let mut memory = GuestMemory::new();
        memory
            .map_region_with_data(
                u64::MAX - 8,
                8,
                MemoryPermissions::READ_WRITE,
                &[1, 2, 3, 4, 5, 6, 7, 8],
            )
            .unwrap();
        for at in [u64::MAX - 8, u64::MAX - 4, u64::MAX - 1, u64::MAX] {
            assert_eq!(memory.read_bytes(at, &mut []), Ok(()));
            assert_eq!(memory.write_bytes(at, &[]), Ok(()));
        }
        assert_eq!(memory.read_u64(u64::MAX - 8), Ok(0x0807_0605_0403_0201));
        assert_eq!(memory.read_u8(u64::MAX - 1), Ok(8));
        let mut failed = [0xee; 2];
        assert_eq!(
            memory.read_bytes(u64::MAX - 1, &mut failed),
            Err(MemoryError::Overflow)
        );
        assert_eq!(failed, [0xee; 2]);
        assert_eq!(
            memory.write_u16(u64::MAX - 1, 0xffff),
            Err(MemoryError::Overflow)
        );
        assert_eq!(memory.read_u64(u64::MAX - 7), Err(MemoryError::Overflow));
        assert_eq!(
            memory.write_u64(u64::MAX - 7, u64::MAX),
            Err(MemoryError::Overflow)
        );
        memory.write_u8(u64::MAX - 1, 0x99).unwrap();
        let mut actual = [0; 8];
        memory.read_bytes(u64::MAX - 8, &mut actual).unwrap();
        assert_eq!(actual, [1, 2, 3, 4, 5, 6, 7, 0x99]);
    }
}

#[cfg(test)]
mod mapping_search_contract_tests {
    use super::*;

    #[test]
    fn every_mapping_and_gap_keeps_its_bytes_across_table_sizes() {
        const BASE: u64 = 0x40_0000;
        for count in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33] {
            let mut memory = GuestMemory::new();
            for index in (0..count).rev() {
                memory
                    .map_region_with_data(
                        BASE + index as u64 * 0x100,
                        8,
                        MemoryPermissions::READ_WRITE,
                        &[(index + 1) as u8; 8],
                    )
                    .unwrap();
            }
            assert_eq!(
                memory.read_u8(BASE - 1),
                Err(MemoryError::UnmappedAddress(BASE - 1))
            );
            if count == 0 {
                assert_eq!(
                    memory.read_u8(BASE),
                    Err(MemoryError::UnmappedAddress(BASE))
                );
                assert_eq!(
                    memory.write_u8(BASE, 1),
                    Err(MemoryError::UnmappedAddress(BASE))
                );
                assert_eq!(
                    memory.read_bytes(BASE, &mut []),
                    Err(MemoryError::UnmappedAddress(BASE))
                );
            }
            for index in 0..count {
                let address = BASE + index as u64 * 0x100;
                let mut actual = [0; 8];
                memory.read_bytes(address, &mut actual).unwrap();
                assert_eq!(actual, [(index + 1) as u8; 8]);
                let replacement = [0x80 + index as u8; 8];
                memory.write_bytes(address, &replacement).unwrap();
                memory.read_bytes(address, &mut actual).unwrap();
                assert_eq!(actual, replacement);
                assert_eq!(memory.read_bytes(address + 8, &mut []), Ok(()));
                assert_eq!(
                    memory.read_u8(address + 8),
                    Err(MemoryError::UnmappedAddress(address + 8))
                );
                let mut failed = [0xee; 2];
                assert_eq!(
                    memory.read_bytes(address + 7, &mut failed),
                    Err(MemoryError::UnmappedAddress(address + 8))
                );
                assert_eq!(failed, [0xee; 2]);
            }
        }
    }
}

/// An opt-in timing run for region insertion and removal (#106). Run in a
/// release build on an otherwise idle host:
///
/// ```text
/// cargo test --release -p xenora-loader --lib region_maintenance_timing -- --ignored --nocapture
/// ```
///
/// The run uses the public heap mapping surface and the internal exact-base
/// release path. Every returned allocation is removed once and the empty final
/// table is checked.
#[cfg(test)]
mod region_maintenance_timing {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore = "manual region maintenance timing run; release build on an otherwise idle host"]
    fn region_maintenance_timing() {
        for blocks in [1usize, 16, 256, 4096] {
            let started = Instant::now();
            let mut memory = GuestMemory::new();
            let mut bases = Vec::with_capacity(blocks);
            for _ in 0..blocks {
                bases.push(memory.map_heap_allocation(PROCESS_HEAP, 64).unwrap());
            }
            let inserted = started.elapsed();

            let started = Instant::now();
            for &base in bases.iter().rev() {
                assert!(
                    memory.release_dynamic_allocation(base, AllocationKind::Heap(PROCESS_HEAP))
                );
            }
            let removed = started.elapsed();
            assert!(memory.regions.is_empty());
            println!(
                "blocks={blocks} insert={inserted:?} remove={removed:?} insert_per_op={:.1?} remove_per_op={:.1?}",
                inserted / blocks as u32,
                removed / blocks as u32,
            );
        }
    }
}

/// An opt-in timing run for the region lookup (#102). It times data reads,
/// data writes and instruction fetches in tables of 1 to 4096 heap blocks,
/// with code mapped below and above the heap. Run the same source on the
/// baseline and the candidate, in a release build, on an otherwise idle host:
///
/// ```text
/// cargo test --release -p xenora-loader --lib region_lookup_timing -- --ignored --nocapture
/// ```
///
/// Every sample is checked: each block holds its own index, so a lookup that
/// finds the wrong block, or a fetch from the wrong code, fails the run.
#[cfg(test)]
mod region_lookup_timing {
    use super::{MemoryPermissions as P, *};
    use std::hint::black_box;
    use std::time::Instant;

    /// Below the heap, where a program's image is.
    const LOW_CODE: u64 = 0x1_4000_0000;
    /// Above every heap block: the region a front-to-back scan reaches last.
    const HIGH_CODE: u64 = 0x7000_0000_0000;

    fn setting(name: &str, default: usize, maximum: usize) -> usize {
        let value = std::env::var(name).map_or(default, |s| s.parse().expect(name));
        assert!((1..=maximum).contains(&value), "invalid {name}");
        value
    }

    fn quantile(sorted: &[f64], fraction: f64) -> f64 {
        let rank = (sorted.len() - 1) as f64 * fraction;
        let lo = rank.floor() as usize;
        sorted[lo] + (sorted[rank.ceil() as usize] - sorted[lo]) * rank.fract()
    }

    /// The order in which the blocks are visited: xorshift64 from a fixed
    /// seed, so every run and both builds visit the same blocks.
    fn order(blocks: usize, accesses: usize) -> Vec<usize> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        (0..accesses)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state % blocks as u64) as usize
            })
            .collect()
    }

    #[test]
    #[ignore = "manual region lookup timing run; release build on an otherwise idle host"]
    fn region_lookup_timing() {
        let samples = setting("XENORA_LOOKUP_SAMPLES", 31, 1001);
        let accesses = setting("XENORA_LOOKUP_ACCESSES", 65_536, 1 << 22);
        let warmups = 3;
        for blocks in [1usize, 16, 256, 4096] {
            let mut memory = GuestMemory::new();
            memory
                .map_region_with_data(LOW_CODE, 4096, P::READ_EXECUTE, &[0x90; 4096])
                .unwrap();
            let bases: Vec<u64> = (0..blocks)
                .map(|_| memory.map_heap_allocation(PROCESS_HEAP, 64).unwrap())
                .collect();
            assert!(bases.iter().all(|&base| base < HIGH_CODE));
            memory
                .map_region_with_data(HIGH_CODE, 4096, P::READ_EXECUTE, &[0xc3; 4096])
                .unwrap();
            for (index, &base) in bases.iter().enumerate() {
                memory.write_u32(base, index as u32).unwrap();
            }
            let order = order(blocks, accesses);
            let expected_sum: u64 = order.iter().map(|&index| index as u64).sum();
            for label in ["read", "write", "fetch-low", "fetch-high"] {
                let mut timings = Vec::with_capacity(samples);
                for sample in 0..samples + warmups {
                    let started = Instant::now();
                    let checked = match label {
                        "read" => {
                            let mut sum = 0u64;
                            for &index in &order {
                                sum += u64::from(memory.read_u32(black_box(bases[index])).unwrap());
                            }
                            sum
                        }
                        "write" => {
                            for (step, &index) in order.iter().enumerate() {
                                memory
                                    .write_u32(black_box(bases[index] + 4), step as u32)
                                    .unwrap();
                            }
                            0
                        }
                        _ => {
                            let code = if label == "fetch-low" {
                                LOW_CODE
                            } else {
                                HIGH_CODE
                            };
                            let mut sum = 0u64;
                            for step in 0..accesses as u64 {
                                let address = black_box(code + (step & 0xfff));
                                sum += u64::from(memory.fetch_instruction_byte(address).unwrap());
                            }
                            sum
                        }
                    };
                    let elapsed = started.elapsed();
                    let expected = match label {
                        "read" => expected_sum,
                        "write" => 0,
                        "fetch-low" => 0x90 * accesses as u64,
                        _ => 0xc3 * accesses as u64,
                    };
                    assert_eq!(black_box(checked), expected, "{label} blocks={blocks}");
                    if label == "write" {
                        // The last write to each block holds the step it was made at.
                        let mut last = vec![None; blocks];
                        for (step, &index) in order.iter().enumerate() {
                            last[index] = Some(step as u32);
                        }
                        for (index, step) in last.into_iter().enumerate() {
                            if let Some(step) = step {
                                assert_eq!(memory.read_u32(bases[index] + 4), Ok(step));
                            }
                        }
                    }
                    if sample >= warmups {
                        timings.push(elapsed.as_nanos() as f64 / accesses as f64);
                    }
                }
                timings.sort_by(f64::total_cmp);
                println!(
                    "region-lookup op={label} blocks={blocks} regions={} accesses={accesses} samples={samples} warmups={warmups} median_ns_per_access={:.3} p10={:.3} p90={:.3}",
                    blocks + 2,
                    quantile(&timings, 0.5),
                    quantile(&timings, 0.1),
                    quantile(&timings, 0.9)
                );
            }
        }
    }
}

/// What a lookup finds in large tables (#102). Expected values follow from
/// the layouts built here and the contract the other tests pin: the earliest
/// mapping that covers a byte supplies it, an access may continue into the
/// next mapping, and a failure reports the lowest address it may not touch.
#[cfg(test)]
mod region_lookup_contract_tests {
    use super::{MemoryPermissions as P, *};

    /// Where a zero-size dynamic allocation is placed when a mapping starts
    /// there: the first candidate base.
    const SHARED: u64 = 0x0000_0003_0000_0000;
    const LOW: u64 = 0x10_0000;
    const HIGH: u64 = 0x5_0000_0000;
    const STRIDE: u64 = 0x100;
    const SIZE: usize = 0x40;

    fn byte_of(index: usize) -> u8 {
        (index % 251) as u8 + 1
    }

    fn permissions_of(index: usize) -> P {
        if index % 3 == 2 {
            P::READ_ONLY
        } else {
            P::READ_WRITE_EXECUTE
        }
    }

    /// `count` mappings from `start`, each `SIZE` bytes of one value, with
    /// empty mappings at the base and the end of every fifth one.
    fn map_run(memory: &mut GuestMemory, start: u64, first: usize, count: usize) {
        for index in first..first + count {
            let base = start + (index - first) as u64 * STRIDE;
            if index % 5 == 0 {
                memory.map_region(base, 0, P::NO_ACCESS).unwrap();
            }
            memory
                .map_region_with_data(base, SIZE, permissions_of(index), &[byte_of(index); SIZE])
                .unwrap();
            if index % 5 == 0 {
                memory.map_region(base, 0, P::NO_ACCESS).unwrap();
                memory
                    .map_region(base + SIZE as u64, 0, P::READ_WRITE_EXECUTE)
                    .unwrap();
            }
        }
    }

    /// Check every mapping of a run and the gaps around it.
    fn check_run(memory: &mut GuestMemory, start: u64, first: usize, count: usize) {
        for index in first..first + count {
            let base = start + (index - first) as u64 * STRIDE;
            let end = base + SIZE as u64;
            let byte = byte_of(index);
            let permissions = permissions_of(index);
            for at in [base, base + 1, end - 1] {
                assert_eq!(memory.read_u8(at), Ok(byte), "{at:#x}");
                assert_eq!(
                    memory.fetch_instruction_byte(at),
                    if permissions.execute {
                        Ok(byte)
                    } else {
                        Err(MemoryError::PermissionViolation {
                            address: at,
                            required: "execute",
                        })
                    },
                    "{at:#x}"
                );
            }
            let mut out = [0u8; SIZE];
            assert_eq!(memory.read_bytes(base, &mut out), Ok(()));
            assert_eq!(out, [byte; SIZE]);
            let written = if permissions.write {
                Ok(())
            } else {
                Err(MemoryError::PermissionViolation {
                    address: base + 2,
                    required: "write",
                })
            };
            assert_eq!(memory.write_u8(base + 2, byte), written, "{base:#x}");
            for gap in [base - 1, end] {
                assert_eq!(memory.read_u8(gap), Err(MemoryError::UnmappedAddress(gap)));
                assert_eq!(
                    memory.fetch_instruction_byte(gap),
                    Err(MemoryError::UnmappedAddress(gap))
                );
            }
            // Running off the end reports the first unmapped byte, and the
            // output is untouched.
            let mut failed = [0xee; 4];
            assert_eq!(
                memory.read_bytes(end - 2, &mut failed),
                Err(MemoryError::UnmappedAddress(end))
            );
            assert_eq!(failed, [0xee; 4]);
            assert_eq!(memory.read_bytes(end, &mut []), Ok(()), "{end:#x}");
        }
    }

    #[test]
    fn large_tables_keep_every_mapping_gap_and_permission() {
        let mut memory = GuestMemory::new();
        map_run(&mut memory, HIGH, 700, 700);
        map_run(&mut memory, LOW, 0, 700);
        check_run(&mut memory, LOW, 0, 700);
        check_run(&mut memory, HIGH, 700, 700);
        assert_eq!(memory.read_u8(0), Err(MemoryError::UnmappedAddress(0)));
        let last = HIGH + 699 * STRIDE + SIZE as u64;
        assert_eq!(
            memory.fetch_instruction_byte(u64::MAX - 1),
            Err(MemoryError::UnmappedAddress(u64::MAX - 1))
        );
        assert_eq!(
            memory.read_u8(last + 0x1000),
            Err(MemoryError::UnmappedAddress(last + 0x1000))
        );
    }

    #[test]
    fn overlapping_mappings_keep_first_mapping_priority_in_a_large_table() {
        let mut memory = GuestMemory::new();
        map_run(&mut memory, LOW, 0, 400);
        map_run(&mut memory, HIGH, 400, 400);
        // A mapping at the first candidate base, then two empty heap blocks,
        // one per heap, that land on it and grow in place over it: three
        // mappings at one base, in the order they were made.
        memory
            .map_region_with_data(SHARED, 4, P::READ_EXECUTE, &[1, 2, 3, 4])
            .unwrap();
        let first = memory.map_heap_allocation(PROCESS_HEAP, 0).unwrap();
        assert_eq!(first, SHARED);
        assert_eq!(
            memory.resize_heap_allocation(PROCESS_HEAP, first, 8, true),
            Ok(SHARED)
        );
        let heap = memory.create_private_heap(0).unwrap();
        let second = memory.map_heap_allocation(heap, 0).unwrap();
        assert_eq!(second, SHARED);
        assert_eq!(
            memory.resize_heap_allocation(heap, second, 12, true),
            Ok(SHARED)
        );
        // Bytes 0-3 come from the mapping, 4-7 from the first block and 8-11
        // from the second; both blocks start zeroed.
        let mut out = [0xee; 12];
        assert_eq!(memory.read_bytes(SHARED, &mut out), Ok(()));
        assert_eq!(out, [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
        // The mapping is not writable, so a write that starts in it fails at
        // its first byte and writes nothing.
        assert_eq!(
            memory.write_u8(SHARED + 1, 9),
            Err(MemoryError::PermissionViolation {
                address: SHARED + 1,
                required: "write",
            })
        );
        // The blocks are writable and not executable.
        assert_eq!(memory.write_u8(SHARED + 5, 0x55), Ok(()));
        assert_eq!(memory.write_u8(SHARED + 9, 0x99), Ok(()));
        assert_eq!(memory.read_u8(SHARED + 5), Ok(0x55));
        assert_eq!(memory.read_u8(SHARED + 9), Ok(0x99));
        assert_eq!(memory.fetch_instruction_byte(SHARED + 3), Ok(4));
        for at in [SHARED + 4, SHARED + 11] {
            assert_eq!(
                memory.fetch_instruction_byte(at),
                Err(MemoryError::PermissionViolation {
                    address: at,
                    required: "execute",
                })
            );
        }
        // A write across the mapping into the blocks fails at the mapping;
        // one that starts in the first block runs on into the second.
        assert_eq!(
            memory.write_bytes(SHARED + 2, &[7; 4]),
            Err(MemoryError::PermissionViolation {
                address: SHARED + 2,
                required: "write",
            })
        );
        assert_eq!(memory.write_bytes(SHARED + 6, &[7; 6]), Ok(()));
        // Heap commits are page granular, so the blocks do not end at their
        // exact sizes: the slack reads back as zeroes, and memory ends at
        // the end of the shared commit page instead.
        let mut out = [0xee; 13];
        memory.read_bytes(SHARED, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 0, 0x55, 7, 7, 7, 7, 7, 7, 0]);
        let mut out = [0xee; 12];
        memory.read_bytes(SHARED, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 0, 0x55, 7, 7, 7, 7, 7, 7]);
        assert_eq!(
            memory.read_u8(SHARED + 0x1000),
            Err(MemoryError::UnmappedAddress(SHARED + 0x1000))
        );
        check_run(&mut memory, LOW, 0, 400);
        check_run(&mut memory, HIGH, 400, 400);
    }

    #[test]
    fn accesses_split_across_adjacent_mappings_in_a_large_table() {
        let mut memory = GuestMemory::new();
        map_run(&mut memory, LOW, 0, 500);
        // Three adjacent mappings in the middle of the table, the last not
        // readable.
        const SPLIT: u64 = 0x2_0000_0000;
        memory
            .map_region_with_data(SPLIT, 8, P::READ_WRITE, &[0x11; 8])
            .unwrap();
        memory
            .map_region_with_data(SPLIT + 8, 8, P::READ_EXECUTE, &[0x22; 8])
            .unwrap();
        memory
            .map_region_with_data(SPLIT + 16, 8, P::NO_ACCESS, &[0x33; 8])
            .unwrap();
        map_run(&mut memory, HIGH, 500, 500);
        // Twelve bytes from the middle of the first mapping run on through
        // the second.
        let mut out = [0u8; 12];
        assert_eq!(memory.read_bytes(SPLIT + 4, &mut out), Ok(()));
        assert_eq!(
            out,
            [
                0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
            ]
        );
        // One byte further reaches the mapping that cannot be read.
        let mut out = [0xee; 13];
        assert_eq!(
            memory.read_bytes(SPLIT + 4, &mut out),
            Err(MemoryError::PermissionViolation {
                address: SPLIT + 16,
                required: "read",
            })
        );
        assert_eq!(out, [0xee; 13]);
        assert_eq!(
            memory.write_bytes(SPLIT + 4, &[0x44; 8]),
            Err(MemoryError::PermissionViolation {
                address: SPLIT + 8,
                required: "write",
            })
        );
        assert_eq!(memory.read_u64(SPLIT), Ok(0x1111_1111_1111_1111));
        assert_eq!(
            memory.fetch_instruction_byte(SPLIT + 7),
            Err(MemoryError::PermissionViolation {
                address: SPLIT + 7,
                required: "execute"
            })
        );
        assert_eq!(memory.fetch_instruction_byte(SPLIT + 8), Ok(0x22));
        assert_eq!(
            memory.read_u8(SPLIT + 24),
            Err(MemoryError::UnmappedAddress(SPLIT + 24))
        );
        check_run(&mut memory, LOW, 0, 500);
        check_run(&mut memory, HIGH, 500, 500);
    }
}

/// The indexed lookup against the front-to-back scan it replaced (#102),
/// after random sequences of every operation that changes the table.
#[cfg(test)]
mod region_lookup_differential_tests {
    use super::{MemoryPermissions as P, *};

    /// Where fixed mappings and dynamic allocations meet: dynamic bases
    /// start here, on 64 KiB boundaries.
    const WINDOW: u64 = 0x0000_0003_0000_0000;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }

        fn pick<T: Copy>(&mut self, items: &[T]) -> T {
            items[self.below(items.len() as u64) as usize]
        }
    }

    /// The lookup before #102: the first region, from the front, that ends
    /// after `address`.
    fn scanned(memory: &GuestMemory, address: u64) -> Option<usize> {
        memory
            .regions
            .iter()
            .position(|region| region.base + region.data.len() as u64 > address)
    }

    /// The resolver before #102, unchanged: the same loop from the front of
    /// the table.
    fn resolve_scanned(
        memory: &GuestMemory,
        address: u64,
        len: usize,
        required: Option<&'static str>,
    ) -> Result<Vec<(usize, usize, usize)>, MemoryError> {
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::Overflow)?;
        if len == 0 {
            return if memory.regions.iter().any(|r| r.contains(address, 0)) {
                Ok(Vec::new())
            } else {
                Err(MemoryError::UnmappedAddress(address))
            };
        }
        let mut pieces = Vec::new();
        let mut cursor = address;
        for (index, region) in memory.regions.iter().enumerate() {
            let region_end = region.base + region.data.len() as u64;
            if region_end <= cursor {
                continue;
            }
            if region.base > cursor {
                break;
            }
            let permitted = match required {
                None => true,
                Some("read") => region.permissions.read,
                Some("write") => region.permissions.write,
                Some(_) => region.permissions.execute,
            };
            if let (false, Some(required)) = (permitted, required) {
                return Err(MemoryError::PermissionViolation {
                    address: cursor,
                    required,
                });
            }
            let take = (end.min(region_end) - cursor) as usize;
            pieces.push((index, (cursor - region.base) as usize, take));
            cursor += take as u64;
            if cursor == end {
                return Ok(pieces);
            }
        }
        Err(MemoryError::UnmappedAddress(cursor))
    }

    /// The order and the invariant `first_ending_after` relies on.
    fn check_table(memory: &GuestMemory) {
        let regions = &memory.regions;
        assert!(regions.windows(2).all(|pair| pair[0].base <= pair[1].base));
        for outer in regions {
            let outer_end = outer.base + outer.data.len() as u64;
            for inner in regions {
                assert!(
                    !(outer.base < inner.base && inner.base < outer_end),
                    "base {:#x} inside [{:#x}, {outer_end:#x})",
                    inner.base,
                    outer.base
                );
            }
        }
    }

    fn change(memory: &mut GuestMemory, rng: &mut Rng, heaps: &mut Vec<u64>) {
        let permissions = rng.pick(&[
            P::NO_ACCESS,
            P::READ_ONLY,
            P::READ_WRITE,
            P::READ_EXECUTE,
            P::READ_WRITE_EXECUTE,
        ]);
        let size = rng.pick(&[0usize, 0, 1, 8, 0x40, 0x4000, 0x1_0000, 0x1_8000]);
        let heap_blocks: Vec<(u64, u64)> = memory
            .regions
            .iter()
            .filter_map(|region| match region.allocation {
                AllocationKind::Heap(heap) => Some((heap, region.base)),
                _ => None,
            })
            .collect();
        match rng.below(10) {
            0 | 1 => {
                let base = if rng.below(16) == 0 {
                    u64::MAX - rng.below(0x100)
                } else {
                    WINDOW + rng.below(48) * 0x8000 + rng.pick(&[0, 0, 4, 0x40])
                };
                let size = size.min((u64::MAX - base) as usize);
                let _ = memory.map_region(base, size, permissions);
            }
            2 => {
                let fixed = WINDOW + rng.below(48) * 0x8000;
                let base = rng.pick(&[0, fixed]);
                let _ = memory.map_virtual_allocation(base, size, permissions);
            }
            3 | 4 => {
                let heap = rng.pick(heaps);
                let _ = memory.map_heap_allocation(heap, rng.pick(&[0, 0, 1, 8, 0x40]));
            }
            5 | 6 if !heap_blocks.is_empty() => {
                let (heap, base) = rng.pick(&heap_blocks);
                let _ = memory.resize_heap_allocation(heap, base, size, rng.below(2) == 0);
            }
            7 if !heap_blocks.is_empty() => {
                let (heap, base) = rng.pick(&heap_blocks);
                assert!(memory.release_heap_allocation(heap, base));
            }
            8 => {
                let virtual_bases: Vec<u64> = memory
                    .regions
                    .iter()
                    .filter(|region| region.allocation == AllocationKind::Virtual)
                    .map(|region| region.base)
                    .collect();
                if virtual_bases.is_empty() {
                    let _ = memory.map_thread_region(0, size, permissions);
                } else {
                    assert!(memory.release_virtual_allocation(rng.pick(&virtual_bases)));
                }
            }
            _ => {
                if heaps.len() > 1 && rng.below(3) == 0 {
                    let heap = heaps.remove(1 + rng.below(heaps.len() as u64 - 1) as usize);
                    assert!(memory.destroy_private_heap(heap));
                } else if let Some(heap) = memory.create_private_heap(0) {
                    heaps.push(heap);
                }
            }
        }
    }

    #[test]
    fn indexed_lookup_matches_a_front_to_back_scan_after_random_changes() {
        let (mut shared_bases, mut overlaps) = (0usize, 0usize);
        for seed in 1..=32u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut memory = GuestMemory::new();
            let mut heaps = vec![PROCESS_HEAP];
            for _ in 0..120 {
                change(&mut memory, &mut rng, &mut heaps);
                check_table(&memory);
                let regions = &memory.regions;
                shared_bases += regions
                    .windows(2)
                    .filter(|pair| pair[0].base == pair[1].base)
                    .count();
                overlaps += regions
                    .windows(2)
                    .filter(|pair| {
                        pair[0].base == pair[1].base
                            && !pair[0].data.is_empty()
                            && !pair[1].data.is_empty()
                    })
                    .count();
                let mut probes = vec![0, 1, WINDOW - 1, u64::MAX - 1, u64::MAX];
                for region in regions {
                    let end = region.base + region.data.len() as u64;
                    for probe in [region.base, end] {
                        probes.extend([probe.wrapping_sub(1), probe, probe.wrapping_add(1)]);
                    }
                }
                for _ in 0..16 {
                    probes.push(WINDOW + rng.below(48 * 0x8000 + 0x2_0000));
                }
                for &probe in &probes {
                    assert_eq!(
                        memory.first_ending_after(probe).map(|(index, _)| index),
                        scanned(&memory, probe),
                        "seed {seed} probe {probe:#x}"
                    );
                    for len in [0usize, 1, 2, 7, 0x41, 0x1_0001] {
                        for required in [None, Some("read"), Some("write"), Some("execute")] {
                            assert_eq!(
                                memory.resolve(probe, len, required),
                                resolve_scanned(&memory, probe, len, required),
                                "seed {seed} probe {probe:#x} len {len} {required:?}"
                            );
                        }
                    }
                }
            }
        }
        // The runs must reach the layouts the invariant is about: mappings
        // that share a base, and non-empty ones that overlap.
        eprintln!("shared bases {shared_bases}, overlaps {overlaps}");
        assert!(shared_bases > 0, "no two mappings ever shared a base");
        assert!(overlaps > 0, "no two non-empty mappings ever overlapped");
    }
}
