// SPDX-License-Identifier: GPL-3.0-or-later

//! Guest-callable graphics command path exported from `xenora_graphics.dll`.
//!
//! The D3D12-style runtime in [`crate::graphics`] is complete, but a guest
//! program could not reach it: the only guest-reachable path was the rigid
//! `xenora_fixture.dll!SubmitGuestDraw` helper, which created its own
//! objects and issued one fixed three-vertex draw. This module exposes the
//! real command path to guest code: device, queue, allocator, command list,
//! buffer and render-target resources, state binding, draws, execution,
//! framebuffer readback, timeline fences and ordered destruction. A guest can also bind a
//! texture: descriptor heaps, shader resource views, samplers and root
//! signatures are reachable from guest code, and the service computes every
//! descriptor handle so that the guest never sees a host pointer.
//!
//! Every export uses the Win64 calling convention and returns an `HRESULT`
//! in `RAX`. Object handles are opaque generation-checked `u64` values that
//! the guest passes back exactly as it received them; out-parameters are
//! guest pointers. A recoverable misuse is reported as a failure `HRESULT`,
//! never as a guest fault, so a bad argument cannot stop the guest.

use super::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ServicesState};
use crate::cpu::ExitReason;
use crate::graphics::{
    CommandListType, D3D12_FILTER_MIN_MAG_MIP_POINT, D3D12_TEXTURE_ADDRESS_MODE_CLAMP,
    DXGI_FORMAT_R8G8B8A8_UNORM, DescriptorRange, DescriptorRangeType, GraphicsBackendId,
    GraphicsContext, GraphicsError, GraphicsHandle, IndexFormat, ResourceDesc, ResourceDimension,
    ResourceStates, RootParameter, RootSignatureDesc, SamplerDesc, ShaderResourceViewDesc,
    ShaderVisibility, SrvDimension,
};
use crate::imports::{ImportRegistry, ServiceStatus, Win64Args};
use crate::memory::{GuestMemory, MemoryError};
use crate::runtime::HResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

const MODULE: &str = "xenora_graphics.dll";
const ERROR_TIMEOUT: u32 = 1460;

/// The smallest vertex stride the runtime accepts: one `float4` position.
/// A flat draw reads three consecutive `float4` positions and ignores the
/// stride, so a flat guest may bind 16-byte records. A textured draw reads the
/// texture coordinate that follows each position and needs a stride of at
/// least 32 bytes.
const MIN_VERTEX_STRIDE: usize = 16;
/// The largest viewport the guest may ask for.
const MAX_VIEWPORT_DIMENSION: u32 = 4096;
/// Backend id of the deterministic software reference rasteriser.
const BACKEND_SOFTWARE_REFERENCE: u32 = 0;
/// Backend id of the native Metal backend.
const BACKEND_METAL_NATIVE: u32 = 1;
/// The `D3D12_DESCRIPTOR_HEAP_TYPE` of a heap of shader resource views,
/// constant buffers and unordered access views.
const HEAP_TYPE_CBV_SRV_UAV: u32 = 0;
/// The `D3D12_DESCRIPTOR_HEAP_TYPE` of a heap of samplers.
const HEAP_TYPE_SAMPLER: u32 = 1;
/// The address mode the guest ABI calls clamp addressing. The D3D12 code for
/// the same mode, `D3D12_TEXTURE_ADDRESS_MODE_CLAMP`, is accepted as well.
const SAMPLER_ADDRESS_CLAMP: u32 = 1;

/// `S_OK`.
fn ok() -> u64 {
    HResult::OK.guest_return()
}

/// `E_INVALIDARG`.
fn invalid_arg() -> u64 {
    HResult::from_win32(ERROR_INVALID_PARAMETER).guest_return()
}

/// `E_ACCESSDENIED`.
fn access_denied() -> u64 {
    HResult::from_win32(ERROR_ACCESS_DENIED).guest_return()
}

/// The `HRESULT` a runtime error maps to.
fn hresult(error: &GraphicsError) -> u64 {
    match error {
        GraphicsError::InvalidDeviceHandle
        | GraphicsError::InvalidQueueHandle
        | GraphicsError::InvalidAllocatorHandle
        | GraphicsError::InvalidCommandListHandle
        | GraphicsError::InvalidFenceHandle
        | GraphicsError::InvalidResourceHandle => invalid_arg(),
        GraphicsError::ResourceLifetimeViolation => access_denied(),
        GraphicsError::FenceTimeout { .. } => HResult::from_win32(ERROR_TIMEOUT).guest_return(),
        _ => HResult::FAIL.guest_return(),
    }
}

/// Whether an error means the handle the guest passed does not name an
/// object of the expected kind.
fn is_invalid_handle(error: &GraphicsError) -> bool {
    matches!(
        error,
        GraphicsError::InvalidDeviceHandle
            | GraphicsError::InvalidQueueHandle
            | GraphicsError::InvalidAllocatorHandle
            | GraphicsError::InvalidCommandListHandle
            | GraphicsError::InvalidFenceHandle
            | GraphicsError::InvalidResourceHandle
    )
}

/// The `HRESULT` a binding error maps to. An invalid descriptor, an
/// unsupported value or an invalid handle is `E_INVALIDARG`, a lifetime
/// violation is `E_ACCESSDENIED`, and any other error is `E_FAIL`.
fn binding_hresult(error: &GraphicsError) -> u64 {
    match error {
        GraphicsError::InvalidDescriptor | GraphicsError::Unsupported(_) => invalid_arg(),
        GraphicsError::ResourceLifetimeViolation => access_denied(),
        _ => hresult(error),
    }
}

/// The handle values a guest argument may name: the value itself, and, when
/// the value does not name an object, the handle stored at that address.
/// The second form lets a guest pass a pointer to a handle slot.
fn handle_candidates(raw: u64, memory: &GuestMemory) -> Vec<u64> {
    let mut candidates = vec![raw];
    if raw != 0
        && let Ok(stored) = memory.read_u64(raw)
        && stored != raw
    {
        candidates.push(stored);
    }
    candidates
}

/// Run `op` with the handle the guest passed, reporting the error of the
/// last candidate when none of them names an object.
fn with_handle<T>(
    raw: u64,
    memory: &GuestMemory,
    missing: GraphicsError,
    mut op: impl FnMut(GraphicsHandle) -> Result<T, GraphicsError>,
) -> Result<T, GraphicsError> {
    let mut last = missing;
    for candidate in handle_candidates(raw, memory) {
        match op(GraphicsHandle::from_u64(candidate)) {
            Ok(value) => return Ok(value),
            Err(error) => {
                if is_invalid_handle(&error) {
                    last = error;
                    continue;
                }
                return Err(error);
            }
        }
    }
    Err(last)
}

/// A descriptor heap the guest created, remembered so that a slot can be
/// checked against the heap's own descriptor count before a descriptor is
/// written or a table is bound.
#[derive(Clone, Copy)]
struct GuestHeap {
    /// The `D3D12_DESCRIPTOR_HEAP_TYPE` the heap was created with.
    heap_type: u32,
    /// The number of descriptors the heap holds.
    num_descriptors: u32,
    /// The device that created the heap.
    device: u64,
}

/// The descriptor heaps of every live graphics context, keyed by the
/// context's address and the heap's handle. The weak reference keeps the
/// context's allocation, and so its address, reserved while the entry lives.
type HeapRegistry = HashMap<(usize, u64), (Weak<Mutex<GraphicsContext>>, GuestHeap)>;

/// The registry of the descriptor heaps the guest created.
fn heap_registry() -> &'static Mutex<HeapRegistry> {
    static REGISTRY: OnceLock<Mutex<HeapRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The address of a context's graphics state, which names it uniquely while
/// its allocation lives.
fn context_address(state: &Arc<ServicesState>) -> usize {
    Arc::as_ptr(&state.graphics) as *const () as usize
}

/// Remember a heap the guest created.
fn remember_heap(state: &Arc<ServicesState>, heap: GraphicsHandle, info: GuestHeap) {
    let key = (context_address(state), heap.to_u64());
    let Ok(mut registry) = heap_registry().lock() else {
        return;
    };
    registry.insert(key, (Arc::downgrade(&state.graphics), info));
}

/// What the guest created a descriptor heap as, if the handle names a heap
/// of this context.
fn known_heap(state: &Arc<ServicesState>, heap: GraphicsHandle) -> Option<GuestHeap> {
    let key = (context_address(state), heap.to_u64());
    let mut registry = heap_registry().lock().ok()?;
    let alive = registry
        .get(&key)
        .is_some_and(|(context, _)| context.strong_count() > 0);
    if !alive {
        registry.remove(&key);
        return None;
    }
    registry.get(&key).map(|(_, info)| *info)
}

/// The descriptor heap a guest argument names, together with what the guest
/// created it as. The argument may be the handle itself or a guest pointer
/// to a handle slot.
fn named_heap(
    state: &Arc<ServicesState>,
    raw: u64,
    memory: &GuestMemory,
) -> Option<(GraphicsHandle, GuestHeap)> {
    handle_candidates(raw, memory)
        .into_iter()
        .find_map(|candidate| {
            let handle = GraphicsHandle::from_u64(candidate);
            known_heap(state, handle).map(|info| (handle, info))
        })
}

/// The D3D12 address mode a guest address mode names, if it names one that
/// the runtime supports.
fn guest_address_mode(value: u32) -> Option<u32> {
    match value {
        SAMPLER_ADDRESS_CLAMP | D3D12_TEXTURE_ADDRESS_MODE_CLAMP => {
            Some(D3D12_TEXTURE_ADDRESS_MODE_CLAMP)
        }
        _ => None,
    }
}

/// The shared graphics runtime, locked for one call.
fn lock_graphics(
    state: &Arc<ServicesState>,
) -> Result<MutexGuard<'_, GraphicsContext>, ExitReason> {
    state
        .graphics
        .lock()
        .map_err(|_| ExitReason::MemoryFault(MemoryError::Overflow))
}

/// Check the output slot before any object is created, so a call that cannot
/// hand its handle back does not leak the object it made.
fn writable_out(memory: &GuestMemory, out: u64) -> bool {
    memory.check_write(out, 8).is_ok()
}

/// Create a device and write its handle to `*ppDevice`.
fn xenora_create_device(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let out = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0 || !writable_out(memory, out) {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let device = match graphics.create_device() {
        Ok(device) => device,
        Err(error) => return Ok(hresult(&error)),
    };
    if memory.write_u64(out, device.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Create a command queue for a device.
fn xenora_create_command_queue(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let list_type = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let out = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    if list_type != 0 || out == 0 || !writable_out(memory, out) {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let queue = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| graphics.create_command_queue(handle, CommandListType::Direct),
    ) {
        Ok(queue) => queue,
        Err(error) => return Ok(hresult(&error)),
    };
    if memory.write_u64(out, queue.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Create a timeline fence at a guest-supplied initial value.
fn xenora_create_fence(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let initial = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let out = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0 || !writable_out(memory, out) {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let fence = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| graphics.create_fence(handle, initial),
    ) {
        Ok(fence) => fence,
        Err(error) => return Ok(binding_hresult(&error)),
    };
    if memory.write_u64(out, fence.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Apply a queue operation with the same device and handle checks for waits and signals.
fn queue_fence(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &GuestMemory,
    operation: fn(
        &mut GraphicsContext,
        GraphicsHandle,
        GraphicsHandle,
        u64,
    ) -> Result<(), GraphicsError>,
) -> Result<u64, ExitReason> {
    let queue = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let fence = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let value = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        queue,
        memory,
        GraphicsError::InvalidQueueHandle,
        |queue_handle| {
            with_handle(
                fence,
                memory,
                GraphicsError::InvalidFenceHandle,
                |fence_handle| operation(&mut graphics, queue_handle, fence_handle, value),
            )
        },
    );
    Ok(result.map_or_else(|error| binding_hresult(&error), |()| ok()))
}

fn xenora_queue_wait(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    queue_fence(state, args, memory, GraphicsContext::queue_wait)
}

fn xenora_queue_signal(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    queue_fence(state, args, memory, GraphicsContext::queue_signal)
}

/// Write the completed fence value to `*pValue`.
fn xenora_get_fence_completed_value(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let fence = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let out = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0 || !writable_out(memory, out) {
        return Ok(invalid_arg());
    }
    let graphics = lock_graphics(state)?;
    let value = match with_handle(fence, memory, GraphicsError::InvalidFenceHandle, |handle| {
        graphics.fence_completed_value(handle)
    }) {
        Ok(value) => value,
        Err(error) => return Ok(binding_hresult(&error)),
    };
    if memory.write_u64(out, value).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

fn xenora_destroy_fence(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let fence = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(fence, memory, GraphicsError::InvalidFenceHandle, |handle| {
        graphics.destroy_fence(handle)
    });
    Ok(result.map_or_else(|error| binding_hresult(&error), |()| ok()))
}

/// Create a command allocator for a device.
fn xenora_create_command_allocator(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let list_type = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let out = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    if list_type != 0 || out == 0 || !writable_out(memory, out) {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let allocator = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| graphics.create_command_allocator(handle, CommandListType::Direct),
    ) {
        Ok(allocator) => allocator,
        Err(error) => return Ok(hresult(&error)),
    };
    if memory.write_u64(out, allocator.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Create a recording command list.
fn xenora_create_command_list(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let allocator = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let list_type = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let out = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
    if list_type != 0 || out == 0 || !writable_out(memory, out) {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let list = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| {
            with_handle(
                allocator,
                memory,
                GraphicsError::InvalidAllocatorHandle,
                |allocator_handle| {
                    graphics.create_command_list(handle, allocator_handle, CommandListType::Direct)
                },
            )
        },
    ) {
        Ok(list) => list,
        Err(error) => return Ok(hresult(&error)),
    };
    if memory.write_u64(out, list.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Create a buffer whose contents are the guest bytes at `guestAddr`.
fn xenora_create_buffer(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let guest_addr = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let byte_length = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    let out = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0 || !writable_out(memory, out) || guest_addr == 0 || byte_length == 0 {
        return Ok(invalid_arg());
    }
    let desc = ResourceDesc {
        dimension: ResourceDimension::Buffer,
        width: byte_length,
        height: 1,
        depth_or_array_size: 1,
        mip_levels: 1,
        format_rgba8: false,
    };
    let mut graphics = lock_graphics(state)?;
    let resource = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| {
            graphics.create_committed_resource(
                handle,
                desc.clone(),
                ResourceStates::VERTEX_AND_CONSTANT_BUFFER,
                Some(guest_addr),
            )
        },
    ) {
        Ok(resource) => resource,
        Err(error) => return Ok(hresult(&error)),
    };
    if memory.write_u64(out, resource.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Create an `R8G8B8A8_UNORM` two-dimensional render target.
fn xenora_create_render_target(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let width = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let height = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let out = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0 || !writable_out(memory, out) || width == 0 || height == 0 {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let resource = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| {
            graphics.create_committed_texture2d(
                handle,
                width,
                height,
                DXGI_FORMAT_R8G8B8A8_UNORM,
                ResourceStates::RENDER_TARGET,
                None,
            )
        },
    ) {
        Ok(resource) => resource,
        Err(error) => return Ok(hresult(&error)),
    };
    if memory.write_u64(out, resource.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Create an `R8G8B8A8_UNORM` two-dimensional texture whose pixels are the
/// guest bytes at `guestAddr`. A `guestAddr` of zero creates a texture with
/// no guest backing.
fn xenora_create_texture2d(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let width = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let height = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let format = args.get(3, memory).map_err(ExitReason::MemoryFault)? as u32;
    let guest_addr = args.get(4, memory).map_err(ExitReason::MemoryFault)?;
    let out = args.get(5, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0 || !writable_out(memory, out) || format != DXGI_FORMAT_R8G8B8A8_UNORM {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let resource = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| {
            graphics.create_committed_texture2d(
                handle,
                width,
                height,
                DXGI_FORMAT_R8G8B8A8_UNORM,
                ResourceStates::COMMON,
                (guest_addr != 0).then_some(guest_addr),
            )
        },
    ) {
        Ok(resource) => resource,
        Err(error) => return Ok(binding_hresult(&error)),
    };
    if memory.write_u64(out, resource.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Create a shader-visible descriptor heap of `numDescriptors` descriptors.
fn xenora_create_descriptor_heap(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let heap_type = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let num_descriptors = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let out = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0
        || !writable_out(memory, out)
        || !matches!(heap_type, HEAP_TYPE_CBV_SRV_UAV | HEAP_TYPE_SAMPLER)
    {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let mut creator = None;
    let heap = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| {
            creator = Some(handle.to_u64());
            graphics.create_descriptor_heap(handle, heap_type, num_descriptors, true)
        },
    ) {
        Ok(heap) => heap,
        Err(error) => return Ok(binding_hresult(&error)),
    };
    if memory.write_u64(out, heap.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    remember_heap(
        state,
        heap,
        GuestHeap {
            heap_type,
            num_descriptors,
            device: creator.unwrap_or(0),
        },
    );
    Ok(ok())
}

/// Write a shader resource view over a texture into a heap slot.
fn xenora_create_shader_resource_view(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let heap = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let slot = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let resource = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
    let format = args.get(4, memory).map_err(ExitReason::MemoryFault)? as u32;
    if format != DXGI_FORMAT_R8G8B8A8_UNORM {
        return Ok(invalid_arg());
    }
    let Some((heap_handle, heap_info)) = named_heap(state, heap, memory) else {
        return Ok(invalid_arg());
    };
    if heap_info.heap_type != HEAP_TYPE_CBV_SRV_UAV
        || slot >= heap_info.num_descriptors
        || !handle_candidates(device, memory).contains(&heap_info.device)
    {
        return Ok(invalid_arg());
    }
    let desc = ShaderResourceViewDesc {
        format,
        view_dimension: SrvDimension::Texture2D,
        most_detailed_mip: 0,
        mip_levels: 1,
    };
    let mut graphics = lock_graphics(state)?;
    let dest = match graphics
        .cpu_descriptor_handle_for_heap_start(heap_handle)
        .ok()
        .and_then(|start| start.offset(slot))
    {
        Some(dest) => dest,
        None => return Ok(invalid_arg()),
    };
    let result = with_handle(
        resource,
        memory,
        GraphicsError::InvalidResourceHandle,
        |resource_handle| graphics.create_shader_resource_view(resource_handle, &desc, dest),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(binding_hresult(&error)),
    }
}

/// Write a sampler into a heap slot.
fn xenora_create_sampler(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let heap = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let slot = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let filter = args.get(3, memory).map_err(ExitReason::MemoryFault)? as u32;
    let address_u = args.get(4, memory).map_err(ExitReason::MemoryFault)? as u32;
    let address_v = args.get(5, memory).map_err(ExitReason::MemoryFault)? as u32;
    let address_w = args.get(6, memory).map_err(ExitReason::MemoryFault)? as u32;
    if filter != D3D12_FILTER_MIN_MAG_MIP_POINT {
        return Ok(invalid_arg());
    }
    let (Some(address_u), Some(address_v), Some(address_w)) = (
        guest_address_mode(address_u),
        guest_address_mode(address_v),
        guest_address_mode(address_w),
    ) else {
        return Ok(invalid_arg());
    };
    let Some((heap_handle, heap_info)) = named_heap(state, heap, memory) else {
        return Ok(invalid_arg());
    };
    if heap_info.heap_type != HEAP_TYPE_SAMPLER
        || slot >= heap_info.num_descriptors
        || !handle_candidates(device, memory).contains(&heap_info.device)
    {
        return Ok(invalid_arg());
    }
    let desc = SamplerDesc {
        filter,
        address_u,
        address_v,
        address_w,
        mip_lod_bias: 0.0,
        min_lod: 0.0,
        max_lod: f32::MAX,
    };
    let mut graphics = lock_graphics(state)?;
    let dest = match graphics
        .cpu_descriptor_handle_for_heap_start(heap_handle)
        .ok()
        .and_then(|start| start.offset(slot))
    {
        Some(dest) => dest,
        None => return Ok(invalid_arg()),
    };
    let result = graphics.create_sampler(&desc, dest);
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(binding_hresult(&error)),
    }
}

/// Create a root signature with one shader resource view table and one
/// sampler table, at the root parameter indices the guest names.
fn xenora_create_root_signature(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let srv_parameter = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let sampler_parameter = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let out = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0
        || !writable_out(memory, out)
        || srv_parameter == sampler_parameter
        || srv_parameter > 1
        || sampler_parameter > 1
    {
        return Ok(invalid_arg());
    }
    let table = |range_type| RootParameter::DescriptorTable {
        ranges: vec![DescriptorRange {
            range_type,
            num_descriptors: 1,
            base_shader_register: 0,
            register_space: 0,
            offset_in_descriptors_from_table_start: 0,
        }],
        visibility: ShaderVisibility::Pixel,
    };
    let mut parameters = Vec::with_capacity(2);
    for index in 0..2u32 {
        let range_type = if index == srv_parameter {
            DescriptorRangeType::Srv
        } else {
            DescriptorRangeType::Sampler
        };
        parameters.push(table(range_type));
    }
    let desc = RootSignatureDesc {
        parameters,
        static_sampler_count: 0,
    };
    let mut graphics = lock_graphics(state)?;
    let root_signature = match with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |handle| graphics.create_root_signature(handle, &desc),
    ) {
        Ok(root_signature) => root_signature,
        Err(error) => return Ok(binding_hresult(&error)),
    };
    if memory.write_u64(out, root_signature.to_u64()).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Bind at most one descriptor heap of each type to a command list. A heap
/// handle of zero means that no heap of that type is bound.
fn xenora_set_descriptor_heaps(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let srv_heap = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let sampler_heap = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    let mut heaps = Vec::with_capacity(2);
    let mut types: Vec<u32> = Vec::with_capacity(2);
    for raw in [srv_heap, sampler_heap] {
        if raw == 0 {
            continue;
        }
        let Some((handle, info)) = named_heap(state, raw, memory) else {
            return Ok(invalid_arg());
        };
        if types.contains(&info.heap_type) {
            return Ok(invalid_arg());
        }
        types.push(info.heap_type);
        heaps.push(handle);
    }
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| graphics.cmd_set_descriptor_heaps(list_handle, &heaps),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(binding_hresult(&error)),
    }
}

/// Bind a root signature to a command list.
fn xenora_set_graphics_root_signature(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let root_signature = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| {
            with_handle(
                root_signature,
                memory,
                GraphicsError::InvalidDescriptor,
                |root_signature_handle| {
                    graphics.cmd_set_graphics_root_signature(list_handle, root_signature_handle)
                },
            )
        },
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(binding_hresult(&error)),
    }
}

/// Bind the descriptor table of one root parameter to a heap slot. The
/// service computes the GPU descriptor handle, so the guest never does
/// descriptor handle arithmetic.
fn xenora_set_graphics_root_descriptor_table(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let root_parameter_index = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let heap = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    let slot = args.get(3, memory).map_err(ExitReason::MemoryFault)? as u32;
    if root_parameter_index > 1 {
        return Ok(invalid_arg());
    }
    let Some((heap_handle, heap_info)) = named_heap(state, heap, memory) else {
        return Ok(invalid_arg());
    };
    if slot >= heap_info.num_descriptors {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let base = match graphics
        .gpu_descriptor_handle_for_heap_start(heap_handle)
        .ok()
        .and_then(|start| start.offset(slot))
    {
        Some(base) => base,
        None => return Ok(invalid_arg()),
    };
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| {
            graphics.cmd_set_graphics_root_descriptor_table(list_handle, root_parameter_index, base)
        },
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(binding_hresult(&error)),
    }
}

/// Bind a vertex buffer at `slot`.
fn xenora_set_vertex_buffer(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let slot = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let resource = args.get(2, memory).map_err(ExitReason::MemoryFault)?;
    let offset = args.get(3, memory).map_err(ExitReason::MemoryFault)? as usize;
    let stride = args.get(4, memory).map_err(ExitReason::MemoryFault)? as usize;
    if slot != 0 || stride < MIN_VERTEX_STRIDE {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| {
            with_handle(
                resource,
                memory,
                GraphicsError::InvalidResourceHandle,
                |resource_handle| {
                    graphics.cmd_set_vertex_buffer(list_handle, resource_handle, offset, stride)
                },
            )
        },
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Bind an index buffer.
fn xenora_set_index_buffer(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let resource = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let offset = args.get(2, memory).map_err(ExitReason::MemoryFault)? as usize;
    let format = args.get(3, memory).map_err(ExitReason::MemoryFault)? as u32;
    if IndexFormat::from_dxgi(format).is_none() {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| {
            with_handle(
                resource,
                memory,
                GraphicsError::InvalidResourceHandle,
                |resource_handle| {
                    graphics.cmd_set_index_buffer(list_handle, resource_handle, offset, format)
                },
            )
        },
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Bind the colour target and the clear colour.
fn xenora_set_render_target(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let resource = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let clear = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let clear_color = [
        (clear & 0xFF) as u8,
        ((clear >> 8) & 0xFF) as u8,
        ((clear >> 16) & 0xFF) as u8,
        ((clear >> 24) & 0xFF) as u8,
    ];
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| {
            if resource == 0 {
                return graphics.cmd_set_render_targets(list_handle, None, clear_color);
            }
            with_handle(
                resource,
                memory,
                GraphicsError::InvalidResourceHandle,
                |resource_handle| {
                    graphics.cmd_set_render_targets(list_handle, Some(resource_handle), clear_color)
                },
            )
        },
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Set the viewport.
fn xenora_set_viewport(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let width = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let height = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    if !(1..=MAX_VIEWPORT_DIMENSION).contains(&width)
        || !(1..=MAX_VIEWPORT_DIMENSION).contains(&height)
    {
        return Ok(invalid_arg());
    }
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| graphics.cmd_set_viewport(list_handle, width as usize, height as usize),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Record a non-indexed draw.
fn xenora_draw(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let vertex_count = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let instance_count = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let start_vertex = args.get(3, memory).map_err(ExitReason::MemoryFault)? as u32;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| {
            graphics.cmd_draw_instanced(list_handle, vertex_count, instance_count, start_vertex, 0)
        },
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Record an indexed draw. `start_index_base` packs the start index in its
/// low 32 bits and a sign-extended 16-bit base vertex in its high 32 bits.
fn xenora_draw_indexed(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let index_count = args.get(1, memory).map_err(ExitReason::MemoryFault)? as u32;
    let instance_count = args.get(2, memory).map_err(ExitReason::MemoryFault)? as u32;
    let start_index_base = args.get(3, memory).map_err(ExitReason::MemoryFault)?;
    let start_index = start_index_base as u32;
    let base_vertex = i32::from(((start_index_base >> 32) as u16) as i16);
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| {
            graphics.cmd_draw_indexed_instanced(
                list_handle,
                index_count,
                instance_count,
                start_index,
                base_vertex,
                0,
            )
        },
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// End recording so the list can be executed.
fn xenora_close_command_list(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| graphics.close_command_list(list_handle),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Execute a closed command list on a queue.
fn xenora_execute_command_lists(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let queue = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let list = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        queue,
        memory,
        GraphicsError::InvalidQueueHandle,
        |queue_handle| {
            with_handle(
                list,
                memory,
                GraphicsError::InvalidCommandListHandle,
                |list_handle| graphics.execute_command_list(queue_handle, list_handle, memory),
            )
        },
    );
    match result {
        Ok(_) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Copy the contents of a resource into guest memory.
fn xenora_readback_resource(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let resource = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let guest_addr = args.get(1, memory).map_err(ExitReason::MemoryFault)?;
    let byte_length = args.get(2, memory).map_err(ExitReason::MemoryFault)? as usize;
    if guest_addr == 0 {
        return Ok(invalid_arg());
    }
    let graphics = lock_graphics(state)?;
    let bytes = match with_handle(
        resource,
        memory,
        GraphicsError::InvalidResourceHandle,
        |resource_handle| graphics.resource_bytes(resource_handle),
    ) {
        Ok(bytes) => bytes,
        Err(error) => return Ok(hresult(&error)),
    };
    let Some(requested) = bytes.get(..byte_length).filter(|bytes| !bytes.is_empty()) else {
        return Ok(invalid_arg());
    };
    if memory.write_bytes(guest_addr, requested).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Write the backend, width, height and draw count of the last frame.
fn xenora_get_last_frame_info(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let out = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    if out == 0 || !writable_out(memory, out) {
        return Ok(invalid_arg());
    }
    let graphics = lock_graphics(state)?;
    let presentation = match graphics.last_presentation.lock() {
        Ok(presentation) => presentation,
        Err(_) => return Ok(HResult::FAIL.guest_return()),
    };
    let backend = match presentation.backend {
        Some(GraphicsBackendId::MetalNative) => BACKEND_METAL_NATIVE,
        Some(GraphicsBackendId::SoftwareReference) | None => BACKEND_SOFTWARE_REFERENCE,
    };
    let width = u32::try_from(presentation.width).unwrap_or(u32::MAX);
    let height = u32::try_from(presentation.height).unwrap_or(u32::MAX);
    let draw_count = u32::try_from(presentation.draw_count).unwrap_or(u32::MAX);
    drop(presentation);
    let mut record = [0u8; 16];
    record[0..4].copy_from_slice(&backend.to_le_bytes());
    record[4..8].copy_from_slice(&width.to_le_bytes());
    record[8..12].copy_from_slice(&height.to_le_bytes());
    record[12..16].copy_from_slice(&draw_count.to_le_bytes());
    if memory.write_bytes(out, &record).is_err() {
        return Ok(invalid_arg());
    }
    Ok(ok())
}

/// Destroy a resource.
fn xenora_destroy_resource(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let resource = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        resource,
        memory,
        GraphicsError::InvalidResourceHandle,
        |resource_handle| graphics.destroy_resource(resource_handle),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Destroy a command list.
fn xenora_destroy_command_list(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let list = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        list,
        memory,
        GraphicsError::InvalidCommandListHandle,
        |list_handle| graphics.destroy_command_list(list_handle),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Destroy a command allocator.
fn xenora_destroy_command_allocator(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let allocator = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        allocator,
        memory,
        GraphicsError::InvalidAllocatorHandle,
        |allocator_handle| graphics.destroy_command_allocator(allocator_handle),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Destroy a command queue.
fn xenora_destroy_command_queue(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let queue = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        queue,
        memory,
        GraphicsError::InvalidQueueHandle,
        |queue_handle| graphics.destroy_command_queue(queue_handle),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

/// Destroy a device.
fn xenora_destroy_device(
    state: &Arc<ServicesState>,
    args: &Win64Args,
    memory: &mut GuestMemory,
) -> Result<u64, ExitReason> {
    let device = args.get(0, memory).map_err(ExitReason::MemoryFault)?;
    let mut graphics = lock_graphics(state)?;
    let result = with_handle(
        device,
        memory,
        GraphicsError::InvalidDeviceHandle,
        |device_handle| graphics.destroy_device(device_handle),
    );
    match result {
        Ok(()) => Ok(ok()),
        Err(error) => Ok(hresult(&error)),
    }
}

pub(super) fn register(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    macro_rules! export {
        ($name:literal, $service:path) => {{
            let state = Arc::clone(state);
            registry.register(MODULE, $name, move |args, _cpu, memory| {
                $service(&state, args, memory)
            });
            registry.set_status(MODULE, $name, ServiceStatus::Implemented);
        }};
    }

    export!("XenoraCreateDevice", xenora_create_device);
    export!("XenoraCreateCommandQueue", xenora_create_command_queue);
    export!("XenoraCreateFence", xenora_create_fence);
    export!("XenoraQueueWait", xenora_queue_wait);
    export!("XenoraQueueSignal", xenora_queue_signal);
    export!(
        "XenoraGetFenceCompletedValue",
        xenora_get_fence_completed_value
    );
    export!("XenoraDestroyFence", xenora_destroy_fence);
    export!(
        "XenoraCreateCommandAllocator",
        xenora_create_command_allocator
    );
    export!("XenoraCreateCommandList", xenora_create_command_list);
    export!("XenoraCreateBuffer", xenora_create_buffer);
    export!("XenoraCreateRenderTarget", xenora_create_render_target);
    export!("XenoraCreateTexture2D", xenora_create_texture2d);
    export!("XenoraCreateDescriptorHeap", xenora_create_descriptor_heap);
    export!(
        "XenoraCreateShaderResourceView",
        xenora_create_shader_resource_view
    );
    export!("XenoraCreateSampler", xenora_create_sampler);
    export!("XenoraCreateRootSignature", xenora_create_root_signature);
    export!("XenoraSetDescriptorHeaps", xenora_set_descriptor_heaps);
    export!(
        "XenoraSetGraphicsRootSignature",
        xenora_set_graphics_root_signature
    );
    export!(
        "XenoraSetGraphicsRootDescriptorTable",
        xenora_set_graphics_root_descriptor_table
    );
    export!("XenoraSetVertexBuffer", xenora_set_vertex_buffer);
    export!("XenoraSetIndexBuffer", xenora_set_index_buffer);
    export!("XenoraSetRenderTarget", xenora_set_render_target);
    export!("XenoraSetViewport", xenora_set_viewport);
    export!("XenoraDraw", xenora_draw);
    export!("XenoraDrawIndexed", xenora_draw_indexed);
    export!("XenoraCloseCommandList", xenora_close_command_list);
    export!("XenoraExecuteCommandLists", xenora_execute_command_lists);
    export!("XenoraReadbackResource", xenora_readback_resource);
    export!("XenoraGetLastFrameInfo", xenora_get_last_frame_info);
    export!("XenoraDestroyResource", xenora_destroy_resource);
    export!("XenoraDestroyCommandList", xenora_destroy_command_list);
    export!(
        "XenoraDestroyCommandAllocator",
        xenora_destroy_command_allocator
    );
    export!("XenoraDestroyCommandQueue", xenora_destroy_command_queue);
    export!("XenoraDestroyDevice", xenora_destroy_device);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryPermissions;
    use crate::services::MockClock;

    const E_INVALIDARG_HRESULT: u64 = 0x8007_0057;
    const E_ACCESSDENIED_HRESULT: u64 = 0x8007_0005;

    const VERTEX_ADDRESS: u64 = 0x0001_0000;
    const READBACK_ADDRESS: u64 = 0x0002_0000;
    const HANDLE_SLOT: u64 = 0x0003_0000;
    const READ_ONLY_ADDRESS: u64 = 0x0004_0000;
    const UNMAPPED_ADDRESS: u64 = 0x0009_0000;
    /// The guest stack the arguments beyond the fourth are written to.
    const STACK_ADDRESS: u64 = 0x0006_0000;
    /// The guest memory the texture of the textured round trip lives in.
    const TEXTURE_ADDRESS: u64 = 0x0007_0000;

    fn state() -> Arc<ServicesState> {
        Arc::new(ServicesState::new(Arc::new(MockClock::new(0))))
    }

    fn memory() -> GuestMemory {
        let mut memory = GuestMemory::new();
        memory
            .map_region(VERTEX_ADDRESS, 0x1000, MemoryPermissions::READ_WRITE)
            .expect("vertex region");
        memory
            .map_region(READBACK_ADDRESS, 0x1000, MemoryPermissions::READ_WRITE)
            .expect("readback region");
        memory
            .map_region(HANDLE_SLOT, 0x1000, MemoryPermissions::READ_WRITE)
            .expect("handle slot region");
        memory
            .map_region(READ_ONLY_ADDRESS, 0x1000, MemoryPermissions::READ_ONLY)
            .expect("read-only region");
        memory
            .map_region(STACK_ADDRESS, 0x1000, MemoryPermissions::READ_WRITE)
            .expect("stack region");
        memory
            .map_region(TEXTURE_ADDRESS, 0x1000, MemoryPermissions::READ_WRITE)
            .expect("texture region");
        memory
    }

    /// The arguments of a call, with the arguments beyond the fourth written
    /// on the guest stack.
    fn call_args(
        memory: &mut GuestMemory,
        rcx: u64,
        rdx: u64,
        r8: u64,
        r9: u64,
        stack: &[u64],
    ) -> Win64Args {
        for (index, value) in stack.iter().enumerate() {
            let at = STACK_ADDRESS + 40 + 8 * index as u64;
            memory.write_u64(at, *value).expect("stack argument");
        }
        Win64Args {
            rcx,
            rdx,
            r8,
            r9,
            rsp: STACK_ADDRESS,
        }
    }

    fn call(
        state: &Arc<ServicesState>,
        rcx: u64,
        rdx: u64,
        r8: u64,
        r9: u64,
        memory: &mut GuestMemory,
    ) -> u64 {
        let args = Win64Args {
            rcx,
            rdx,
            r8,
            r9,
            rsp: 0,
        };
        xenora_create_device(state, &args, memory).expect("service call succeeds")
    }

    /// The three vertex positions of a triangle that covers a 4 by 3 viewport.
    fn covering_vertices() -> Vec<u8> {
        let positions: [[f32; 4]; 3] = [
            [-3.0, 11.0 / 3.0, 0.0, 1.0],
            [-3.0, -7.0, 0.0, 1.0],
            [5.0, 11.0 / 3.0, 0.0, 1.0],
        ];
        let mut bytes = Vec::new();
        for position in positions {
            for value in position {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn invalid_device_handle_is_rejected() {
        let state = state();
        let mut memory = memory();
        let invalid = 0xDEAD_BEEF_u64;
        let result = {
            let args = Win64Args {
                rcx: invalid,
                rdx: 0,
                r8: HANDLE_SLOT,
                r9: 0,
                rsp: 0,
            };
            xenora_create_command_queue(&state, &args, &mut memory).expect("service call succeeds")
        };
        assert_eq!(result, E_INVALIDARG_HRESULT);
    }

    #[test]
    fn zero_out_pointer_is_rejected() {
        let state = state();
        let mut memory = memory();
        let args = Win64Args {
            rcx: 0,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        let result =
            xenora_create_device(&state, &args, &mut memory).expect("service call succeeds");
        assert_eq!(result, E_INVALIDARG_HRESULT);
    }

    fn live_objects(state: &Arc<ServicesState>) -> [usize; 5] {
        let graphics = state.graphics.lock().expect("graphics state");
        graphics.live_counts()
    }

    fn create_device_handle(state: &Arc<ServicesState>, memory: &mut GuestMemory) -> u64 {
        let args = Win64Args {
            rcx: HANDLE_SLOT,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_device(state, &args, memory).expect("service call succeeds"),
            ok()
        );
        memory.read_u64(HANDLE_SLOT).expect("handle slot")
    }

    #[test]
    fn create_services_reject_unwritable_out_pointers_without_allocating() {
        let state = state();
        let mut memory = memory();
        let before = live_objects(&state);
        // Unmapped, read-only, and a slot that starts inside the region but
        // crosses its end. Each must be refused before a device exists.
        for out in [
            UNMAPPED_ADDRESS,
            READ_ONLY_ADDRESS,
            HANDLE_SLOT + 0x1000 - 4,
        ] {
            let args = Win64Args {
                rcx: out,
                rdx: 0,
                r8: 0,
                r9: 0,
                rsp: 0,
            };
            assert_eq!(
                xenora_create_device(&state, &args, &mut memory).expect("service call succeeds"),
                E_INVALIDARG_HRESULT,
                "out pointer {out:#x} was accepted"
            );
            assert_eq!(
                live_objects(&state),
                before,
                "out pointer {out:#x} allocated"
            );
        }
    }

    #[test]
    fn a_buffer_with_an_unwritable_out_pointer_allocates_nothing() {
        let state = state();
        let mut memory = memory();
        let device = create_device_handle(&state, &mut memory);
        let before = live_objects(&state);
        for out in [
            UNMAPPED_ADDRESS,
            READ_ONLY_ADDRESS,
            HANDLE_SLOT + 0x1000 - 4,
        ] {
            let args = Win64Args {
                rcx: device,
                rdx: VERTEX_ADDRESS,
                r8: 16,
                r9: out,
                rsp: 0,
            };
            assert_eq!(
                xenora_create_buffer(&state, &args, &mut memory).expect("service call succeeds"),
                E_INVALIDARG_HRESULT,
                "out pointer {out:#x} was accepted"
            );
            assert_eq!(
                live_objects(&state),
                before,
                "out pointer {out:#x} allocated"
            );
        }
    }

    #[test]
    fn texture_creation_with_unwritable_handle_outputs_is_transactional() {
        check_binding_creator_outputs(|state, device, out, memory| {
            let args = call_args(
                memory,
                device,
                2,
                2,
                u64::from(DXGI_FORMAT_R8G8B8A8_UNORM),
                &[TEXTURE_ADDRESS, out],
            );
            xenora_create_texture2d(state, &args, memory)
        });
    }

    #[test]
    fn heap_creation_with_unwritable_handle_outputs_is_transactional() {
        check_binding_creator_outputs(|state, device, out, memory| {
            let args = call_args(
                memory,
                device,
                u64::from(HEAP_TYPE_CBV_SRV_UAV),
                1,
                out,
                &[],
            );
            xenora_create_descriptor_heap(state, &args, memory)
        });
    }

    #[test]
    fn root_signature_creation_with_unwritable_handle_outputs_is_transactional() {
        check_binding_creator_outputs(|state, device, out, memory| {
            let args = call_args(memory, device, 0, 1, out, &[]);
            xenora_create_root_signature(state, &args, memory)
        });
    }

    #[test]
    fn fence_creation_with_unwritable_handle_outputs_is_transactional() {
        check_binding_creator_outputs(|state, device, out, memory| {
            let args = call_args(memory, device, 0x1_0000_0003, out, 0, &[]);
            xenora_create_fence(state, &args, memory)
        });
    }

    fn check_binding_creator_outputs(
        create: impl Fn(&Arc<ServicesState>, u64, u64, &mut GuestMemory) -> Result<u64, ExitReason>,
    ) {
        let state = state();
        let mut memory = memory();
        memory
            .map_region(
                READ_ONLY_ADDRESS - 0x1000,
                0x1000,
                MemoryPermissions::READ_WRITE,
            )
            .expect("writable page adjacent to the read-only page");
        let partial_outputs = [HANDLE_SLOT + 0x1000 - 4, READ_ONLY_ADDRESS - 4];
        let marker = 0x1234_5678;
        for out in partial_outputs {
            memory.write_u32(out, marker).expect("writable prefix");
        }

        for out in [0, READ_ONLY_ADDRESS, UNMAPPED_ADDRESS, u64::MAX - 3]
            .into_iter()
            .chain(partial_outputs)
        {
            let device = create_device_handle(&state, &mut memory);
            assert_eq!(
                create(&state, device, out, &mut memory).expect("service call succeeds"),
                E_INVALIDARG_HRESULT,
                "out pointer {out:#x}"
            );
            if partial_outputs.contains(&out) {
                assert_eq!(memory.read_u32(out).expect("writable prefix"), marker);
            }
            let args = call_args(&mut memory, device, 0, 0, 0, &[]);
            assert_eq!(
                xenora_destroy_device(&state, &args, &mut memory).expect("service call succeeds"),
                ok(),
                "rejected out pointer {out:#x} left a live child"
            );
        }

        memory
            .map_region(HANDLE_SLOT + 0x1000, 0x1000, MemoryPermissions::READ_WRITE)
            .expect("second writable handle page");
        let out = partial_outputs[0];
        let device = create_device_handle(&state, &mut memory);
        memory
            .write_u64(out, u64::MAX)
            .expect("split writable output");
        assert_eq!(
            create(&state, device, out, &mut memory).expect("service call succeeds"),
            ok()
        );
        let handle = memory.read_u64(out).expect("published graphics handle");
        assert_ne!(handle, 0);
        assert_ne!(handle, u64::MAX);
    }

    #[test]
    fn repeated_device_creation_and_destruction_leaves_no_objects() {
        let state = state();
        let mut memory = memory();
        let empty = [0; 5];
        for _ in 0..3 {
            let device = create_device_handle(&state, &mut memory);
            assert_eq!(live_objects(&state), [1, 0, 0, 0, 0]);
            let args = Win64Args {
                rcx: device,
                rdx: 0,
                r8: 0,
                r9: 0,
                rsp: 0,
            };
            assert_eq!(
                xenora_destroy_device(&state, &args, &mut memory).expect("service call succeeds"),
                ok()
            );
            assert_eq!(live_objects(&state), empty);
        }
    }

    #[test]
    fn a_queue_belongs_to_its_own_device() {
        let state = state();
        let mut memory = memory();
        let first = create_device_handle(&state, &mut memory);
        // The handle slot is reused, so keep the first device before making
        // the second one.
        let slot = 0x0005_0000;
        memory
            .map_region(slot, 0x1000, MemoryPermissions::READ_WRITE)
            .expect("second handle slot");
        let args = Win64Args {
            rcx: slot,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_device(&state, &args, &mut memory).expect("service call succeeds"),
            ok()
        );
        let second = memory.read_u64(slot).expect("handle slot");
        assert_ne!(first, second);

        let queue_args = Win64Args {
            rcx: first,
            rdx: 0,
            r8: HANDLE_SLOT,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_queue(&state, &queue_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let queue = memory.read_u64(HANDLE_SLOT).expect("handle slot");

        // Destroying the other device must not touch the first device's queue.
        let destroy = Win64Args {
            rcx: second,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_destroy_device(&state, &destroy, &mut memory).expect("service call succeeds"),
            ok()
        );
        let destroy_queue = Win64Args {
            rcx: queue,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_destroy_command_queue(&state, &destroy_queue, &mut memory)
                .expect("service call succeeds"),
            ok(),
            "the queue still belongs to the first device"
        );
    }

    #[test]
    fn zero_viewport_width_is_rejected() {
        let state = state();
        let mut memory = memory();
        let args = Win64Args {
            rcx: 1,
            rdx: 0,
            r8: 3,
            r9: 0,
            rsp: 0,
        };
        let result =
            xenora_set_viewport(&state, &args, &mut memory).expect("service call succeeds");
        assert_eq!(result, E_INVALIDARG_HRESULT);
    }

    #[test]
    fn device_outlives_its_queue() {
        let state = state();
        let mut memory = memory();
        let args = Win64Args {
            rcx: HANDLE_SLOT,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_device(&state, &args, &mut memory).expect("service call succeeds"),
            ok()
        );
        let device = memory.read_u64(HANDLE_SLOT).expect("device handle");
        let queue_args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: HANDLE_SLOT + 8,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_queue(&state, &queue_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let queue = memory.read_u64(HANDLE_SLOT + 8).expect("queue handle");

        let destroy_device_args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_destroy_device(&state, &destroy_device_args, &mut memory)
                .expect("service call succeeds"),
            E_ACCESSDENIED_HRESULT
        );

        let destroy_queue_args = Win64Args {
            rcx: queue,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_destroy_command_queue(&state, &destroy_queue_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        assert_eq!(
            xenora_destroy_device(&state, &destroy_device_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
    }

    /// Run one guest draw through the software reference backend and return
    /// the service state, the guest memory and the render target handle.
    fn executed_draw() -> (Arc<ServicesState>, GuestMemory, u64) {
        let state = state();
        let mut memory = memory();
        memory
            .write_bytes(VERTEX_ADDRESS, &covering_vertices())
            .expect("vertex data");

        // Device.
        let args = Win64Args {
            rcx: HANDLE_SLOT,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_device(&state, &args, &mut memory).expect("service call succeeds"),
            ok()
        );
        let device = memory.read_u64(HANDLE_SLOT).expect("device handle");

        // Command queue and allocator.
        let queue_args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: HANDLE_SLOT + 8,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_queue(&state, &queue_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let queue = memory.read_u64(HANDLE_SLOT + 8).expect("queue handle");
        let allocator_args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: HANDLE_SLOT + 16,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_allocator(&state, &allocator_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let allocator = memory.read_u64(HANDLE_SLOT + 16).expect("allocator handle");

        // Command list.
        let list_args = Win64Args {
            rcx: device,
            rdx: allocator,
            r8: 0,
            r9: HANDLE_SLOT + 24,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_list(&state, &list_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let list = memory.read_u64(HANDLE_SLOT + 24).expect("list handle");

        // A 4 by 3 render target and a vertex buffer over the guest data.
        let target_args = Win64Args {
            rcx: device,
            rdx: 4,
            r8: 3,
            r9: HANDLE_SLOT + 32,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_render_target(&state, &target_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let target = memory.read_u64(HANDLE_SLOT + 32).expect("target handle");
        let buffer_args = Win64Args {
            rcx: device,
            rdx: VERTEX_ADDRESS,
            r8: 48,
            r9: HANDLE_SLOT + 40,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_buffer(&state, &buffer_args, &mut memory).expect("service call succeeds"),
            ok()
        );
        let buffer = memory.read_u64(HANDLE_SLOT + 40).expect("buffer handle");

        // Record the draw.
        let set_target_args = Win64Args {
            rcx: list,
            rdx: target,
            r8: 0xFF00_0000,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_render_target(&state, &set_target_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let viewport_args = Win64Args {
            rcx: list,
            rdx: 4,
            r8: 3,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_viewport(&state, &viewport_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let vertex_args = call_args(&mut memory, list, 0, buffer, 0, &[16]);
        assert_eq!(
            xenora_set_vertex_buffer(&state, &vertex_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let draw_args = Win64Args {
            rcx: list,
            rdx: 3,
            r8: 1,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_draw(&state, &draw_args, &mut memory).expect("service call succeeds"),
            ok()
        );
        let close_args = Win64Args {
            rcx: list,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_close_command_list(&state, &close_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );

        // Execute.
        let execute_args = Win64Args {
            rcx: queue,
            rdx: list,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_execute_command_lists(&state, &execute_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        (state, memory, target)
    }

    #[test]
    fn software_reference_round_trip() {
        let (state, mut memory, target) = executed_draw();
        let readback_args = Win64Args {
            rcx: target,
            rdx: READBACK_ADDRESS,
            r8: 48,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_readback_resource(&state, &readback_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let mut pixels = [0u8; 48];
        memory
            .read_bytes(READBACK_ADDRESS, &mut pixels)
            .expect("readback bytes");
        assert_eq!(pixels.len(), 4 * 3 * 4);
        for pixel in pixels.as_chunks::<4>().0 {
            assert_eq!(*pixel, [255u8, 0, 0, 255]);
        }
    }

    #[test]
    fn last_frame_info_reports_the_executed_draw() {
        let (state, mut memory, _target) = executed_draw();
        let info_args = Win64Args {
            rcx: HANDLE_SLOT + 48,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_get_last_frame_info(&state, &info_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let mut info = [0u8; 16];
        memory
            .read_bytes(HANDLE_SLOT + 48, &mut info)
            .expect("frame info");
        assert_eq!(
            u32::from_le_bytes(info[0..4].try_into().expect("backend")),
            0
        );
        assert_eq!(u32::from_le_bytes(info[4..8].try_into().expect("width")), 4);
        assert_eq!(
            u32::from_le_bytes(info[8..12].try_into().expect("height")),
            3
        );
        assert_eq!(
            u32::from_le_bytes(info[12..16].try_into().expect("draw count")),
            1
        );
    }

    #[test]
    fn service_calls_report_their_hresult() {
        let state = state();
        let mut memory = memory();
        // A call that only exercises the argument plumbing still returns a
        // status rather than faulting the guest.
        assert_eq!(call(&state, 0, 0, 0, 0, &mut memory), E_INVALIDARG_HRESULT);
    }

    /// The pixels of the 2 by 2 texture of the textured round trip: column 0
    /// is red, column 1 is blue.
    fn texture_pixels() -> Vec<u8> {
        vec![
            255, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0, 255, 0, 0, 255, 255,
        ]
    }

    /// The vertices of a triangle that covers the whole viewport: a float4
    /// position and a float4 texture coordinate each.
    fn textured_vertices() -> Vec<u8> {
        let positions: [[f32; 4]; 3] = [
            [-1.0, -1.0, 0.0, 1.0],
            [3.0, -1.0, 0.0, 1.0],
            [-1.0, 3.0, 0.0, 1.0],
        ];
        let texcoords: [[f32; 4]; 3] = [
            [0.25, 0.5, 0.0, 0.0],
            [0.25, 0.5, 0.0, 0.0],
            [0.25, 0.5, 0.0, 0.0],
        ];
        let mut bytes = Vec::new();
        for (position, texcoord) in positions.iter().zip(&texcoords) {
            for value in position.iter().chain(texcoord.iter()) {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn descriptor_heap_with_an_unsupported_type_is_rejected() {
        let state = state();
        let mut memory = memory();
        let device = create_device_handle(&state, &mut memory);
        let args = Win64Args {
            rcx: device,
            rdx: 2,
            r8: 1,
            r9: HANDLE_SLOT + 64,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_descriptor_heap(&state, &args, &mut memory)
                .expect("service call succeeds"),
            E_INVALIDARG_HRESULT
        );
    }

    #[test]
    fn shader_resource_view_with_a_different_format_is_rejected() {
        let state = state();
        let mut memory = memory();
        let device = create_device_handle(&state, &mut memory);
        memory
            .write_bytes(TEXTURE_ADDRESS, &texture_pixels())
            .expect("texture data");
        let texture_args = call_args(
            &mut memory,
            device,
            2,
            2,
            DXGI_FORMAT_R8G8B8A8_UNORM as u64,
            &[TEXTURE_ADDRESS, HANDLE_SLOT + 64],
        );
        assert_eq!(
            xenora_create_texture2d(&state, &texture_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let texture = memory.read_u64(HANDLE_SLOT + 64).expect("texture handle");
        let heap_args = Win64Args {
            rcx: device,
            rdx: HEAP_TYPE_CBV_SRV_UAV as u64,
            r8: 1,
            r9: HANDLE_SLOT + 72,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_descriptor_heap(&state, &heap_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let heap = memory.read_u64(HANDLE_SLOT + 72).expect("heap handle");
        // The view's format differs from the resource's.
        let view_args = call_args(&mut memory, device, heap, 0, texture, &[71u64]);
        assert_eq!(
            xenora_create_shader_resource_view(&state, &view_args, &mut memory)
                .expect("service call succeeds"),
            E_INVALIDARG_HRESULT
        );
    }

    #[test]
    fn descriptor_slot_beyond_the_heap_is_rejected() {
        let state = state();
        let mut memory = memory();
        let device = create_device_handle(&state, &mut memory);
        memory
            .write_bytes(TEXTURE_ADDRESS, &texture_pixels())
            .expect("texture data");
        let texture_args = call_args(
            &mut memory,
            device,
            2,
            2,
            DXGI_FORMAT_R8G8B8A8_UNORM as u64,
            &[TEXTURE_ADDRESS, HANDLE_SLOT + 64],
        );
        assert_eq!(
            xenora_create_texture2d(&state, &texture_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let texture = memory.read_u64(HANDLE_SLOT + 64).expect("texture handle");
        let srv_heap_args = Win64Args {
            rcx: device,
            rdx: HEAP_TYPE_CBV_SRV_UAV as u64,
            r8: 1,
            r9: HANDLE_SLOT + 72,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_descriptor_heap(&state, &srv_heap_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let srv_heap = memory.read_u64(HANDLE_SLOT + 72).expect("heap handle");
        let sampler_heap_args = Win64Args {
            rcx: device,
            rdx: HEAP_TYPE_SAMPLER as u64,
            r8: 1,
            r9: HANDLE_SLOT + 80,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_descriptor_heap(&state, &sampler_heap_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let sampler_heap = memory
            .read_u64(HANDLE_SLOT + 80)
            .expect("sampler heap handle");

        // The heap holds one descriptor, so slot 1 is beyond it.
        let view_args = call_args(&mut memory, device, srv_heap, 1, texture, &[28u64]);
        assert_eq!(
            xenora_create_shader_resource_view(&state, &view_args, &mut memory)
                .expect("service call succeeds"),
            E_INVALIDARG_HRESULT
        );
        let sampler_args = call_args(
            &mut memory,
            device,
            sampler_heap,
            1,
            D3D12_FILTER_MIN_MAG_MIP_POINT as u64,
            &[
                SAMPLER_ADDRESS_CLAMP as u64,
                SAMPLER_ADDRESS_CLAMP as u64,
                SAMPLER_ADDRESS_CLAMP as u64,
            ],
        );
        assert_eq!(
            xenora_create_sampler(&state, &sampler_args, &mut memory)
                .expect("service call succeeds"),
            E_INVALIDARG_HRESULT
        );
        // The descriptor table of root parameter 0 names slot 1 of the same
        // heap.
        let table_args = Win64Args {
            rcx: 0,
            rdx: 0,
            r8: srv_heap,
            r9: 1,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_graphics_root_descriptor_table(&state, &table_args, &mut memory)
                .expect("service call succeeds"),
            E_INVALIDARG_HRESULT
        );
    }

    #[test]
    fn root_signature_with_equal_parameters_is_rejected() {
        let state = state();
        let mut memory = memory();
        let device = create_device_handle(&state, &mut memory);
        let args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: 0,
            r9: HANDLE_SLOT + 64,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_root_signature(&state, &args, &mut memory)
                .expect("service call succeeds"),
            E_INVALIDARG_HRESULT
        );
    }

    #[test]
    fn textured_draw_samples_the_guest_texture() {
        let state = state();
        let mut memory = memory();
        memory
            .write_bytes(TEXTURE_ADDRESS, &texture_pixels())
            .expect("texture data");
        memory
            .write_bytes(VERTEX_ADDRESS, &textured_vertices())
            .expect("vertex data");

        // Device, queue, allocator and command list.
        let device = create_device_handle(&state, &mut memory);
        let queue_args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: HANDLE_SLOT + 8,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_queue(&state, &queue_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let queue = memory.read_u64(HANDLE_SLOT + 8).expect("queue handle");
        let allocator_args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: HANDLE_SLOT + 16,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_allocator(&state, &allocator_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let allocator = memory.read_u64(HANDLE_SLOT + 16).expect("allocator handle");
        let list_args = Win64Args {
            rcx: device,
            rdx: allocator,
            r8: 0,
            r9: HANDLE_SLOT + 24,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_command_list(&state, &list_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let list = memory.read_u64(HANDLE_SLOT + 24).expect("list handle");

        // The texture, the vertex buffer and the render target.
        let texture_args = call_args(
            &mut memory,
            device,
            2,
            2,
            DXGI_FORMAT_R8G8B8A8_UNORM as u64,
            &[TEXTURE_ADDRESS, HANDLE_SLOT + 32],
        );
        assert_eq!(
            xenora_create_texture2d(&state, &texture_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let texture = memory.read_u64(HANDLE_SLOT + 32).expect("texture handle");
        let buffer_args = Win64Args {
            rcx: device,
            rdx: VERTEX_ADDRESS,
            r8: 96,
            r9: HANDLE_SLOT + 40,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_buffer(&state, &buffer_args, &mut memory).expect("service call succeeds"),
            ok()
        );
        let buffer = memory.read_u64(HANDLE_SLOT + 40).expect("buffer handle");
        let target_args = Win64Args {
            rcx: device,
            rdx: 2,
            r8: 2,
            r9: HANDLE_SLOT + 48,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_render_target(&state, &target_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let target = memory.read_u64(HANDLE_SLOT + 48).expect("target handle");

        // One descriptor in each heap.
        let srv_heap_args = Win64Args {
            rcx: device,
            rdx: HEAP_TYPE_CBV_SRV_UAV as u64,
            r8: 1,
            r9: HANDLE_SLOT + 56,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_descriptor_heap(&state, &srv_heap_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let srv_heap = memory.read_u64(HANDLE_SLOT + 56).expect("heap handle");
        let sampler_heap_args = Win64Args {
            rcx: device,
            rdx: HEAP_TYPE_SAMPLER as u64,
            r8: 1,
            r9: HANDLE_SLOT + 64,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_descriptor_heap(&state, &sampler_heap_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let sampler_heap = memory
            .read_u64(HANDLE_SLOT + 64)
            .expect("sampler heap handle");

        // The view, the sampler and the root signature.
        let view_args = call_args(&mut memory, device, srv_heap, 0, texture, &[28u64]);
        assert_eq!(
            xenora_create_shader_resource_view(&state, &view_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let sampler_args = call_args(
            &mut memory,
            device,
            sampler_heap,
            0,
            D3D12_FILTER_MIN_MAG_MIP_POINT as u64,
            &[
                SAMPLER_ADDRESS_CLAMP as u64,
                SAMPLER_ADDRESS_CLAMP as u64,
                SAMPLER_ADDRESS_CLAMP as u64,
            ],
        );
        assert_eq!(
            xenora_create_sampler(&state, &sampler_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let root_args = Win64Args {
            rcx: device,
            rdx: 0,
            r8: 1,
            r9: HANDLE_SLOT + 72,
            rsp: 0,
        };
        assert_eq!(
            xenora_create_root_signature(&state, &root_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let root_signature = memory
            .read_u64(HANDLE_SLOT + 72)
            .expect("root signature handle");

        // Bind the heaps, the root signature and the two tables.
        let heaps_args = Win64Args {
            rcx: list,
            rdx: srv_heap,
            r8: sampler_heap,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_descriptor_heaps(&state, &heaps_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let root_args = Win64Args {
            rcx: list,
            rdx: root_signature,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_graphics_root_signature(&state, &root_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let srv_table_args = Win64Args {
            rcx: list,
            rdx: 0,
            r8: srv_heap,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_graphics_root_descriptor_table(&state, &srv_table_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let sampler_table_args = Win64Args {
            rcx: list,
            rdx: 1,
            r8: sampler_heap,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_graphics_root_descriptor_table(&state, &sampler_table_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );

        // The render target, the viewport and the draw.
        let set_target_args = Win64Args {
            rcx: list,
            rdx: target,
            r8: 0xFF00_0000,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_render_target(&state, &set_target_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let viewport_args = Win64Args {
            rcx: list,
            rdx: 2,
            r8: 2,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_set_viewport(&state, &viewport_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let vertex_args = call_args(&mut memory, list, 0, buffer, 0, &[32]);
        assert_eq!(
            xenora_set_vertex_buffer(&state, &vertex_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let draw_args = Win64Args {
            rcx: list,
            rdx: 3,
            r8: 1,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_draw(&state, &draw_args, &mut memory).expect("service call succeeds"),
            ok()
        );
        let close_args = Win64Args {
            rcx: list,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_close_command_list(&state, &close_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let execute_args = Win64Args {
            rcx: queue,
            rdx: list,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_execute_command_lists(&state, &execute_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );

        // The frame is the colour of the texture's red column.
        let readback_args = Win64Args {
            rcx: target,
            rdx: READBACK_ADDRESS,
            r8: 16,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_readback_resource(&state, &readback_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let mut pixels = [0u8; 16];
        memory
            .read_bytes(READBACK_ADDRESS, &mut pixels)
            .expect("readback bytes");
        assert_eq!(pixels.len(), 2 * 2 * 4);
        for pixel in pixels.as_chunks::<4>().0 {
            assert_eq!(*pixel, [255u8, 0, 0, 255]);
        }

        // The software reference backend drew the frame.
        let info_args = Win64Args {
            rcx: HANDLE_SLOT + 88,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        };
        assert_eq!(
            xenora_get_last_frame_info(&state, &info_args, &mut memory)
                .expect("service call succeeds"),
            ok()
        );
        let mut info = [0u8; 16];
        memory
            .read_bytes(HANDLE_SLOT + 88, &mut info)
            .expect("frame info");
        assert_eq!(
            u32::from_le_bytes(info[0..4].try_into().expect("backend")),
            0
        );
        assert_eq!(u32::from_le_bytes(info[4..8].try_into().expect("width")), 2);
        assert_eq!(
            u32::from_le_bytes(info[8..12].try_into().expect("height")),
            2
        );
        assert_eq!(
            u32::from_le_bytes(info[12..16].try_into().expect("draw count")),
            1
        );
    }
}
