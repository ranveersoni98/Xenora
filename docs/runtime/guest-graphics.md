# Guest graphics command path

Xenora's guest runtime can execute x86-64 programs, load original PE32+
executables, and translate gfx1030 vertex and pixel stages to Metal. What it
could not do, until this interface, was let a *guest program* author graphics
work. The D3D12-style runtime in `crates/loader/src/graphics.rs` offered
devices, command queues, allocators, command lists, resources, descriptor
heaps, root signatures, shader resource views, samplers, index buffers and
draws, but only as a Rust API that the guest could not reach.

The earlier prototype, `xenora_fixture.dll!SubmitGuestDraw`, did not close
that gap. It created its own device, queue, allocator and command list, read
one hardcoded 48-byte vertex buffer from a guest address, issued one
three-vertex draw with a caller-supplied clear colour, and returned a pixel
*count*. The guest could not create its own resources, bind its own index
buffer or render target, read a framebuffer back, or keep a device across
calls. A feature that exists inside the Metal backend but cannot be reached
from guest execution is not guest compatibility.

This document specifies the interface that closes it.

## Module and calling convention

The guest graphics path is exported from `xenora_graphics.dll`. It is a
separate module from `xenora_fixture.dll` so that the prototype services and
their existing fixtures keep working unchanged.

Every export uses the Win64 calling convention and returns an `HRESULT`
(`i32`) in `RAX`. `S_OK` is `0`. Failure codes are the usual Win32 values
mapped into `HRESULT` form, so `E_INVALIDARG` is `0x80070057` and `E_FAIL` is
`0x80004005`.

Guest object handles are opaque `u64` values. They are generation-checked, so a
handle of a destroyed object never resolves to a new object that reuses its
slot. Zero is not a valid handle. The guest passes a handle back exactly as it
received it; a handle is never a host pointer.

Creation exports that return an object handle require a non-null pointer to
eight writable guest bytes. They return `E_INVALIDARG` for an invalid output
before creating the object.

| Export | Arguments (Win64 order) | Effect |
| --- | --- | --- |
| `XenoraCreateDevice` | `ppDevice` | Creates a device and writes its handle to `*ppDevice`. |
| `XenoraCreateCommandQueue` | `device`, `listType`, `ppQueue` | Creates a command queue. `listType` must be `0` (direct). |
| `XenoraCreateFence` | `device`, `initialValue`, `ppFence` | Creates a device-owned timeline fence at a `u64` value and writes its handle to `*ppFence`. |
| `XenoraQueueSignal` | `queue`, `fence`, `value` | Signals the fence after earlier work and waits on that queue. |
| `XenoraQueueWait` | `queue`, `fence`, `value` | Records a dependency for the next execute or signal on the queue. |
| `XenoraGetFenceCompletedValue` | `fence`, `pValue` | Writes the completed `u64` value to eight writable guest bytes at `pValue`. |
| `XenoraDestroyFence` | `fence` | Destroys a fence once all applicable queue waits have been consumed. |
| `XenoraCreateCommandAllocator` | `device`, `listType`, `ppAllocator` | Creates a command allocator. `listType` must be `0`. |
| `XenoraCreateCommandList` | `device`, `allocator`, `listType`, `ppList` | Creates a recording command list. `listType` must be `0`. |
| `XenoraCreateBuffer` | `device`, `guestAddr`, `byteLength`, `ppResource` | Creates a buffer whose contents are the `byteLength` guest bytes at `guestAddr`. |
| `XenoraCreateRenderTarget` | `device`, `width`, `height`, `ppResource` | Creates an `R8G8B8A8_UNORM` two-dimensional render target. |
| `XenoraCreateTexture2D` | `device`, `width`, `height`, `format`, `guestAddr`, `ppResource` | Creates an `R8G8B8A8_UNORM` two-dimensional texture whose pixels are the guest bytes at `guestAddr`. `guestAddr` may be `0` for a texture with no guest backing. |
| `XenoraSetVertexBuffer` | `list`, `slot`, `resource`, `offset`, `stride` | Binds a vertex buffer at `slot`, which must be `0`. `stride` is the size of one vertex record in bytes and must be at least 16. |
| `XenoraSetIndexBuffer` | `list`, `resource`, `offset`, `dxgiFormat` | Binds an index buffer. `dxgiFormat` is `57` (`R16_UINT`) or `42` (`R32_UINT`). |
| `XenoraSetRenderTarget` | `list`, `resource`, `clearColor` | Binds the colour target and the clear colour. `resource` may be `0` for no target. `clearColor` is packed `R | G<<8 | B<<16 | A<<24`. |
| `XenoraSetViewport` | `list`, `width`, `height` | Sets the viewport. Both dimensions must be in `1..=4096`. |
| `XenoraDraw` | `list`, `vertexCount`, `instanceCount`, `startVertex` | Records a non-indexed draw. |
| `XenoraDrawIndexed` | `list`, `indexCount`, `instanceCount`, `startIndexBase` | Records an indexed draw. `startIndexBase` packs `startIndex` in the low 32 bits and a sign-extended 16-bit `baseVertex` in the high 32 bits. |
| `XenoraCloseCommandList` | `list` | Ends recording so the list can be executed. |
| `XenoraExecuteCommandLists` | `queue`, `list` | Executes a closed list. The rendered pixels are written into the bound render target. |
| `XenoraReadbackResource` | `resource`, `guestAddr`, `byteLength` | Copies exactly `byteLength` bytes from the start of a resource into guest memory at `guestAddr`. A zero length, a length beyond the resource, or an unwritable output span returns `E_INVALIDARG` without writing bytes. |
| `XenoraGetLastFrameInfo` | `ppInfo` | Writes four `u32`s: backend, width, height, draw count. |
| `XenoraCreateDescriptorHeap` | `device`, `heapType`, `numDescriptors`, `ppHeap` | Creates a descriptor heap. `heapType` is `0` (`CBV_SRV_UAV`) or `1` (`SAMPLER`). |
| `XenoraCreateShaderResourceView` | `device`, `heap`, `slot`, `resource`, `format` | Writes a shader resource view over `resource` into the heap slot. The format must equal the resource's. |
| `XenoraCreateSampler` | `device`, `heap`, `slot`, `filter`, `addressU`, `addressV`, `addressW` | Writes a sampler into the heap slot. The filter must be `0` (point) and every address mode must be the clamp mode. |
| `XenoraCreateRootSignature` | `device`, `srvParameter`, `samplerParameter`, `ppRootSignature` | Creates a root signature with exactly two pixel-stage descriptor tables: one for the shader resource view at root parameter index `srvParameter` and one for the sampler at `samplerParameter`. The two indices must differ. |
| `XenoraSetDescriptorHeaps` | `list`, `srvHeap`, `samplerHeap` | Binds at most one heap of each type. A heap of `0` means no heap of that type. |
| `XenoraSetGraphicsRootSignature` | `list`, `rootSignature` | Binds the root signature. |
| `XenoraSetGraphicsRootDescriptorTable` | `list`, `rootParameterIndex`, `heap`, `slot` | Binds the descriptor table for one root parameter. |
| `XenoraDestroyResource` | `resource` | Destroys a resource. |
| `XenoraDestroyCommandList` | `list` | Destroys a command list. |
| `XenoraDestroyCommandAllocator` | `allocator` | Destroys a command allocator. |
| `XenoraDestroyCommandQueue` | `queue` | Destroys a command queue. |
| `XenoraDestroyDevice` | `device` | Destroys a device. |

`XenoraGetLastFrameInfo` reports the backend that produced the last frame:
`0` for the deterministic software reference rasteriser and `1` for native
Metal. A guest that reports the wrong backend has not run on the GPU, and the
integration test checks this value rather than assuming it.

## Timeline fences

The queue and fence must belong to the same device. `XenoraQueueWait` records
the dependency and returns immediately. The next execute or signal applies it.
If its producer has yet to submit a sufficient signal, that operation returns
`HRESULT_FROM_WIN32(ERROR_TIMEOUT)` (`0x800705B4`). The queue retains the wait so
the guest can submit the producer signal and retry. Signals can repeat their
current value or increase it. Decreasing signals and `UINT64_MAX` are invalid.
The runtime allows 16 live fences and eight distinct pending fences per queue.

A native graphics context uses its configured Metal shared-event factory. The
software reference applies the same ordering with an in-memory timeline.
A device with a live fence, or a fence with a pending queue wait, cannot be
destroyed. Those refusals return `E_ACCESSDENIED`.

## Resource lifetime

Destruction is ordered, and the order is enforced rather than assumed.

- A device cannot be destroyed while a queue, allocator, command list or
  resource created from it is still alive.
- A command allocator cannot be destroyed while a command list created from it
  is still alive.
- A command list cannot be destroyed while it is still recording. Close it
  first.
- A resource cannot be destroyed while a recording command list references it.
- A command queue cannot be destroyed while a command list it submitted is
  still alive.

Each refusal is an explicit error, not a silent success and not a use-after-free.

## Vertex layout

A vertex record is `stride` bytes. A flat draw reads three consecutive `float4`
positions from the bound offset and ignores the stride, so a flat guest may
bind 16-byte records. A textured draw reads a `float4` texture coordinate after
each position and therefore needs a stride of at least 32 bytes.

## Textured draws

A guest that wants a sampled texture binds it in the usual order:

1. Create the texture with `XenoraCreateTexture2D`, pointing at guest memory
   that holds its pixels.
2. Create a `CBV_SRV_UAV` descriptor heap and a `SAMPLER` descriptor heap.
3. Create a shader resource view over the texture in a slot of the first heap,
   and a sampler in a slot of the second.
4. Create a root signature whose two descriptor tables hold the view and the
   sampler.
5. Record `XenoraSetDescriptorHeaps`, `XenoraSetGraphicsRootSignature` and one
   `XenoraSetGraphicsRootDescriptorTable` per root parameter, then the
   viewport, the render target, the vertex buffer and the draw.

The service computes the CPU and GPU descriptor handles for a heap slot
internally, so a guest never performs descriptor handle arithmetic and never
sees a host pointer. A slot beyond the heap's descriptor count is refused.

## The execution path

A guest draw now travels the whole way:

```
guest PE32+ executable
  -> loader maps, relocates, binds imports
  -> guest calls xenora_graphics.dll exports
  -> services drive the GraphicsContext
  -> graphics commands are recorded and validated
  -> the backend renders (software reference, or native Metal)
  -> Metal runs the translated gfx1030 vertex and pixel stages
  -> pixels are written into the bound render target resource
  -> XenoraReadbackResource copies them into guest memory
  -> the guest inspects them and exits with a status
```

The native path crosses the existing `BackendRenderer` closure boundary, so
`crates/loader` stays free of a direct Metal dependency and the software
reference rasteriser remains the default on hosts without a GPU.

## Limits

- One triangle per draw, one instance, no primitive restart.
- Vertex records are a `float4` position, plus a `float4` texture coordinate
  for a textured draw.
- Render targets and textures are `R8G8B8A8_UNORM`, at most 64 by 64.
- The sampler is point filtering with clamp addressing; that is the only
  supported state.
- Descriptor heaps, shader resource views, samplers and root signatures are
  reachable, but constant buffers, upload or readback heaps, render target
  views and depth views are not.
- Draw execution and readback are synchronous. Fences order work across guest
  queues.
- The `x86_64` guest architecture is decoded by Xenora; the guest is not an
  Xbox title and no console behaviour is established here.

## Reproducing

The original guest program is
[`tests/compat_fixtures/guest_graphics.c`](../../tests/compat_fixtures/guest_graphics.c).
Its build script is
[`tests/compat_fixtures/build-guest-graphics.sh`](../../tests/compat_fixtures/build-guest-graphics.sh),
which cross-compiles it to x86-64 PE32+ and checks that the tools it uses are
native ARM64. The integration test is
[`crates/loader/tests/guest_graphics_path.rs`](../../crates/loader/tests/guest_graphics_path.rs):

```sh
cargo test --locked -p xenora-loader --test guest_graphics_path -- --nocapture
```

The textured counterpart is
[`tests/compat_fixtures/guest_textured.c`](../../tests/compat_fixtures/guest_textured.c),
built by
[`tests/compat_fixtures/build-guest-textured.sh`](../../tests/compat_fixtures/build-guest-textured.sh)
and exercised by
[`crates/loader/tests/guest_textured_path.rs`](../../crates/loader/tests/guest_textured_path.rs):

```sh
cargo test --locked -p xenora-loader --test guest_textured_path -- --nocapture
```

`scripts/test-gpu.sh` runs the native Metal variants of the geometry and texture tests.

The two-queue fence workload is
[`fixtures/pe/guest-fence.c`](../../fixtures/pe/guest-fence.c). Rebuild or compare
the checked-in PE with `fixtures/pe/build-guest-fence.sh --check`. Run the software
reference test with `cargo test --locked -p xenora-loader --test guest_graphics_fences`.
Add `--features gpu-tests` for the native shared-event test on Apple Silicon.
