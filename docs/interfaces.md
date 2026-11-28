# Interfaces

## gfx1030 compute fixtures

The first input is little-endian gfx1030 machine code for a compute fixture with optional statically resolved forward scalar branches. The synthetic ABI starts with full Wave32 EXEC and reserves vector general-purpose register (VGPR) 0 for the grid index used by buffer accesses. Resource operands select documented synthetic bindings. The parser must require explicit target identification and validate all lengths before allocating. Console containers and AMDHSA initialization require separate contracts.

The production decoder takes borrowed code bytes. Its output records typed instructions, operand classes, original offsets and byte lengths. Unknown encodings and unsupported forms fail with a byte offset. The reference interpreter takes the original bytes and input words and performs its own decoding. It shares no production instruction definitions.

The compiler lifts decoded instructions to typed operations and verifies register initialization, supported resource offsets and termination before generating MSL. The initial subset permits only lane-indexed 32-bit buffer accesses against two disjoint buffers with equal lengths. The input is read-only. Each invocation may write only its own output word. The compiler and reference check instruction boundaries, termination placement and buffer bindings throughout the stream. Register initialization and transfer state are checked on the path selected by compile-time known forward scalar branches. Dynamic branches, workgroup barriers and cross-lane operations remain unsupported.

The Wave32 execution mask (EXEC) starts full. A supported scalar move can
assign a known 32-bit value to its low half. Each bit selects the corresponding
logical lane, numbered by the one-dimensional grid index modulo 32. Partial
masks limit vector arithmetic and moves to selected lanes. These instructions
must write an initialized destination so inactive lanes can retain their values.
Empty EXEC suppresses vector arithmetic and moves. Reachable vector memory
operations require full EXEC. Forward branches on EXEC or the vector condition
code (VCC) test only their low halves. VCC must be initialized before use.

The native backend exposes `NativeCompute::new()` and `run_words(source, entry, input)` for trusted MSL. It binds input at index 0 and output at index 1, dispatches one invocation per word and returns owned readback after completion. `run_words_profiled` returns the same output plus measured library, pipeline, GPU and host durations for the benchmark harness; those timings are single submissions, not distributions. The caller runs generated MSL in a bounded child process. Raw MSL is a trusted developer input. Errors report the operation and backend detail. Across other stages, diagnostics carry a stage, error kind, optional byte offset and human-readable context.

## Synthetic guest experiment

The separate [X1–X4 driver](../experiments/x1/README.md) loads fixed-base
PE32+ fixtures, interprets a bounded x86-64 subset and dispatches synthetic
services. X3 and X4 validate fixed-size command records from read-only
guest bytes before issuing compute or draw work. Their command formats and
Metal shaders are authored for the experiment.

The multi-function guest fixture (X6) maps PE32+ sections with separate
read, write and execute permissions. Its interpreter tracks the expected
return slot and continuation for each call. A return from the authenticated
root frame ends execution.

The named-import fixture (X7) resolves imports for one synthetic module
before guest entry. An indirect call may invoke only a resolved slot in the
guest import address table. The handler validates the guest buffer and
operates on words in checked guest memory. The command prints the guest
exit value, while its host exit code reports whether loading and execution
succeeded.

With the Metal feature, the guest compute fixture (X8) adds the
`xenora_compute` import to the same loader. RCX points to a four-byte-aligned
readable and writable three-word buffer. RDX points to a readable aligned
16-byte record containing four little-endian 32-bit fields: command 1,
handle 0, input slot 0, and word count 3. Handle 0 names the buffer supplied
on this call and is consumed after a successful dispatch. A second submission
within the same guest run fails with a stale-resource fault.
The CPU validates both spans before creating a Metal context.
It selects the original translated XOR program, waits for completion,
writes the three output words back to guest memory, and returns 3.
The guest can read the result through its existing report import.

A general guest command stream must submit validated resource handles and ranges through an explicit address translation boundary. The graphics side owns mappings and the lifetime of in-flight views. Completion and fence signaling flow back across the command boundary. Guest addresses are never host pointers.

`NativeCompute::run_guest_words` takes a host-provided immutable resource
table and a synthetic guest view. The view selects an input slot, table index,
byte offset and byte length. The backend validates slot zero, little-endian
32-bit words, alignment, bounds and dispatch size before copying the selected
range into a Metal buffer. Slot one holds a separate output buffer. The call
returns owned words after command completion or a stage-specific error.

## PE32+ fixture startup and static import reports

`xenora_loader::startup::run_synthetic_startup` takes an original, trusted
fixture, guest memory addresses, a service registry and an entry instruction
budget. It maps and rebases the image, binds imports, initializes thread-local
storage, invokes its callbacks and runs the entry point. The fixture entry point
uses a Win64-aligned stack. It may end with HLT, call `ExitProcess`, or return.
The result includes the loaded guest memory and the entry execution outcome.

A guest ends its process through `kernel32.dll!ExitProcess`, also reachable as
`api-ms-win-core-processthreads-l1-1-0.dll!ExitProcess`. Execution stops with
`ExitReason::ProcessExit(status)`, where the status is the full 32-bit value
the guest passed. Only the guest stops: the host process is not ended. A
returning entry point does the same with EAX as the status, which matches
Windows while the process has one thread. The exit closes every guest handle:
kernel objects, WinHTTP objects, Winsock sockets and task-queue handles,
which `ServicesState::open_handle_count` counts together. Files stay on the synthetic `C:` drive, guest memory stays mapped so the host
can inspect it, and `atexit` functions are not run: that belongs to the C
runtime's `exit`, described below. `ServicesState::exit_status`
reports the status. After an exit the `DbtEngine` that ran the guest executes
no further guest instruction and answers every later `run` with the same
`ProcessExit`. A service callback that was in progress is never resumed.

A C program ends through the C runtime instead. `ucrtbase.dll` and
`api-ms-win-crt-runtime-l1-1-0.dll` provide three ways out, each ending the
guest with the same `ProcessExit` and the same cleanup as `ExitProcess`:

| Service | Behaviour |
| --- | --- |
| `exit(status)` | Calls the functions registered with `atexit` and `_crt_atexit`, most recently registered first, then ends the process with `status` |
| `_exit(status)` | Ends the process with `status` and calls no registered function |
| `abort()` | Ends the process with exit code 3 and calls no registered function |

`exit` takes one function at a time from the registered list. A function
registered while `exit` runs is therefore called next, before the older ones
that have not run yet, which is ISO C's rule. A registered function that calls
`exit` again is undefined in ISO C; here the functions that have not run yet
run once each and the process ends with the status of the later call.
Functions that `_cexit` has already run are not run again.

All three are partial. `exit` flushes no stream, because there are none, and
runs no thread-local destructor. It does not walk a module's own `_onexit`
table; that module's startup code runs it through `_execute_onexit_table`.
`abort` prints no message and does not call a `SIGABRT` handler, which the
documentation says it does when one is set. `_Exit`, `quick_exit` and
`_c_exit` are not provided. None of this has been compared with Windows.

A TLS callback may end the process too. Startup then reports the exit as its
outcome, with the status, and runs neither the remaining callbacks nor the
entry point; `StartupResult::tls_callbacks` counts the callbacks that finished.
Any other stop inside a TLS callback is still a startup error.

The executable's static TLS block follows the alignment in its PE TLS
directory, up to 8 KiB. Startup rounds the address again when the block must
move past the reserved thread environment block. An unspecified alignment
keeps the default layout, and the reserved encoding is rejected.

The engine recognises two return addresses, one under the entry point and one
under a guest callback, before it executes anything at them. Both are in the
4 KiB page at `imports::RETURN_SENTINEL_PAGE`, which startup reserves with no
access. An image or layout that covers that page is refused, and a guest
allocation there fails. The import trampolines above that page are intercepted
in the same way and are not reserved.

Loading an image maps its headers as well as its sections. The first
`SizeOfHeaders` bytes of the file are mapped read-only at the image base, in
whole 4 KiB pages. Everything in those pages past `SizeOfHeaders` is zero, even
where the file holds more bytes there. A guest can read its own DOS header,
section table and data directories; it cannot write or execute them.

When startup loads an image away from its preferred base, it writes the load
base into the mapped optional header's `ImageBase` field after the relocations
have been applied, so an entry aimed at that field cannot leave any other value
there. This is Xenora's policy: the PE specification defines `ImageBase` as the
preferred base, and the behaviour has not been compared with Windows.

The load is refused with `PeError::InvalidHeaderSize` when `SizeOfHeaders` is
zero, ends before the section table does, runs past the end of the file, or its
pages would reach into a section, and when the bytes given to the loader are not
the PE32+ headers that were parsed. The page rule is stricter than the loader
was before: an image whose section alignment is below 4 KiB, with a section
that starts inside the header page, used to load and is now refused. The header
pages count toward the 256 MiB mapping budget of one image, which is checked
before anything is mapped. `ParsedPe::parse` does not make these checks, so
static inspection of a file is unchanged.

The separate explicit-module loader infrastructure can plan and map a batch of
caller-supplied in-memory PE32+ images without host file search. Batch mapping
returns half-open reservation records and also retains those complete image
spans in `GuestMemory` as lightweight ownership records. Only headers and
sections are committed; holes remain unmapped. A batch is rejected before
mutation when memory already exists anywhere in a planned span, and later
unrelated mappings or dynamic allocations cannot reuse those holes. The records
do not implement unloading,
per-section ownership or host operating-system guard pages. Batch relocation
requires exactly one reservation per input image and validates its index,
64 KiB-aligned base, `SizeOfImage` extent, entry and preferred-base metadata
and overlap shape before mutation. It then applies the existing DIR64
relocation engine at each reserved base and writes each mapped optional-header
`ImageBase` field. A DIR64 target must be continuously backed by committed
image headers or sections; a target in a `SizeOfImage` hole is refused even
if inconsistent memory state contains unrelated bytes there. Any validation or
relocation failure restores the exact pre-relocation address space, including
fixups already applied to earlier images. The implementation uses a whole
`GuestMemory` snapshot for that transaction; this is correct but deliberately
expensive and is not the final memory-ownership design. Relocation itself
performs no import or IAT write. Ordinary-IAT binding is a separate implemented
step, while delayed imports, service registration, exception-directory
registration, TLS callbacks, unloading, reference counting and module execution
remain unsupported. Before ordinary-IAT writes, the binder also requires
fixed-base images to occupy their preferred reservations and each image/base
pair to satisfy the same nonmutating mapping validation that produces legitimate
reservations.
step, while delayed imports, service registration, TLS callbacks, unloading,
reference counting and module execution remain unsupported.

Batch exception-directory registration uses the same exact-one reservation
validation. For each image it reads PE data directory 3, requires whole aligned
`RUNTIME_FUNCTION` entries in ascending order inside `SizeOfImage`, and requires
the directory, function ranges and fixed unwind-data bytes to be backed by
committed image headers or sections. Valid tables are registered in input order
for the existing x64 exception lookup path, while an absent directory is an
honest no-op. Registration writes no guest bytes; if a later image fails, the
function-table list is truncated to its original length so earlier registrations
do not remain visible. Language-specific variable-sized handler data is not fully bounded here. This
does not execute module code, change unwind semantics, implement dynamic
function-table APIs or provide unloading.

Batch TLS preparation uses the same exact-one reservation validation. For
each image it reads PE data directory 9, rebases preferred-image virtual
addresses to the reservation base, and validates the complete declared
directory, the four-byte index location, the template bytes and the callback
array including its terminator against committed image backing. Callback
targets must be inside executable committed image code, but they are only
reported; this layer never executes them. An absent directory is an honest
no-op.

The caller selects one thread's TLS pointer array by its eight-byte-aligned
base. If that array is absent it is created as bounded thread-owned memory;
if it already exists it must be writable. Zero slots are Xenora's free-slot
markers for this batch layer. Preparation never overwrites a nonzero slot and
assigns the first free slots in input order to modules that have TLS
directories. It writes each module's index, copies its template in bounded
chunks into independently owned thread-dynamic storage and leaves the declared
zero-fill bytes zero. Reports therefore distinguish no directory, prepared
storage ownership and callbacks discovered without execution. The caller must
supply the batch in dependency order; this layer treats input order as the
initialization-order contract. Dependency sorting and module initialization
execution remain separate responsibilities.

All TLS metadata is validated before mutation. A later allocation, backing or
copy failure restores the exact pre-preparation memory through the same
deliberately expensive whole-memory snapshot used by the other batch seams.
This is not a general memory transaction API. TLS callbacks, `DllMain`, thread
creation policy, dynamic TLS APIs, unloading and reference counting remain
unsupported. A directory with no template bytes and no zero-fill receives a
batch-local index but has no storage pointer with which later independent
batches could retain that slot; that edge is part of the unresolved storage
ownership design rather than silent Windows-compatible behavior.

Module initialization-order planning is also non-executing metadata. The
planner requires positional agreement between logical package inputs, parsed
explicit images and reservations. It can run before TLS preparation; when TLS
reports are supplied it validates and carries them through the same image
indexes. It rebuilds the module dependency graph from the supplied bytes and
rejects a stale or mismatched caller-supplied graph before using it. The resulting components keep
the graph's provider-before-consumer condensation order and annotate each
module with its file name, actual reserved entry-point address and TLS callback
addresses. DLL entries are distinguished as potential `DllMain` work from
non-DLL process entries; neither kind is executed. Circular strongly connected
components remain grouped without an invented member order, and incomplete
import or export table inspection is reported as ordering uncertainty because
hidden dependencies could change the correct order. Loader-lock behavior,
thread policy, initialization execution, unloading and reference counting
remain unsupported.

Package startup composes those seams for one explicit set of images.
`run_package_startup` takes positional package modules, an entry index, a
layout arena, an import registry and a step budget. It builds the dependency
graph, plans and maps every image, applies relocations, registers exception
directories, classifies and binds each import, prepares TLS, then runs TLS
callbacks and `DllMain` in provider-before-consumer order before the entry
point. Detach runs in reverse order only for modules whose attach completed.
An export from another package image takes precedence over a same-named host
registration; a missing module or export, an unresolved API set and an
explicit stub are refused with structured per-import diagnostics before any
guest code runs. The ordinary runner exposes this as
`xenora run --pe <entry> --package <module>...`, with one bounded regular-file
snapshot per supplied image, distinct file names and the existing mapped-image
budget as the arena limit. The tested package is an original no-CRT executable
with two dependent provider DLLs built by the native ARM64 toolchain; console
compatibility and game execution are not claimed.

A separate closed-world provisioned module store admits immutable PE32+ images
under bounded, printable logical names. Host callers populate it before
execution; guest strings are never converted to host paths. Admission rejects
duplicate canonical names, any name owned by a registered service module,
malformed images and the store's aggregate byte and module limits. The ordinary
runner exposes this admission as `--module <name>=<path>`: each value must name
an existing regular file and is read as a bounded snapshot. Admission alone
does not load or execute the image.

`prepare_runtime_load` is a crate-internal preparation seam rather than a
guest-visible `LoadLibrary` implementation. It takes logical roots, collects
their in-package transitive dependencies and refuses circular components before
any memory mutation. It uses the existing layout planner with caller-supplied
occupied ranges, then composes batch mapping, relocation, exception-directory
registration, transactional IAT writing and TLS preparation. Service registry
keys are resolved first; provisioned images cannot claim a service module name,
and package exports resolve forwarded requests inside the selected dependency
closure. All imports are inspected before the first write, an explicit stub is
refused, and any failure after mapping restores the caller's whole
`GuestMemory` snapshot. Success returns reservations, per-stage reports and
IAT diagnostics but runs no guest code: TLS callbacks are discovered only, and
initialization, unloading and reference counting remain later lifecycle work.
Preparation does not itself admit the images to the kernel32 dynamic-module
catalog; that metadata registration is a separate crate-internal hook for the
later guest-visible load integration.

The original fixture in `fixtures/pe/loadlib` is static evidence for the later
guest-visible integration, not a working `LoadLibrary` path. Its no-CRT consumer
imports only `LoadLibraryA`, `GetProcAddress`, `FreeLibrary` and `ExitProcess`,
loads logical module `xenora_loadlib.dll`, resolves one function and three
initialization-evidence exports by name, calls the function indirectly and exits
with status 70 only when the expected values are present. The provider's TLS
callback and `DllMain` write distinct markers. Two control images keep the same
embedded logical module name: one omits the function export and one refuses
`DLL_PROCESS_ATTACH`. The fixture build is reproducible with the native ARM64
LLVM toolchain. No initializer execution, registry publication, reference
counting, unloading or end-to-end dynamic loading is implied.

`xenora probe --mode static` inventories ordinary and delay-loaded PE imports
without guest execution. Without `--report` it writes to `diagnostics/probe`,
where `xenora imports sync` also looks. `missing_imports.csv` lists unresolved ordinary keys
with their import address table relative virtual addresses. The full inventory,
`imports.csv`, marks each entry `ordinary` or `delayed` in its `import_table`
column and records whether each key is registered, its implementation
status, and the canonical module behind API-set aliases. Modules and services
loaded by other means at run time require separate analysis. The coverage matrix
groups unresolved ordinary imports by shared startup prerequisites. Static
imports do not reveal call order. The JSON report counts import slots, DLL and
symbol keys, distinct names with DLL-scoped ordinals, and canonical registered
handlers separately. The unresolved total includes explicitly tracked
unsupported APIs and other missing handlers. Existing stubs remain visible in
the full inventory.

Delay-loaded imports come from the PE32+ delay-load directory, data directory
13 in Microsoft's PE format. The probe reports each one with its DLL, symbol or
ordinal, and slot in the delay import address table, after the ordinary rows.
Binding does not resolve them: the PE format leaves that to a delay-load helper
inside the image. The totals above and `missing_imports.csv` therefore cover
ordinary imports only, and the JSON report counts delayed slots and DLLs in
`delayed_imports` and `delayed_imported_dlls_count`. `xenora imports sync`
leaves delayed rows out of its backlog for the same reason.

The probe reads only descriptors that lie wholly inside the directory's
declared size, and expects that size to hold the empty descriptor that ends the
table. It reads descriptors whose `RvaBased` attribute is set, and requires each
one's DLL name, import address table and import name table to be present and to
start in section data. A table that breaks one of these rules, sets a reserved
attribute bit, is truncated, or uses the earlier virtual-address descriptor form
is reported in `delay_import_error` and in the Markdown report, together with
the entries read before it.

### Microsoft atomic-wait deadlines (#1163)

`msvcp140_atomic_wait.dll` exposes deadline creation and remaining-time
helpers backed by the guest monotonic clock. Infinite deadlines retain their
sentinel, elapsed deadlines return zero, and finite wait intervals are capped
at ten days. The behavior is derived from the public [Microsoft STL source](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/src/atomic_wait.cpp)
(copyright Microsoft Corporation, Apache-2.0 WITH LLVM-exception). Atomic
waiting, notification and scheduling are not provided by these helpers.

### Microsoft codecvt locale-ID data (#1163)

The four `msvcp140_codecvt_ids.dll` UTF conversion facet ID exports each
bind to a distinct, zero-initialized eight-byte guest cell. This supports the
initial data objects only: lazy locale ID assignment, facet construction and
character conversion remain unsupported. The layout and initial value come
from the public Microsoft STL [locale header](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/inc/xlocale)
and [codecvt ID definitions](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/src/ulocale.cpp),
copyright Microsoft Corporation, Apache-2.0 WITH LLVM-exception. The
independently authored PE verifies storage identity and initialization only.

### Microsoft runtime memory exports (#1163)

`vcruntime140.dll` resolves `memcpy`, `memmove`, `memset`, `memcmp` and
`memchr` to the existing UCRT guest-memory services. They retain the same
bounds and fault behavior. The original MSVC-ABI guest fixture exercises
copying, overlap, filling, comparison, searching and zero-length comparison;
it is not evidence for the rest of VCRUNTIME or for Xbox execution.

### UCRT standard-stream buffer fields (#1163)

`_get_stream_buffer_pointers` resolves for the three standard UCRT streams.
It returns guest addresses of their current pointer, base pointer and count
fields in the requested output order; null output arguments are allowed.
A null stream returns `EINVAL`, and unknown or nonstandard streams stop with
the runtime-limit fault. Standard streams are modeled as unbuffered: their
base and current pointer reference their own two-byte guest storage and their
available count is zero. `fputc` and `fflush` retain the existing immediate
output behavior. Guest-controlled buffering, streams opened by `fopen`, and a
complete UCRT `FILE` implementation are not supported by this interface.

The declaration is in the public Windows SDK `stdio.h`; Microsoft classifies
this as an [internal CRT function](https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions).
The initial unbuffered pointer arrangement was checked against Windows SDK
10.0.22621.0 UCRT source. Original guest fixtures cover stable field addresses,
ordinary output, optional parameters, null input and invalid addresses.

### Microsoft-header iostream workload (#1163)

`fixtures/pe/msvc-iostream.cpp` is an original program that uses the actual
Microsoft STL headers and calls `std::cout.write`, `flush`, and `good` before
leaving its `ios_base::Init` scope. `fixtures/pe/build-msvc-iostream.sh` builds
it using local header paths supplied in `MS_STL_INCLUDE`, `MSVC_INCLUDE` and
`WINDOWS_SDK_INCLUDE`, and writes the executable under ignored `artifacts/`.
One local build used Microsoft STL commit `0cabaf3c7e0a73fe3040aabce40cd8833e80392b`,
VC headers 14.44.35207 and Windows SDK 10.0.22621.0. The Microsoft STL headers
are copyright Microsoft Corporation and licensed Apache-2.0 WITH LLVM-exception;
no vendor headers or redistributable binaries are included in this fixture.

In that local build, six of seven imports resolve to standard services; the `cout` object remains
unresolved. This is import resolution only, not successful execution. A
separate local run with Microsoft redistributable DLLs supplied as guest
modules stopped before execution with 76 required imports unresolved. A
separate original freestanding guest uses the same decorated exports, including
the `cout` data import, and executes the bounded slice described below. It does
not make the Microsoft-header fixture executable. No complete C++ stream
execution or cleanup is claimed.

### Static import census scope (#1163)

The historical probe input `artifacts/msvc-dll-probe/imports.csv` records the
static imports of one original Microsoft-header guest module, not a whole
redistributable package. Re-running the classifier against fresh `origin/main`
revision `bdedc62d309b0ee78ad0619c6eaad9f192d1ac94` found 198 distinct wanted
imports: 27 implemented, 95 partial and 76 missing. The missing set has 51
C/C++ CRT Runtime names and 25 `KERNEL32.dll` names. The latter cover
threadpool objects, pointer encoding, processor and stack diagnostics, file
information, locale and string conversion, temporary paths, callback
lifetime, and one unhandled-exception filter.

The number 76 is a single-module static census. It is not a reproduction of,
nor directly comparable with, the historical multi-module package preflight
counts of 75, 76, 77 or 83 recorded in separate local notes. No authorized
Microsoft redistributable DLLs or original package executable were available
for a fresh package preflight, so that question remains unresolved; no
Microsoft binary was added to the repository. Reports regenerated from the
CSV are import-classification evidence only. They do not show that any
redistributable DLL loads or executes, and they do not validate the fidelity
of any service.

### Microsoft ostream write and flush (#1163)

The narrow `basic_ostream::write` and `flush` exports support a guest-provided
x64 stream object with a guest stream buffer. They call the buffer lock,
`xsputn` or `sync`, and unlock virtual functions through the guest callback
boundary. Short writes and sync failure set `badbit`. A tied stream,
unit-buffered sentry, or exception requiring C++ unwinding stops explicitly;
these paths are not silently reported as successful. The documented method
behavior follows the public [Microsoft STL ostream implementation](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/inc/__msvc_ostream.hpp)
and [stream buffer header](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/inc/streambuf),
copyright Microsoft Corporation, Apache-2.0 WITH LLVM-exception. The vtable
slots and virtual-base layout were inspected using Clang with those headers.
The original synthetic-layout guests test callbacks, failure state and refusal
paths with a guest-provided stream object. The bounded `std::cout` object below
uses the CRT stream directly; neither validates general iostream ABI.

### Microsoft locale facet primitives (#1163)

The Microsoft x64 `locale::facet` increment and decrement exports update the
32-bit guest reference count at offset 8; decrement returns the facet when
the new count is zero, leaving destruction to its caller. The narrow
`ctype<char>::do_widen` scalar export preserves the input byte. These partial
primitives do not construct locale or facet objects or run destructors. Their
semantics follow the public [Microsoft STL locale header](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/inc/xlocale),
copyright Microsoft Corporation, Apache-2.0 WITH LLVM-exception. A locally
compiled synthetic-layout guest tests the primitives; independent acceptance
and a Microsoft-header locale lifecycle fixture remain outstanding.

### Microsoft stream state queries (#1163)

The x64 `ios_base` exports `rdstate`, `good`, `eof`, `fail` and `bad` read
the 32-bit state field at offset 16 of the guest `ios_base` subobject. Bit
meanings follow the public Microsoft STL [xiosbase header](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/inc/xiosbase);
its x64 layout was inspected using Clang with Microsoft headers. Synthetic
guest tests exercise the bits and an overflowing pointer. The accessors read
the bounded synthetic `std::cout` object below as well as guest-provided state;
they do not construct general streams, validate object type, or provide C++
unwinding.

### Microsoft STL initialization count (#1163)

`msvcp140.dll` exposes the Microsoft x64 decorated `ios_base::Init` count,
count accessor, public constructor and destructor, and their helpers. The data import and
accessor share one guest-memory cell, initialized to -1. Construction changes a
negative count to 1 and otherwise increments it; destruction decrements it. On
the final destruction Xenora checks and flushes the bounded `std::cout` object
below, then returns. Count overflow and a flush failure still stop the guest.
This is a partial initialization boundary: it does not initialize other
standard streams or establish general Microsoft STL support.

The count behavior is independently implemented from the publicly available
[Microsoft STL source at commit 0cabaf3](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/src/iostream.cpp)
and its [header declarations](https://github.com/microsoft/STL/blob/0cabaf3c7e0a73fe3040aabce40cd8833e80392b/stl/inc/xiosbase).
These files are copyright Microsoft Corporation, Apache-2.0 WITH LLVM-exception;
no source text was copied. The original freestanding fixture declares just the
ABI under test, imports the public constructor and destructor, and does not include
the Microsoft headers or prove a complete MSVC iostream program. Its output uses UCRT `puts`, not a C++ stream.

### Bounded standard output object (#1163)

The decorated `std::cout` data import is bound to one 128-byte writable guest
object. Its 32-bit state word at offset 16 and exception mask at offset 20 are
the same fields used by the `ios_base` accessors. `ostream::write` through that
object sends up to one mebibyte directly to the CRT standard output; a short or
failed transfer sets `badbit`, and a state bit already present in the exception
mask stops the guest instead of unwinding C++ exceptions. `ostream::flush`
checks the object state and the CRT descriptor; the stream holds no buffered
bytes. The final `ios_base::Init` destructor performs that flush before
returning.

`fixtures/pe/msvc-standard-stream.cpp` declares only these x64 exports. The
original guest writes `hello from std::cout`, flushes, checks `good`, and exits
with code 0; variants cover a forged object, a bad stream whose exception mask
includes `badbit`, and a transfer above the one-mebibyte bound. `fixtures/pe/build-msvc-standard-stream.sh` builds them
with native ARM64 Clang and `lld-link` without Microsoft headers or binaries.
This is one synthetic narrow stream: it supplies no stream buffer vtable,
locale, wide stream, `cerr`, `clog`, Microsoft DLL, complete iostream program or
independent acceptance.

### Import name diagnostics

`xenora_import_gen::demangle` decodes Microsoft Visual C++ decorated names
for diagnostics, in the style of Microsoft's `undname`. It covers functions,
data, member access and storage, `this` qualifiers, calling conventions,
constructors, destructors, common operators, `vftable` names, classes,
structs, unions, enums, pointers, references, primitive types, templates
with type and integer arguments, and name and type back-references. Function
pointer types, RTTI descriptors, nested function scopes and other constructs
return `None`, so callers show the decorated name instead of a guess. The
generator manifest's list of imports that need manual engineering shows the
undecorated form beside each decorated C++ import. Tests check names mangled
by clang for `x86_64-pc-windows-msvc` against their source declarations.

The synthetic process registry supports the current-process pseudo handle and
its process ID. The priority boost setter and getter record and query a guest
policy. They are partial until a guest scheduler applies the policy. The process
ID lookup is limited to the current-process pseudo handle. An unsupported
handle reports `ERROR_INVALID_HANDLE` through the guest error slot. The getter
rejects invalid guest output addresses with `ERROR_NOACCESS`.

Win32 references include Microsoft's documentation for
[GetCurrentProcess](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess),
[GetProcessId](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessid),
[SetProcessPriorityBoost](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocesspriorityboost),
and [GetProcessPriorityBoost](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesspriorityboost).

### Generated report paths and future caches

Probe exports can write to `artifacts/` or `diagnostics/probe/` within a
Xenora Git checkout. Explicit `--report` destinations outside checkouts are
allowed. Relative paths use the process's current directory. A symlink in
the directory path is resolved before applying the policy, and dangling
links or links at individual output filenames are refused. The guard checks
every filename before creating any directories or files.

Future persistent caches default to
`~/Library/Caches/local.xenora.Xenora/` on macOS and must be outside
checkouts, including ignored development output directories. This policy
does not enable a persistent cache.

The probe stages reports on the destination filesystem and publishes each
complete file by rename. An I/O failure during publication can leave a mix of
old and new reports. Use an output directory controlled by the caller.
Preflight assumes the directory tree stays stable. A writer exposed to
concurrent untrusted changes needs directory-descriptor-relative operations
that reject links during traversal and publication.

### Performance timing

The guest can import `QueryPerformanceCounter` and `QueryPerformanceFrequency`
from Kernel32 or the profile API set. The counter measures monotonic elapsed
time at a fixed 10 MHz, independently of wall-clock time. Synthetic fixtures
can advance it deterministically. A failed guest output write returns false
and records `ERROR_NOACCESS`. `GetTickCount` and `GetTickCount64` return
whole milliseconds since the synthetic runtime was created. The 32-bit value
wraps at 2³² milliseconds. Both use the monotonic clock and are available
through Kernel32 and the system-information API set.

RDTSC does not read this clock. It reads a separate guest time-stamp counter
that counts RDTSC executions and does not advance with time. The
[instruction registry](cpu/instruction-registry.md#guest-time-stamp-counter-and-rdtsc)
specifies that counter.

See Microsoft's documentation for
[QueryPerformanceCounter](https://learn.microsoft.com/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter)
[QueryPerformanceFrequency](https://learn.microsoft.com/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency),
[GetTickCount](https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount),
and [GetTickCount64](https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64).

### Thread handles and virtual memory

The thread object model exposes one guest thread with a stable synthetic ID.
`OpenThread` issues rights-checked handles to that thread, and `CloseHandle`
invalidates real handles. A thread pseudo handle refers to the current synthetic
thread. `GetThreadId` accepts the pseudo handle and live thread handles with
query rights. The priority APIs store and query the thread's base-priority setting.
Thread creation, inheritance, debugger exceptions, and scheduling remain outside
this model. Within the synthetic process, `DuplicateHandle` can convert the
thread pseudo handle to a real handle or copy a live thread handle. The new
handle can keep or reduce the source's rights. The original and duplicate can
be closed independently. Cross-process duplication, inheritable handles,
process-handle duplication, and closing the source during duplication are
outside this subset. A failed output write leaves the handle table unchanged.

`VirtualAlloc` supports combined reserve and commit for data-only pages.
`VirtualFree` supports `MEM_RELEASE` with the exact allocation base and a
zero size. The guest memory map tracks allocation ownership and bounds live
virtual allocations to 64 MiB. Decommit, executable pages, and console-specific
allocation lifecycle remain unsupported.

`xmem.dll!XMemAlloc` uses the same bounded backing store for its narrow
data-only allocation subset, while `XMemFree` releases only the exact base of
a live XMem-owned allocation. XMem and VirtualAlloc ownership are distinct in
the memory map, so one API cannot release the other's allocation. Because the
public free routine returns void, a null, interior, foreign or already-freed
address stops with Xenora's explicit runtime-limit fault instead of inventing
an error channel or silently accepting ownership corruption. Allocator IDs,
graphics memory types, page-size selection, alignment attributes and physical
Xbox memory behavior remain unsupported; attribute bits are currently not
interpreted.

References include Microsoft's public
[XMemAlloc](https://docs.xbox.com/reference/system/xmem/functions/xmemalloc_routine)
and [XMemFree](https://docs.xbox.com/reference/system/xmem/functions/xmemfree_routine)
routine signatures. The behavior above is Xenora's bounded ownership model,
not GDK or Xbox-hardware comparison evidence.

References include Microsoft's
[thread handle](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread),
[thread ID](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadid),
[thread priority](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority),
[handle duplication](https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-duplicatehandle),
[handle close](https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle),
[virtual allocation](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc),
[virtual release](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualfree),
[virtual protection](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect),
and [virtual query](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualquery) contracts.

### Virtual-memory query and protection

`VirtualQuery` reports the 48-byte x64 `MEMORY_BASIC_INFORMATION` layout for
a committed region of Xenora's guest memory. The answer uses the region's
current permissions, `MEM_COMMIT` state, private/image type inference and the
allocation base Xenora actually tracks. A hole, including an uncommitted hole
inside a retained module image span, fails with `ERROR_INVALID_ADDRESS` rather
than inventing reserve or free-state bookkeeping the memory model does not
record. A short output buffer receives only the requested prefix and the
return value is the number of bytes copied.

`VirtualProtect` supports the non-executable base protections Xenora already
models: `PAGE_NOACCESS`, `PAGE_READONLY` and `PAGE_READWRITE`. The affected
range is rounded to whole pages as documented, including a two-byte range
straddling a page boundary. Complete committed coverage and one allocation
ownership domain are validated before mutation; an invalid range leaves all
pages and the old-protection output unchanged. The old protection of the first
page is written before the change, so the output variable may itself lie in a
range being made inaccessible. Split regions preserve the original allocation
identity, keeping adjacent independent allocations distinct.

Executable protection values, guard pages and mapped-file access modes remain
unsupported because translated-code invalidation and those ownership models
are outside the current slice. Heap, thread and Xmem-owned allocations are
likewise refused rather than confused with `VirtualAlloc` ownership. The
registrations remain partial; no Windows comparison, independent acceptance
or game execution is claimed.

### Structured exceptions and CPU faults

`__C_specific_handler` (`ucrtbase.dll`, and the CRT private API set) is the
language handler of MSVC-style C structured exception handling (`__try`,
`__except`, `__finally`) and of the mingw-w64 C runtime's startup frames
(#453). It reads the function's scope table, calls `__except` filters in the
search phase and `__finally` termination handlers in the unwind phase as
guest code, and starts the unwind to an accepting `__except` body with the
exception code in EAX. The scope-table layout is derived from compiled
programs, not from a public specification; `docs/research/exception-handling.md`
records it.

A fault raised by a guest instruction becomes an exception the guest can
catch when the process has an exception directory:

| CPU fault (`ExitReason`) | Exception |
| --- | --- |
| `DivideError` | `STATUS_INTEGER_DIVIDE_BY_ZERO` (`0xC0000094`), also for a quotient overflow |
| `MemoryFault` with an address | `STATUS_ACCESS_VIOLATION` (`0xC0000005`), parameters 0 read / 1 write / 8 instruction fetch, then the address |
| `IllegalInstruction` at UD2 | `STATUS_ILLEGAL_INSTRUCTION` (`0xC000001D`) |

Every other fault still stops the guest: `GeneralProtection`, `SimdException`,
`IllegalInstruction` at any other opcode (it may be a valid instruction Xenora
does not implement) including the runtime-limit marker `0xFE`, faults inside
host services, and faults whose stack has no room for the dispatcher.

When a search for a fault or a raised exception reaches the end of the stack
with no frame accepting it, the filter stored by `SetUnhandledExceptionFilter`
is called as guest code with an `EXCEPTION_POINTERS` (#476). Its result
`EXCEPTION_CONTINUE_EXECUTION` (-1) continues from the exception context,
with any change the filter made to it; `EXCEPTION_CONTINUE_SEARCH` (0) and
`EXCEPTION_EXECUTE_HANDLER` (1) take the default action, as does an exception
with no filter set. Xenora's default action, a policy since the pages read
give no exit status, is `ExitReason::ProcessExit(code)` with the exception
code as the status and the registers of the raise or fault. Any other filter
result, continuing a noncontinuable exception, an exit unwind (`RtlUnwindEx`
with a NULL target frame) and the `ExceptionNestedException` and
`ExceptionCollidedUnwind` dispositions stop the guest with
`ExitReason::InvalidUnwind`. Nothing here was compared with Windows or with an
Xbox console.

### CRT strings and byte memory

The standard registry provides `strlen` and `strnlen` under UCRT and the CRT
string API set. They count bytes using checked guest memory. The scan stops at
a null byte or the requested bound for `strnlen`. A scan that would continue
past 1 MiB reports an unsupported-service fault. See the
[Microsoft CRT string-length contract](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s).

The same modules expose `strcmp` and `strncmp`. These compare unsigned bytes
and stop at the first difference, null byte, or supplied comparison bound.
They share the 1 MiB scan budget. `wcslen`, `wcsnlen`, `wcscmp`, and
`wcsncmp` apply the same rules to unsigned 16-bit Windows code units.
Counts and bounds for the wide variants are in code units.

The same modules expose `memset`, `memcpy`, `memmove`, and `memcmp` for spans
up to 1 MiB. Each nonempty span must be fully mapped with the required permissions.
A span may cross adjacent guest regions. Writes validate the full destination before changing
bytes, and moves preserve the original source bytes when ranges overlap.


The registry also provides the small CRT utilities of the survey under UCRT,
the CRT string, convert and environment API sets and - for the copying forms
and `strrchr` - the private API set mingw imports them through: `strcpy`,
`strncpy`, `strcat` and `strncat` copy and concatenate with the documented
zero padding and termination of the bounded forms. `strrchr` scans to the
terminator included. `_strdup` copies into process-heap memory the caller
owns. `_strlwr`, `_strupr` and `_strrev` convert or reverse in place with
the ASCII semantics of the C locale, as do the collation forms `strcoll`
(byte-wise) and `strxfrm` (the identity copy with the documented length
answer). `memcpy_s` and `memmove_s` enforce the Annex K constraints: a null
pointer is invalid, a count over the destination size zeroes the destination
and answers ERANGE, and `memcpy_s` also rejects overlapping ranges. The
integer formatting family `_itoa`, `_ltoa`, `_i64toa`, `_ultoa`, `_ui64toa`
and `_itoa_s` formats radix 2 through 36 with lowercase digits; negative
numbers in radix ten carry a minus sign, in every other radix the value is
its unsigned width. The `_s` form answers EINVAL when the buffer cannot hold
the digits. `getenv_s` answers the documented empty over the empty
environment: length zero, no error. All of this is implemented behaviour
verified through the unit tests and the hosted `crt_crtutils` fixture.
Nothing here was compared with Windows or with an Xbox console.

### Program arguments and environment

A hosted C program's startup code gets `argc`, `argv` and `envp` for `main`
from five C runtime services. A host supplies the arguments with
`ServicesState::set_program_arguments(&["program", "first", ...])`, program
name first, before it runs the guest.

| Service | Behaviour |
| --- | --- |
| `__p___argc()`, `__p___argv()`, `__p__environ()` | The address of the guest variable `__argc`, `__argv` or `_environ`. All three start as zero or null |
| `_configure_narrow_argv(mode)` | For mode 1 or 2, sets `__argc` to the number of arguments and `__argv` to a table of pointers to their NUL-terminated strings, with a null pointer after the last, and returns 0. It builds the table once; later calls return 0 and change nothing. Mode 0 returns 0 and builds nothing. Any other mode returns `EINVAL` |
| `_initialize_narrow_environment()` | Points `_environ` at a table holding one null pointer, once, and returns 0 |

`set_program_arguments` refuses an argument containing a NUL byte, arguments
whose bytes and terminators exceed 32,767 (`MAX_PROGRAM_ARGUMENT_BYTES`, the
documented Windows command-line limit), and a call after the guest has built
its table or read its command line. A host that never calls it gives the program one argument, the
empty string, which is what ISO C specifies when no program name is
available. An empty list gives it none.

What is documented, inferred and chosen:

- **Documented:** the three global variables and what they hold, and ISO C's
  rules for `argv` (a null pointer after the last argument, strings the
  program may modify).
- **Inferred:** that each `__p_` function returns the address of its
  variable, as the documented `__p__fmode` does. Microsoft lists these five
  functions only by name.
- **Xenora's choice:** what the two initialization functions do. Arguments
  reach the guest as the bytes of the host's strings, with no code page.
  Mode 2 asks for wildcard expansion and none is performed. The environment
  is empty. The variables and tables are blocks from the process heap.

The wide-character counterparts and environment variables do not exist.
`GetCommandLineA` and `GetCommandLineW` are in the next section. All five services are `partial`. None of
this has been compared with Windows.

### Startup information and command line

`GetStartupInfoA` and `GetStartupInfoW` return the `STARTUPINFO` structure the
process was started with. The host takes the place of the creating process and
passes it with `ServicesState::set_startup_info` before the guest runs; once the
guest has read it, a change is refused. Strings with a NUL, strings of 32,767
UTF-16 units or more, undocumented flags, flags documented as not combinable and
`SW_SHOWDEFAULT` as the initial show state are refused. Without host input there
are no flags and no strings. `cb` is 104, and the reserved members are zero. The
desktop and title pointers stay the same for the life of the process. The
functions document no failure, so a structure that cannot be written stops the
guest. Nothing acts on the information: there are no windows, consoles or
standard handles, and handle values reach the guest as the host gave them.

`GetCommandLineA` and `GetCommandLineW` return one string each, at a fixed
address. It is built from the program arguments on first use, and the arguments
cannot change after that. Arguments are quoted so that the rules in Microsoft's
"Parsing C command-line arguments" give them back. The program name takes no
escapes there, so a quote in it is left out. No arguments give an empty string.
The process code page is UTF-8, which is Xenora's choice, so the narrow strings
are UTF-8.

Both resolve through `kernel32.dll` and the API sets Microsoft's pages list.
Those pages list one set of locations for a function and its A and W names
together, so both names resolve in each.
`crates/loader/tests/startup_info.rs` runs original C and C++ programs through
them. Nothing was compared with Windows.

The UCRT and `api-ms-win-crt-runtime-l1-1-0.dll` provide
`_get_narrow_winmain_command_line` and `_get_wide_winmain_command_line`.
Each returns a pointer into the corresponding `GetCommandLineA` or
`GetCommandLineW` allocation after the executable name and its separator.
The tails preserve the serialized quoting and the original UTF-8 bytes or
UTF-16 code units. The pointer addresses the terminating NUL when there
are no arguments. The helpers have partial status for the synthetic
startup environment.

### XInput controller state

`XInputGetState` resolves through the legacy DirectX redistributable
`xinput1_3.dll` name as well as `xinput1_4.dll`, `xinput9_1_0.dll` and
`xinputuap.dll`. Undocumented ordinal 100 (`XInputGetStateEx` in public
reverse-engineering literature) resolves only on `xinput1_3.dll` and
`xinput1_4.dll`; it uses the same evidenced 16-byte output layout but preserves
the guide-button bit `0x0400`, while named `XInputGetState` masks that bit.
This ordinal behavior is compatibility evidence from public reverse-engineering
reports, not a Microsoft-documented contract or Xbox-hardware observation. The public structure layout is 16 bytes: a 32-bit packet
number followed by the packed 12-byte gamepad state. A host may install one explicit snapshot per slot through
`ServicesState::set_xinput_controller`. The runtime applies no deadzones and
stores the documented units directly: the XInput button bitmask, triggers from
0 through 255 and signed thumb axes from -32768 through 32767. A connected
snapshot returns `ERROR_SUCCESS` and writes the exact 16-byte layout: packet
number, buttons, triggers, then left X/Y and right X/Y in little-endian order.
The packet number starts at one for a newly connected snapshot and increments
only when a supplied snapshot changes or a disconnected slot reconnects.
Supplying the same snapshot repeatedly leaves it unchanged. Disconnecting a
slot makes later calls return `ERROR_DEVICE_NOT_CONNECTED` without mutating
output. Slots start disconnected, so the honest default is that error.

Indexes outside zero through three return `ERROR_BAD_ARGUMENTS`. Null,
unwritable or truncated output ranges also return `ERROR_BAD_ARGUMENTS` before
any mutation; Microsoft does not document that pointer-validation case, so
this is Xenora's memory-safety boundary rather than Windows comparison
evidence.

The native application interface carries one explicit host snapshot through
`xenora_session_send_xinput_state`: a 16-byte wire structure with public XInput
button bits, triggers already scaled to 0 through 255, both thumbstick axes, a
connected flag constrained to 0 or 1, a feature byte and two zeroed reserved
bytes. Bit zero of the feature byte is host-reported vibration support; all
other feature bits must be zero. The interface
accepts user slots zero through three and validates session state, null
pointers, indexes, the connected flag and reserved bytes. The frame-loop
session owns its `ServicesState`, so a snapshot accepted there is what a guest
later reads through `XInputGetState`. The legacy fixture input structure stays
separate: it is not reinterpreted as XInput and its mouse fields are not
overloaded as stick axes.

The macOS app's existing GameController polling maps extended and micro
gamepads into those XInput units. Menu and options map to start and back where
available; the documented face, shoulder, thumbstick-button and directional-pad
bits map directly; an extended gamepad's home button maps to the ordinal-100
guide bit even though named `XInputGetState` masks it. Thumbsticks are scaled
without applying the legacy fixture deadzone, with -1 reaching -32768 and +1 reaching 32767. Triggers scale to 0
through 255.

The app discovers up to four playable GameController devices for the XInput
bridge. Discovery orders extended gamepads before micro gamepads, preferring
the current controller within each class and otherwise following the order
returned by GameController. The frame loop then keeps session-local slot
assignments by controller object identity: an assigned controller keeps its
slot while it remains present, a disconnected controller vacates its slot, and
a newly discovered controller uses the lowest empty slot. This stable
session-local policy is Xenora host behavior, not Windows or Xbox assignment
evidence.
Slot zero remains the primary controller for the legacy fixture input, the
on-screen virtual input and vibration output. If slot zero is empty, the
lowest occupied slot supplies legacy input, but vibration remains tied to the
controller actually assigned to slot zero. The on-screen directional control
can act as a virtual host input on slot zero and replace only the horizontal
directional bits, mirroring the legacy fixture control. No physical
multiplayer hardware verification has been performed.

`XInputSetState` accepts the exact four-byte public vibration layout for a
connected virtual slot and records the latest motor command with a sequence
number. Disconnected slots, invalid indexes and invalid input memory fail
before mutation. Disconnecting a slot clears the motors and sequence. The
native interface exposes the latest command through
`xenora_session_poll_xinput_vibration`: a 12-byte structure containing the
sequence, left and right motor speeds, a connected byte, an enabled byte and
two zeroed reserved bytes. Polling is non-consuming. A disconnected slot succeeds with a zeroed
command so the host can stop output; invalid indexes, null output, invalid
sessions and sessions without a running loop are rejected before writing.

The macOS frame-loop fixture polls each XInput slot that has an assigned
physical controller, plus a previously connected slot once after removal so its
actuator can stop. Changed sequences for each slot pass to an independent
GameController/Core Haptics output sink. When the selected controller exposes
left- and right-handle localities, the XInput left and right motor speeds map
to continuous haptic intensity on those respective actuators. When it does
not, Xenora uses the guaranteed default locality once with the stronger motor
intensity; this is an explicit approximation, not independent motor emulation.
Motor speed maps to intensity only. Xenora does not claim the XInput low- and
high-frequency motor characters, trigger actuators, exact force response or a
hardware-verified effect. Engine or player failures are surfaced in the app;
commands are best-effort host output evidence only. When the host input
snapshot reports vibration support, the runtime advertises the force-feedback
capability bit and 16-bit motor resolution for that slot. That is host
capability metadata and best-effort output plumbing, not evidence that a
physical pulse was observed. Without that host bit, motor resolutions remain
zero.

`XInputEnable` is available on `xinput1_3.dll`, `xinput1_4.dll` and
`xinputuap.dll`, matching the public export sets, and is absent from reduced `xinput9_1_0.dll`. It tracks
one global reporting state, initially enabled. While disabled,
`XInputGetState` still reports connected slots but returns neutral gamepad
data. Public documentation does not define the packet number in this mode;
Xenora explicitly chooses zero because the visible neutral state is constant,
and this is not Windows comparison evidence. `XInputSetState` commands remain
registered and sequence-numbered while disabled, but the FFI vibration poll
reports `enabled = 0`, so host actuators must stop. When reporting is
re-enabled, the same stored command is exposed with `enabled = 1`, implementing
the documented replay of the latest vibration request. The macOS frame-loop
fixture applies that enabled bit through its haptic sink. This is only the
guest API state machine; the app does not yet integrate physical window-focus
policy with it.

`XInputGetKeystroke` is available on `xinput1_3.dll`, `xinput1_4.dll` and
`xinputuap.dll`, matching the public export sets; it is deliberately absent from the reduced
`xinput9_1_0.dll` surface. The implementation validates indexes zero through
three or `XUSER_INDEX_ANY`, requires the reserved parameter to be zero and
checks the full eight-byte output range before looking at device state. A
specific disconnected slot, or `XUSER_INDEX_ANY` with no connected slots,
returns `ERROR_DEVICE_NOT_CONNECTED`. Connected slots currently return the
documented `ERROR_EMPTY` result because Xenora has no host keystroke-event
source yet. No key press, repeat, release, Unicode value or HID code is
fabricated and the output buffer is not mutated for an empty result.

`XInputGetBatteryInformation` is available on `xinput1_3.dll`,
`xinput1_4.dll` and `xinputuap.dll`, matching the public export metadata, and is absent from
reduced `xinput9_1_0.dll`. It validates the two-byte output range and accepts
only the documented gamepad/headset device-type values. A disconnected slot or
the unsupported headset reports `BATTERY_TYPE_DISCONNECTED` with empty level.
A connected gamepad always reports `BATTERY_TYPE_UNKNOWN`: Apple
GameController exposes charge state and an approximate fraction but no battery
chemistry or wired/wireless XInput class, so Xenora must not invent
`ALKALINE`, `NIMH` or `WIRED`. Public XInput documentation says the level is
meaningful only for wireless devices with a known battery type. Xenora makes
an explicit compatibility policy rather than claiming Windows behavior: when
the host supplies a real percentage, it is published beside the unknown type
using Xenora's coarse quantization (`0...10` empty, `11...40` low, `41...70`
medium and `71...100` full). A missing battery object or an object with no
trustworthy level leaves the level empty, where empty means no valid evidence
rather than a measured drained pack. Charging/discharging/full evidence is
transported through the additive host FFI and retained internally; it is not
misrepresented as XInput chemistry.

`XInputGetAudioDeviceIds` is available only on `xinput1_4.dll` and
`xinputuap.dll`; it is absent from `xinput1_3.dll` and reduced
`xinput9_1_0.dll`. The implementation extracts the fifth Win64 argument from
the guest stack, validates the slot and every supplied count pointer before
mutation, and treats a supplied nonzero count as requiring a writable buffer
of at least one wide character. Public documentation does not define those
malformed-pointer cases, so they are Xenora's memory-safety boundary rather
than Windows comparison evidence. A connected virtual controller succeeds with
zero counts and empty strings where capacity exists because Xenora exposes no
headset endpoint. A disconnected slot returns `ERROR_DEVICE_NOT_CONNECTED`.
Omitted optional count pointers leave the corresponding buffers untouched. No
WASAPI endpoint identifier is invented and no audio render/capture path is
implemented.

`XInputGetDSoundAudioDeviceGuids` is available only on the legacy
`xinput1_3.dll` and `xinput9_1_0.dll` surfaces, matching public documentation;
it is absent from `xinput1_4.dll` and `xinputuap.dll`. Both GUID output ranges
are validated before mutation. A connected virtual controller succeeds with
two `GUID_NULL` values because Xenora exposes no headset endpoint, while a
disconnected slot returns `ERROR_DEVICE_NOT_CONNECTED`. This is only the
legacy identifier boundary: no DirectSound device, audio render path, capture
path or headset is implemented. The ordinal-only xinput1_3 exports remain
unsupported because their public contracts are undocumented.

`XInputGetCapabilities` is available on the same four library names for a
connected virtual slot. It accepts flags zero or `XINPUT_FLAG_GAMEPAD` and
writes the exact 20-byte public structure. Xenora reports the virtual surface
as `XINPUT_DEVTYPE_GAMEPAD`/`XINPUT_DEVSUBTYPE_GAMEPAD`, every standard input
button bit, trigger resolution 255 and thumbstick resolution 32767. Motor
resolution and the force-feedback feature flag reflect only host-reported
haptic support as described above; the runtime does not pretend that wireless,
voice, plug-in module or physical force-feedback properties are known.
Disconnected slots return `ERROR_DEVICE_NOT_CONNECTED`, and invalid slots,
flags or output ranges return `ERROR_BAD_ARGUMENTS` before mutation.

Hardware-verified vibration output, keystroke event capture,
hardware-verified physical battery behavior, actual headset/audio endpoints and audio render/capture,
physical-controller hotplug policy beyond the app's existing
polling, ordinal 101/102/103 guide-wait/poweroff functions,
arbitrary game execution and real-game compatibility remain unsupported. This chain proves conversion and delivery
into runtime services; it does not prove physical Xbox controller behavior and
was not compared with Windows or Xbox hardware.

### Host input router

Each native application session owns one host input router, from the `xenora-input` crate (Campaign F, [#942](https://github.com/ranveersoni98/Xenora/issues/942)). The router is described in [the input campaign document](coordination/input-campaign.md). The app feeds it through the `xenora_session_input_*` functions:

- physical macOS key codes, up to `0x7F`, as presses and releases;
- relative mouse deltas and mouse buttons;
- focus changes;
- controller connections, each with a family number;
- optional profile text for a controller;
- raw GameController values (`xenora_controller_raw`): positional element bits, sticks from -1 to 1, triggers from 0 to 1, a vibration feature bit, and zeroed reserved bytes. These can come with battery evidence in the existing `xenora_xinput_battery` form.

`xenora_controller_recognize` turns a GameController product category and the presence of paddle and Share buttons into a family number. It uses the crate's exact-match rule, so the app does not carry its own copy of that rule.

`xenora_session_input_snapshot` writes the router's four slots in the `xenora_xinput_state` form without touching the guest, so a settings or test screen reads the same router that guest execution uses. `xenora_session_input_publish` installs those four slots into the running frame loop's XInput slots through the existing snapshot-and-battery path. Without a running loop it returns `XENORA_INVALID_STATE`.

Every argument is validated before any state changes. Unknown devices, out-of-range modes, families, key codes and buttons, non-finite deltas, malformed raw structures, malformed batteries and malformed profile text return `XENORA_INVALID_ARGUMENT`. A fifth controller returns `XENORA_LIMIT_EXCEEDED`.

A slot reports the vibration bit and battery evidence only in automatic and physical-only modes, and only when a controller owns that slot. A merged or keyboard-only slot reports neither. This is Xenora host policy.

The router is not yet used by the app's frame loop. That comes with the app wiring.

### Guest heaps

`GetProcessHeap`, `HeapAlloc`, `HeapSize`, and `HeapFree` expose the
default synthetic heap. Allocations are at least 16-byte aligned and zero initialized.
A zero-size request allocates one byte. All heaps in an address space share a 64 MiB budget and a limit of
4096 live allocations. Heap and virtual allocations have distinct ownership.
`HeapReAlloc` preserves the retained bytes and zeroes newly added bytes.
It can move a block unless `HEAP_REALLOC_IN_PLACE_ONLY` is set. Failed
resizes preserve the original block. `HeapCreate` supports up to 256 growable private heaps with default flags.
The initial size is checked against the budget and backing is allocated on
demand. `HeapDestroy` frees all blocks owned by that private heap and
invalidates its handle. The default heap cannot be destroyed. See the [Windows heap API reference](https://learn.microsoft.com/windows/win32/api/heapapi/).

UCRT and the CRT heap API set expose `malloc`, `calloc`, `realloc`, and
`free` on the bounded default guest heap. `calloc` checks for size overflow.
`realloc(NULL, size)` allocates a new block, and resizing a nonnull block to
zero frees it. Allocation failures return null and preserve existing blocks.
Allocation failures also set the synthetic main thread's CRT `errno` to
`ENOMEM`. The runtime API set and UCRT expose `_errno`, `_get_errno`, and
`_set_errno` through a stable guest memory slot. Additional guest threads
and CRT parameter or new-handler callbacks remain unsupported. See
[Microsoft CRT allocation documentation](https://learn.microsoft.com/cpp/c-runtime-library/memory-allocation).

### Standard output and formatted printing

A hosted C program prints through the C runtime. Six services give it the
standard streams, and what it writes to `stdout` and to `stderr` is captured
where a host or a test can read it: `ServicesState::standard_output()` and
`ServicesState::standard_error()`.

| Service | Behaviour |
| --- | --- |
| `__acrt_iob_func(index)` | The `FILE` object of `stdin` (0), `stdout` (1) or `stderr` (2) |
| `__stdio_common_vfprintf(options, stream, format, locale, arguments)` | Formats with the arguments in the guest's `va_list`, writes to `stdout` or `stderr`, and returns the number of characters written. This is what `printf` and `fprintf` call |
| `fwrite(buffer, size, count, stream)` | Writes `size * count` bytes and returns `count` |
| `fputs(string, stream)` | Writes the string without its terminator and returns 0 |
| `fflush(stream)` | Returns 0. A null stream means every stream |
| `setvbuf(stream, buffer, mode, size)` | Checks the mode and size and returns 0 |

The standard streams are text-mode streams, so each line feed a program
writes is captured as a carriage return and a line feed, as the Windows
documentation of text mode describes. Function results count the characters
before that replacement. Output is never held back: `fflush` has nothing to
do and `setvbuf` only validates. Each captured stream keeps at most 16 MiB
(`MAX_CAPTURED_OUTPUT`).

The formatting engine (`crates/loader/src/services/crt_format.rs`) follows
Microsoft's "Format specification syntax: printf and wprintf functions" and
ISO C:

- Flags `-`, `+`, blank, `#` and `0`; a width and a precision as digits or
  `*`; size prefixes `hh`, `h`, `l`, `ll`, `j`, `z`, `t`, `I`, `I32`, `I64`.
- Types `d`, `i`, `u`, `o`, `x`, `X`, `c`, `s`, `p` and `%%`. An integer
  without a size prefix, and a `long`, is 32 bits. A null string prints
  `(null)`.
- Its output is compared with the host C library's `snprintf` on 2,600
  generated cases whose result ISO C defines
  (`crates/loader/tests/printf/reference.py`).

Documented failures return their documented result and set `errno` to
`EINVAL`: a null stream, format, buffer or string, and an invalid `setvbuf`
mode or size. An invalid format, which includes `%n` because Windows
disables it by default, also returns -1 with `EINVAL` and writes nothing;
on Windows the invalid parameter handler runs first.

The standard input is the bytes the host supplies before the run, read in
full by `xenora run` up to 1 MiB; more is a command-line error before
anything executes, never a silent truncation. A terminal, or fd 0 already
serving the diagnostic channel, means no input. Text mode applies when the
input is stored: a CR LF pair becomes one line feed, a CR alone stays. The
end-of-file indicator follows ISO C: a read that meets the end sets it, so
a last line without a newline sets it while one that ends at a line feed
does not. `scanf` is not provided. Wide input and output in the C locale are in the wide stream io section below.

Everything else that is not modelled stops the guest with the runtime-limit
fault and writes nothing, so that nothing is printed wrongly: the
floating-point types (`e`, `f`, `g`, `a`), wide characters and strings (`C`,
`S`, `lc`, `ls`), a locale object, option bits other than the three that do
not affect these conversions, a pointer that is no stream, writing `stdin`,
an index above 2, more than 1 MiB in one call, and output past the 16 MiB
bound.

Choices where the documentation leaves room, each marked in the source:
`%p` prints sixteen upper-case hexadecimal digits; `0` pads a character and
a string as it pads a number; a precision also limits `(null)`; `%#.0o` of
zero prints `0`, which is ISO C's rule. All six services are `partial`. None
of this has been compared with Windows.

### Wide stream io in the C runtime

`fputws`, `fgetws`, `fputwc`, `putwchar` and `getwchar` read and write wide
characters in the C locale: every byte is the wide character of the same
value, and a wide character above 255 cannot convert, so the write fails with
`WEOF` and `EILSEQ`. Streams carry the C orientation: the first io operation
on a stream fixes it byte or wide, and the other kind then fails — byte io on
a wide-oriented stream answers `EOF` or `WEOF`, wide io on a byte-oriented
one answers `WEOF` or null. This holds for the files and for the three
standard streams alike; mixing `printf` and `putwchar` on stdout is a
conflict, as it is in the CRT. The text-mode translations are the byte
streams' own. All five services are `partial`: there is one locale, the C
locale, and no multi-byte encoding. None of this has been compared with
Windows.

### Wide buffer formatting in the C runtime

`__stdio_common_vswprintf` formats into wide buffers: the syntax and the
conversions are the narrow engine's, with the wide family's turned-around
character and string types — `%c` and `%s` are wide, `%C` and `%S` narrow,
`h` forces narrow and `l` wide. Everything is counted in wide units. The
default behavior is the CRT's legacy one, measured against a mingw-w64
binary: truncation writes the count characters without a terminator and
answers -1, a null buffer answers -1 with `EINVAL` — there is no size query.
A program that sets the standard-snprintf option bit gets the standard rules
instead, as the narrow buffer forms implement them. The service is `partial`:
the wide printf forms for streams (`wprintf`, `fwprintf`) do not exist yet.
None of this has been compared with Windows.

### Files through the C runtime

`fopen`, `fclose` and `fgets` give a hosted C program files, and the output
services above (`__stdio_common_vfprintf`, `fwrite`, `fputs`, `fflush`,
`setvbuf`) accept a stream `fopen` returned as well as `stdout` and `stderr`.
The files are the ones on the in-memory `C:` drive described under
"Synthetic guest files": a file written through a C stream is the file
`ReadFile` reads, and the reverse.

| Service | Behaviour |
| --- | --- |
| `fopen(name, mode)` | Opens a file and returns its `FILE*`, or null with `errno` set. `r` needs the file to exist; `w` creates it or destroys its contents; `a` creates it and makes every write go to its end; `+` adds the other direction; `b` or `t` selects binary or text |
| `fclose(stream)` | Closes the stream and returns 0; `EOF` with `EINVAL` for a null stream |
| `fgets(buffer, count, stream)` | Reads up to `count - 1` characters, stopping after a newline, which it keeps, and adds a terminator. Returns the buffer, or null at end of file or on an error |
| `perror(message)` | Writes the message, `: `, the text for `errno` and a newline to `stderr`; only the text when the message is null or empty |

A stream is in text mode unless its mode has `b`: a line feed is stored as a
carriage return and a line feed, the pair is read back as a line feed, and
`CTRL+Z` ends the input. Names are ASCII, with either slash, in any case,
with or without `C:\`, as the drive accepts them.

`errno` after a failed `fopen`: `EINVAL` for a null or empty name or mode, a
mode this runtime does not open, and a name the drive rejects; `ENOENT` when
the file or its directory does not exist; `EACCES` for a directory; `EMFILE`
when 64 streams are already open; `ENOSPC` when the drive holds its 256
files; `ENOMEM` when the `FILE` object cannot be allocated. Output to a
stream that was not opened for writing, and reading one not opened for
reading, fail with `EBADF`; output the drive has no room for fails with
`ENOSPC`. A failed write writes nothing.

What is not provided, and what is Xenora's choice:

- **Not provided:** the mode characters `x`, `c`, `n`, `N`, `S`, `R`, `T`,
  `D` and `ccs=`, which are refused; `fread`, `fseek`, `ftell`, `rewind`,
  `ferror`, `fscanf`, and closing a standard stream, which stop the
  guest.
- **No buffering.** A write reaches the drive at once, so the rule that a
  `+` stream needs `fflush` or a seek between writing and reading does not
  apply.
- **No sharing.** A C stream is not a Win32 handle. It does not stop
  `DeleteFileW` or `MoveFileW`, and ignores a handle's sharing mode. After
  its file is deleted a stream's reads and writes fail with `EBADF`.
- **Choices:** the `errno` values above other than `EINVAL` for a null or
  empty argument, which is documented; an `a+` stream reads from the start;
  every `perror` text except "No such file or directory", which is the one
  Microsoft's page shows.

All four services are `partial`. None of this has been compared with
Windows.

**Positions and file operations (#493).** `_ftelli64`, `_fseeki64`,
`fgetpos` and `fsetpos` work on a stream `fopen` returned. A position is the
byte offset in the file on the drive, in text mode too, where each line feed
written is two bytes; `fpos_t` is the Universal CRT's `__int64`. `_fseeki64`
takes `SEEK_SET`, `SEEK_CUR` and `SEEK_END`; a position before the start, an
unknown origin and a null argument fail with -1 and `EINVAL`, and the
position is unchanged. A position past the end is allowed, and a write there
fills the gap with zero bytes. A text-mode seek to any offset is allowed,
where Microsoft guarantees only offsets `ftell` returned. Positions of the
standard streams are not modelled and stop the guest. `remove` deletes a
file: `ENOENT` when it is missing or the name is rejected, `EACCES` for a
directory. `rename` moves a file's bytes to a new name: `ENOENT` when the old
name holds nothing, `EACCES` when the new name exists or its directory does
not, `EINVAL` for a null or rejected name; renaming a directory is not
modelled and stops the guest. Neither is stopped by an open stream, whose
later operations fail with `EBADF`. `fseek`, `ftell` and `rewind` remain
unprovided here; #312 holds them. `remove` is `implemented`, the other five
`partial`.

**Temporary files (#493, last part).** `tmpfile` opens a stream for
reading and writing in binary on a file no other stream uses; closing the
stream deletes the file, as the Microsoft page says. `tmpnam` writes a
name no file on the drive holds, `tmp` and a decimal counter, into the
caller's buffer, or into a static buffer allocated once when the argument
is null, as the CRT keeps one. The counter never rewinds, so a name a
closed temporary file freed can come back — the page documents the same
for its names. Both are `implemented`. `freopen` is not served: its close
semantics on failure are unspecified beyond what the drive model can
answer honestly, and no fixture demanded it.

**The descriptor layer (#493, third part).** `_open`, `_read`, `_write`,
`_lseek`, `_close`, `_fileno`, `_isatty`, `_access` and `_unlink` serve the
POSIX-shaped half of the CRT. A descriptor is either a file `_open` made,
with its own state, or one `_fileno` gave out for a stream, in which case
it shares the stream's state as the CRT does: a write through the
descriptor moves where `fgets` reads, and closing it closes the underlying
file, leaving the stream dangling — undefined behaviour in C, a guest stop
here. The standard descriptors are 0, 1 and 2: `_read` consumes what the
host supplied, `_write` appends to the captured output, and neither can be
sought. Descriptors are the lowest free number, at most 8192: a standard
number the guest closed is free exactly as the CRT models, so the
close-then-open redirection idiom lands the open on the number just freed,
while an undisturbed one stays the standard stream's own. Text
mode translates CR LF both ways as the streams do. `_O_TEMPORARY` deletes
the file when the descriptor closes; the wide text modes are not modelled
and stop the guest; the hint bits change nothing. `_lseek` positions are
32-bit `long`s: a position no `long` holds is `EINVAL`. `_isatty` is always
0, as nothing here is a character device. `_access` treats the drive's
files as readable and writable, so only existence decides. `_unlink` is
`remove` by another name. All nine services are `implemented` except
`_open`, which is `partial` for the wide modes.

**The secure open and the stream indicators (#493, second part).**
`fopen_s` is `fopen` through a pointer: the error number is the result and
`errno` at once, and the pointer holds null whenever the call does not
succeed, as Microsoft's page says. A null or empty argument is `EINVAL`,
and the invalid parameter handler is not modelled. A file stream keeps the
end-of-file indicator ISO C defines: a read that meets the end (or the
CTRL+Z of a text stream) sets it, and `feof` reports it for file streams as
it already did for the standard input. `clearerr` clears the end-of-file
and error indicators. Nothing raises the error indicator yet, as a failed
read or write reports its `errno` at the call. `clearerr` is `implemented`;
`fopen_s` is `partial` for the unmodelled handler.

**The C time services (#459, package 5).** `_gmtime64`/`gmtime`,
`_localtime64`/`localtime`, `_mktime64`/`mktime`, `asctime`, `_ctime64`/
`ctime`, `asctime_s`, `_ctime64_s`/`ctime_s`, `clock`, `_difftime64`/
`difftime` and `strftime` come in through `api-ms-win-crt-time-l1-1-0.dll`.
The calendar arithmetic is exact (Hinnant's public-domain civil
conversions). The machine's clock is UTC throughout: Xenora has no answer
for what zone it stands in, so local time is UTC, `tm_isdst` is 0, and
`mktime` composes what `gmtime` breaks down. The CRT's shared static
buffers are reproduced: one `struct tm` for `gmtime`/`localtime`, one
string for `asctime`/`ctime`. `clock` reads the injected clock's
performance count in milliseconds. `strftime` covers the documented C
locale conversions and copies unknown ones verbatim. Times before 1970 or
after 3000 are `EINVAL`, as the Microsoft pages say. All `implemented`.
`FileTimeToLocalFileTime` is the identity under the UTC clock (`partial`).
`GetDateFormatW` and `GetTimeFormatW` belong to the locale package and are
not served.

**The wide conversions and classification (#459, package 6, first
part).** `mbtowc`/`wctomb`/`mblen`/`mbstowcs`/`wcstombs`/`mbsrtowcs`/
`wcsrtombs` through `api-ms-win-crt-convert-l1-1-0.dll`, and `iswctype`,
`iswalpha` and its siblings, `towlower`/`towupper`, `wcsncat` and
`_wcsdup` through `api-ms-win-crt-string-l1-1-0.dll`. The C locale is the
only one the emulator has, and its multibyte encoding is documented as
the answer: every byte is the wide character of the same value,
zero-extended, and a wide character above 255 fails the conversion with
`EILSEQ`. The restartable forms have no shift state to keep and say so.
They check output capacity before reading the next source unit: exact
capacity leaves the next unit unconsumed, copying the terminator clears the
source pointer, sizing queries make no source progress, and an
unrepresentable wide unit is left as the next input unit. These progress
rules follow [WG14 N2310 section 7.29.6.4](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2310.pdf).
The classification is the ASCII table, through `iswctype`'s bits — the
form mingw-w64 actually imports, as the `isw*` macros inline to it. All
`implemented`. The wide stream operations and the wide printf forms are
the rest of package 6 and are not served yet: they need the stream
orientation machinery, which is their own work.

### CRT integer conversion

UCRT and the CRT conversion API set expose strtol, strtoul, wcstol, and
wcstoul with 32-bit Windows long results. The parser supports C-locale
whitespace, explicit bases 2–36 and automatic base selection, and writes
the first unparsed guest address to a supplied end pointer. Overflow
clamps the result and sets ERANGE. Scans have a 1 MiB input budget. The long-long variants and
Microsoft's _strtoi64, _strtoui64, _wcstoi64, and _wcstoui64 apply the
same rules with 64-bit results.

### The narrow file services

The narrow forms of the directory, move, copy and find services read UTF-8
paths, coherent with the process code page, and share one implementation
and one drive with the wide forms: a file written through one width is the
file read through the other. `CopyFile` onto itself is a sharing violation,
`GetFullPathName` resolves relative names against the synthetic root -
there is no current directory yet - `SetFileAttributes` accepts only the
normal and archive bits because the drive keeps no attribute state, and
`GetTempFileName` answers unique names within a run. Nothing was compared
with Windows.

### The legacy memory services

`GlobalAlloc` and `LocalAlloc` are thin wrappers over the process heap, as
on every 32- or 64-bit Windows: memory is always fixed, the handle is the
pointer itself, and the moveable bit and the discardable hints of the
16-bit memory manager are accepted and inert. Freeing the null handle is
a no-op success; freeing a non-allocation answers the handle itself with
the invalid-handle error. Flags outside the documented mask are an invalid
parameter. Nothing was compared with Windows.

### Error reporting

`FormatMessage` reads the system table for the error codes the synthetic
services produce, in en-US, with the trailing newline real messages carry.
Insert sequences expand string and numeric specifiers; the arguments are
read as a flat array of machine words, so floating point inserts are not
formatted. The allocate form allocates from the process heap and the memory
is released with `LocalFree`, as documented. Unknown identifiers fail with
the missing-message error; module tables do not exist yet and
`FORMAT_MESSAGE_FROM_HMODULE` is refused as unsupported. `SetErrorMode`
stores and exchanges the mode even though no error dialogs exist. Nothing
was compared with Windows.

### The environment block

The environment is empty, so expansion is the identity - the documented
result when no variable is defined. `ExpandEnvironmentStrings` counts the
terminator in both its success return and its required-size answer.
`GetEnvironmentStringsW` hands each caller its own copy of the empty block
from the process heap, because the documentation requires the caller to
free it.

### The simulated machine

`GetVersionEx` reports a Windows 10 era NT workstation, coherent with the
GDK-era programs the runtime hosts; it is simulated, not measured.
`GetWindowsDirectory` and `GetSystemDirectory` answer the synthetic drive's
layout, the computer name is XENORA, and the processor topology is one core
in one package in one group, coherent with the count `GetSystemInfo`
reports. Numa, cache and group relationships are not modeled yet:
enumerating them alone answers zero entries. Nothing was compared with
Windows.

### Cryptography API: Next Generation random generator

The standard `bcrypt.dll` registry supports the user-mode `RNG` algorithm.
`BCryptOpenAlgorithmProvider` accepts the default provider or the exact
`Microsoft Primitive Provider` name. Each guest registry holds up to 64
live provider tokens. Closing a token invalidates it and frees one slot.
Tokens cannot be used in another guest registry or after process exit.

`BCryptGenRandom` accepts an open RNG token, the Windows 10 RNG pseudo-handle,
or a null handle with the system-preferred flag. The Windows 8 and later
entropy-in-buffer flag is accepted and ignored. A request can write up to
65,536 bytes. The runtime validates the complete guest span before reading
host entropy and publishes the bytes only after a successful read. A
zero-length request with a nonnull pointer writes nothing. The three APIs
return an NTSTATUS value and leave the caller's Win32 last error intact.
Provider registration, kernel flags and other algorithms are outside the
supported subset.

### WinHTTP synchronous cleartext subset

`winhttp.dll` has a partial, synchronous object and cleartext HTTP/1.1
transport model. `WinHttpOpen` copies the optional agent string and creates a
session handle. The direct and default access modes are accepted; because the
synthetic machine has no proxy configuration, the default mode currently means
direct access. Named and automatic proxy modes and every nonzero session flag,
including asynchronous operation, fail with `ERROR_NOT_SUPPORTED`. Proxy
strings are not dereferenced in the accepted modes because Microsoft's
documentation makes them inputs to the named-proxy mode.

`WinHttpCrackUrl` splits canonical HTTP and HTTPS URLs without opening a
connection. The Win64 `URL_COMPONENTS` record takes counted or terminated
UTF-16 input up to 32,768 units. An output field can borrow a pointer into
the input or copy a NUL-terminated component into a caller-provided buffer.
The result reports the scheme, port and UTF-16 units written before the
terminator. A zero extra-info length keeps query and fragment text in the
path. An empty view returns a null pointer and zero units. Short, invalid or
overlapping output spans fail before any output changes. The supported flags
are zero and `ICU_REJECT_USERPWD`. Percent escapes remain intact.

`WinHttpCreateUrl` composes a URL from the same record without opening a
connection. A null component pointer omits the component; a zero length reads
a zero-terminated string and a nonzero length counts units exactly, as the
`URL_COMPONENTS` remarks document. A scheme string wins over `nScheme`,
mirroring the precedence the WinINet twin documents; either must resolve to
HTTP or HTTPS because WinHTTP recognizes no other scheme. `ICU_REJECT_USERPWD`
fails credential input with `ERROR_WINHTTP_INVALID_URL`, and `ICU_ESCAPE`
escapes the unsafe set the public URL page lists - control characters, DEL,
space, percent, `"< > # { } | \ ^ ~ [ ] ` '"` - in path and extra info, even
inside an existing escape triplet. The sizing contract follows the documented
example: an insufficient or absent buffer reports the required wide-character
count including the terminator through the length pointer and fails with
`ERROR_INSUFFICIENT_BUFFER` without touching output, while success writes the
count excluding the terminator. Choices the public text leaves silent are
Xenora canonical decisions: scheme text is emitted verbatim, host verbatim, a
port equal to the scheme default or zero is elided so canonical URLs round
trip, a nonempty path without a leading slash gains one, empty components
contribute nothing, a password without a user name is an invalid URL,
non-ASCII characters percent-encode as UTF-8 because Xenora models no system
code page, and unpaired surrogates are invalid URLs. Unknown flags fail with
`ERROR_NOT_SUPPORTED`. No network use occurs in either direction.

`WinHttpConnect` requires a live session handle of the correct type, a
nonempty ASCII host or address string rather than a URL, a zero reserved field
and a 16-bit `INTERNET_PORT`; only the low sixteen bits of the Win64 argument
register are consumed. It creates a connection object but, as on Windows,
establishes no network connection. `WinHttpOpenRequest` requires a live
connection handle of the correct type. Validation and insertion happen under
the same handle-table lock, so another thread cannot close the parent between
the two steps. Null verb and version strings default to `GET` and `HTTP/1.1`;
a null object name is transmitted as `/`. The request copies its strings and
accept types out of guest memory. Its initial header collection includes the
configured User-Agent, Accept and Referer values. A request accepts zero
flags or `WINHTTP_FLAG_SECURE`. The latter records that HTTPS was requested.
Sending that request fails with `ERROR_NOT_SUPPORTED` before network use.

`WinHttpAddRequestHeaders` updates a live request before sending begins. It
copies a counted or null-terminated UTF-16 header block and accepts CRLF between
fields, with an optional trailing CRLF. Add, add-if-new, replace, remove and
comma or semicolon coalescing operate on case-insensitive field names.
Replacement and coalescing affect the first match. Each update is atomic and
the configured collection is bounded at 256 fields, 64 KiB serialized and
8 KiB per field line. Indexed updates, conflicting modifiers and changes to
transport-managed framing fields fail explicitly.

`WinHttpSendRequest` performs one synchronous cleartext HTTP/1.1 exchange.
The request includes configured fields followed by the call's additional
header block.
It validates and copies additional headers and the optional request body out
of guest memory before network use. A header length of `-1` means a
null-terminated UTF-16 header block; otherwise the documented length is a
count of UTF-16 units. Header lines must use CRLF and a printable ASCII field
name and value. `Host`, `Content-Length`, `Connection` and
`Transfer-Encoding` are generated by the transport. `Host`, `Content-Length`
and `Connection` are refused in the additional-header block; a
`Transfer-Encoding` line is accepted only when its value is exactly
`chunked`, the one upload coding the synchronous transport supports. Xenora
emits `Connection: close`; there is no connection reuse or keep-alive pool.
When the declared total length exceeds the optional body, the remainder
streams synchronously through `WinHttpWriteData`, which copies bytes verbatim,
refuses writes beyond the declared length and completes the upload when the
accounting reaches zero. Chunked upload follows the public Windows Server
2008 contract: the request carries the `Transfer-Encoding: chunked` header,
optional data must be absent and no total length may be declared — the
`WinHttpSendRequest` reference forbids optional data with the header, and the
Content-Length the total length specifies cannot combine with it. As public
.NET WinHttpHandler usage documents, WinHTTP does not frame the chunks; the
caller writes the chunk framing itself and the bytes pass through verbatim.
Because the framing carries no completion signal the transport can recognize,
`WinHttpReceiveResponse` is accepted directly from the writing phase for a
chunked upload; reads before any writing remain invalid. This is a Xenora
choice the public text leaves silent. The pre-send copy is bounded at 16 MiB;
larger inline bodies fail with `ERROR_OUTOFMEMORY`.

`WinHttpSetTimeouts` accepts session and not-yet-sent request handles. Its
signed millisecond values follow the public contract: zero or minus one means
no API-level timeout, positive values are finite timeouts and other negative
values fail with `ERROR_INVALID_PARAMETER`. Sessions start with the documented
defaults: infinite resolution, 60-second connect, 30-second send and 30-second
receive timeouts. A request inherits a snapshot of the session values when it
is created; later session changes do not rewrite that request, while a request
override applies only to that request. Connect, send and receive timeouts are
applied to the blocking TCP operations. Rust's host resolver is blocking and
cannot be cancelled once entered, so a finite resolution timeout is enforced
with a detached helper thread: the caller fails with `ERROR_WINHTTP_TIMEOUT`,
while a late resolver result is discarded. Resolution therefore has the
documented helper-thread cost and is not true cancellation of the operating
system resolver. A request may connect to whatever address the resolver
returns; loopback tests are evidence of the transport mechanics only, not of
general Internet reachability.

`WinHttpSetOption` takes a four-byte guest DWORD for resolve, connect, send or
receive timeouts on a session or a request before sending begins. It preserves
the full unsigned range. Zero and `0xffffffff` disable the timer in this
transport, and `WinHttpQueryOption` returns the stored DWORD unchanged.
Querying implements the required-size contract by writing four to
`lpdwBufferLength` when the output buffer is null or too small and failing
with `ERROR_INSUFFICIENT_BUFFER`; success writes exactly four bytes. Connection
handles fail with the incorrect-handle-type error, unknown options fail with
`ERROR_WINHTTP_INVALID_OPTION`, and arbitrary other options remain unsupported.

`WinHttpReceiveResponse` parses HTTP/1.0 and HTTP/1.1 status lines and a
bounded response header block. It preserves the status line and headers for
the supported `WinHttpQueryHeaders` forms: `WINHTTP_QUERY_STATUS_CODE` as a
UTF-16 string or combined with `WINHTTP_QUERY_FLAG_NUMBER` as a 32-bit number,
`WINHTTP_QUERY_STATUS_TEXT` as a UTF-16 string, `WINHTTP_QUERY_CONTENT_TYPE`,
`WINHTTP_QUERY_CONTENT_LENGTH` as a UTF-16 string or 32-bit number, and
`WINHTTP_QUERY_SERVER`. Named response-header lookup is case-insensitive and
returns the occurrence `lpdwIndex` selects, zero-based and defaulting to
zero, advancing by one on success only, as the public implementation evidence
contracts the enumeration loop. A missing supported header fails with
`ERROR_WINHTTP_HEADER_NOT_FOUND`. String forms implement the documented
required-size contract and report the successful byte length without the
terminating null. Request-header queries and all other info levels remain
unsupported. Bodies with
`Content-Length` are bounded by
that length; responses without one are read until close. `HEAD`, informational,
204 and 304 responses have no body. Chunked transfer coding is decoded incrementally; other transfer codings are
rejected rather than decoded incorrectly.

`WinHttpQueryDataAvailable` reports bytes available without consuming them,
waiting for more cleartext body data in the synchronous subset when the end
has not been reached. `WinHttpReadData` zeroes its count output before other
work, validates the destination span before consuming network data, returns a
bounded partial read, reports EOF with a zero count and propagates malformed
responses, timeouts and reset connections as documented WinHTTP errors.
Responses whose only transfer coding is exactly `chunked` are decoded
incrementally: chunk sizes and extensions are bounded and validated, chunk
data is exposed without the framing bytes, trailers are validated and
discarded, and malformed framing or premature EOF fails the request rather
than being exposed as body data. Other transfer codings and combinations
remain unsupported.
Operations on one request handle are serialized by its transport lock;
independent handles may proceed independently. Closing a handle while another
thread is using it remains caller misuse, but the implementation retains the
in-flight object rather than corrupting the table.

`WinHttpCloseHandle` closes exactly one session, connection or request handle
and makes later use of that value fail. Closing a parent does not rewrite an
existing child object: children carry immutable snapshots of the state they
need. This is Xenora's object-lifetime policy for the synchronous subset;
Microsoft's public documentation requires applications to close handles and
not reuse them but does not give a complete parent-close cascade contract.
Handles are process-local opaque values and are also discarded when the guest
process exits.

`WinHttpQueryHeaders` also answers `WINHTTP_QUERY_RAW_HEADERS_CRLF` with the
exact wire text of the final response head: the status line and every header
line in received order, each CRLF-terminated, with no trailing blank line,
and `WINHTTP_QUERY_RAW_HEADERS` with the same head transcribed into the
NUL-separated form — every line ending becoming the line's terminator, the
trailing empty string's own terminator appended exactly as the public
implementation evidence lays the form out.
Interim informational responses are not included. It answers
`WINHTTP_QUERY_CUSTOM` by matching the caller-supplied header name
case-insensitively against the final response headers and returning the first
value. The name must be a nonempty printable-ASCII field name; a missing
header fails with `ERROR_WINHTTP_HEADER_NOT_FOUND`. Both forms share the
textual sizing contract: insufficient or absent buffers report the required
byte count including the terminator through the length parameter and fail
with `ERROR_INSUFFICIENT_BUFFER` without writing, while success reports the
byte count excluding the terminator.

`WinHttpReceiveResponse` follows redirects automatically, as the public
implementation evidence describes: statuses 301, 302, 307 and 308 with a
required `Location` header, absolute targets cracked by the same parser as the
public cracking service, `/`-rooted locations replacing the path and other
relative locations resolving against the parent directory of the current
path. POST rewrites to GET with the body dropped for 301 and 302 only; 307
and 308 preserve the verb. Body bytes are retained as sent — bounded at the
same 16 MiB as inline bodies — so verb-preserving redirects replay them
exactly; retention overflow fails the redirect. HTTPS targets fail with
`ERROR_WINHTTP_REDIRECT_FAILED` because TLS is unsupported, a missing
`Location` fails with `ERROR_WINHTTP_HEADER_NOT_FOUND`, and following stops
with `ERROR_WINHTTP_REDIRECT_FAILED` past ten redirects — a Xenora bound the
public text leaves silent. Redirect-disabling options, policies and callbacks
remain unsupported.

TLS certificate validation, HTTPS, asynchronous callbacks, in-flight cancellation,
authentication, proxy resolution, connection
reuse, transfer codings other than exactly `chunked` and their combinations, chunk
framing generated by the transport, and libcurl-compatible interfaces
remain unsupported. Tests
use independently authored controlled loopback servers and synthetic guest
memory on Apple Silicon only. They are not Windows comparison evidence,
independent review or proof of Internet connectivity.

### Encoding conversions and code pages

`MultiByteToWideChar` and `WideCharToMultiByte` convert between the narrow
and wide forms of three documented public pages: UTF-8 exactly (surrogate
pairs and the malformed sequences of the Unicode standard's substitution
included), Windows-1252 and IBM 437. `GetACP` answers UTF-8 — Xenora's
choice, the value of a Windows installation in its documented UTF-8 mode,
coherent with the UTF-8 process arguments — and `GetOEMCP` answers 437.
`IsValidCodePage` is true for exactly the three numbers; `GetCPInfo`
reports their widest characters and default bytes. Malformed input is
replaced with U+FFFD unless the caller passes the strict flag, which fails
with `ERROR_NO_UNICODE_TRANSLATION`; a character the target page cannot
represent becomes the default byte and raises the caller's flag. A zero
byte count is the documented failure Microsoft's pages describe, not an
empty conversion. Nothing was compared with Windows.

### Locale identity

One locale exists: English (United States), which is Xenora's choice. The
LCID and LANGID getters answer its `0x0409`, `GetUserDefaultLocaleName`
answers `en-US`, and the `GetLocaleInfo` forms serve its documented public
strings — the decimal point, the date and time formats, the currency — in
wide and narrow output. Another locale, an unknown type or the number form
fails with `ERROR_INVALID_PARAMETER` rather than answering wrong. Nothing
was compared with Windows.

### String comparison

`lstrcmp`, `CompareString` and the insensitive forms compare in byte order -
ordinal, not the linguistic order Windows en-US uses - with an ASCII-only
case fold when insensitivity is requested. Flags Xenora does not implement
are refused with `ERROR_INVALID_PARAMETER` rather than silently ignored.
`GetStringTypeW` answers `CT_CTYPE1` classification of ASCII input and
refuses the other types; `LCMapStringW` maps ASCII case and refuses sort
keys. Nothing was compared with Windows.

### The console and the standard handles

The three standard devices answer fixed pseudo-handles. `WriteConsole` and
`printf` append to the same capture in call order; the console code pages
are UTF-8, coherent with the process code page. `SetStdHandle` changes what
`GetStdHandle` answers, but console writes and reads still belong to the
fixed console devices: a redirected handle that is no console fails with
`ERROR_INVALID_HANDLE`. The console mode bits round-trip without altering
the capture behavior yet. `ReadConsoleA` hands one input line back with CR
LF restored. Nothing was compared with Windows.

### The narrow file services

The narrow forms of the directory, move, copy and find services read UTF-8
paths, coherent with the process code page, and share one implementation
and one drive with the wide forms: a file written through one width is the
file read through the other. `CopyFile` onto itself is a sharing violation,
`GetFullPathName` resolves relative names against the synthetic root -
there is no current directory yet - `SetFileAttributes` accepts only the
normal and archive bits because the drive keeps no attribute state, and
`GetTempFileName` answers unique names within a run. Nothing was compared
with Windows.

### The legacy memory services

`GlobalAlloc` and `LocalAlloc` are thin wrappers over the process heap, as
on every 32- or 64-bit Windows: memory is always fixed, the handle is the
pointer itself, and the moveable bit and the discardable hints of the
16-bit memory manager are accepted and inert. Freeing the null handle is
a no-op success; freeing a non-allocation answers the handle itself with
the invalid-handle error. Flags outside the documented mask are an invalid
parameter. Nothing was compared with Windows.

### Error reporting

`FormatMessage` reads the system table for the error codes the synthetic
services produce, in en-US, with the trailing newline real messages carry.
Insert sequences expand string and numeric specifiers; the arguments are
read as a flat array of machine words, so floating point inserts are not
formatted. The allocate form allocates from the process heap and the memory
is released with `LocalFree`, as documented. Unknown identifiers fail with
the missing-message error; module tables do not exist yet and
`FORMAT_MESSAGE_FROM_HMODULE` is refused as unsupported. `SetErrorMode`
stores and exchanges the mode even though no error dialogs exist. Nothing
was compared with Windows.

### The environment block

The environment is empty, so expansion is the identity - the documented
result when no variable is defined. `ExpandEnvironmentStrings` counts the
terminator in both its success return and its required-size answer.
`GetEnvironmentStringsW` hands each caller its own copy of the empty block
from the process heap, because the documentation requires the caller to
free it.

### The simulated machine

`GetVersionEx` reports a Windows 10 era NT workstation, coherent with the
GDK-era programs the runtime hosts; it is simulated, not measured.
`GetWindowsDirectory` and `GetSystemDirectory` answer the synthetic drive's
layout, the computer name is XENORA, and the processor topology is one core
in one package in one group, coherent with the count `GetSystemInfo`
reports. Numa, cache and group relationships are not modeled yet:
enumerating them alone answers zero entries. Nothing was compared with
Windows.

### Guest modules

The program's module handle is the base address its image was loaded at.
`GetModuleHandleA` and `GetModuleHandleW` return it for a null name, and
otherwise recognize the built-in Kernel32, KernelBase and UCRT modules, the
API sets registered for Kernel32 and the UCRT, and prepared guest modules
admitted to the in-memory dynamic catalog. Names compare without case; `.dll`
is appended to a name without a dot, while a trailing dot means exactly that
extensionless name. Paths and the program's own file name are not recognized.
Built-in handles are identities without an image.

`GetModuleHandleExA` and `GetModuleHandleExW` also count a reference, pin the
module, leave the count alone, or find the module by an address. Pinning cannot
be combined with an unchanged count. The address may lie anywhere in the program's
image or in a registered guest module's half-open image range; a built-in module
contains only its handle. The program, Kernel32 and KernelBase stay loaded
whatever the count; the UCRT is unloaded with its last reference unless it was
pinned. `FreeLibrary` releases only references that were counted.

`K32GetModuleInformation`, and `GetModuleInformation` of `psapi.dll`, give the
program's base, `SizeOfImage` and entry point. They refuse built-in modules with
`ERROR_NOT_SUPPORTED` and any process but the current one. Microsoft documents no
error codes for these functions; the ones used are Xenora's choice.

`GetProcAddress` resolves case-sensitive names and ordinals of built-in modules to
guest service trampolines. The catalog is built after every other standard service
is registered and leaves out stubs. The program's own export table is not read.
KernelBase exports only what Microsoft lists for it here. The services resolve
through the API sets on Microsoft's pages. No host library is ever loaded.

A crate-internal registration hook can admit an already prepared guest PE image
to the same catalog under its closed-world logical file name, base address,
half-open image size and retained export table. The hook performs no host file
search, loading, relocation, initialization or execution; the caller must already
have prepared the image. A registered module's handle is its base. Direct named
and ordinal exports resolve to `base + RVA` guest image addresses, never service
trampolines. Forwarder strings follow the package loader's documented last-dot
grammar, are limited to eight edges, and may terminate in another registered
guest module or in a captured built-in service export; only the service terminal
produces a service trampoline. `GetModuleFileName` answers the logical module
name, never a host path.

Dynamic modules are process-resident in the current lifecycle model. Registration
adds one loader-owned reference and pins the image because unloading, unmapping
and reference-count teardown do not exist yet. A guest `FreeLibrary` can release
counted references, but it never unmaps the image or makes its exports invalid.
This is a documented deviation from Windows loader teardown, not a claim of full
`LoadLibrary` support: converting a guest load request into preparation and
registration remains later work. Original byte-built synthetic modules cover
handle identity, range containment, direct and ordinal exports, guest and
kernel32 forwarder terminals, the eight-hop bound, logical file names, collision
refusal and process-resident bookkeeping. `crates/loader/tests/modules.rs` runs
original C and C++ programs through the built-in service surface; nothing was
compared with Windows.

### Synthetic guest files

The runtime exposes an in-memory C: drive through CreateFileW, ReadFile,
WriteFile, GetFileSizeEx, and CloseHandle. It supports UTF-16 file and
directory names, ASCII case folding, synchronous I/O, per-open file positions, and
read/write sharing. SetFilePointerEx supports seeking from the beginning,
current position, and end. SetEndOfFile truncates or zero-extends writable
files at the current position. Seeks alone do not change file length.
Paths cannot access host files. The drive supports
256 files and 16 MiB of data, with a 1 MiB limit per transfer.
CreateDirectoryW and RemoveDirectoryW manage up to 256 directories. Parents
must exist, and directories must be empty before removal. DeleteFileW
deletes closed files. MoveFileW moves closed files to an unused name under
an existing directory. GetFileAttributesW distinguishes files and directories.
Traversal components and device names are rejected.
FindFirstFileW, FindNextFileW, and FindClose enumerate a sorted snapshot of
direct children. The final path component accepts literal names, * and ?
wildcards, and *.* matches every name. Results include attributes, byte size,
and a UTF-16 name. Times and alternate names are zero. Up to 32 searches
can be open. Same-process file handle duplicates share the file position and keep the
original sharing reservation until the last duplicate closes. Access can
be reduced per handle. DOS wildcard edge cases, persistence, and
asynchronous I/O remain outside this subset.

### Event and semaphore signaling

The synthetic runtime supports unnamed manual-reset and auto-reset events
created with default security attributes. `SetEvent` signals an event,
`ResetEvent` clears it, and `CloseHandle` invalidates the handle.
`WaitForSingleObject` consumes an auto-reset signal once, leaves a manual-reset
signal set, and reports `WAIT_TIMEOUT` when a zero-timeout poll finds no signal.
Without an attached thread scheduler, a wait that would block returns `WAIT_FAILED` with `ERROR_NOT_SUPPORTED`; with one it blocks the calling guest thread ([guest threads](runtime/threads.md)).
Thread and event handles are distinct types in the same bounded table.
Event duplicates share signal state and keep the event alive independently.
A duplicate can retain or reduce its rights. Waiting requires synchronize
access, and setting or resetting requires modify-state access.

`WaitForMultipleObjects` supports immediate waits on up to 64 events or semaphores.
Wait-any selects the first signaled handle. Wait-all consumes auto-reset
signals only when every object is ready. Repeated handles and wait-all
aliases to the same event are rejected. The extended single- and multiple-
object wait APIs support the same immediate behavior when alerting is
disabled. Alertable calls and waits that would block return an unsupported
error.

`CreateSemaphoreA` and `CreateSemaphoreW` create unnamed semaphores
with default security attributes. A successful wait consumes one permit.
`ReleaseSemaphore` can return the previous count and rejects a release
that exceeds the maximum without changing the count. Duplicates share
the same permit count.

`CreateMutexA`, `CreateMutexW` and their `Ex` forms create unnamed mutexes,
optionally owned by the caller. Ownership belongs to the calling guest
thread, identified by its TEB. The owner can acquire the mutex again, and
each acquisition needs a matching `ReleaseMutex`. Another thread sees the
mutex as unsignaled. A release by a thread that is not the owner fails with
`ERROR_NOT_OWNER`. Waits, duplicates and wait-all treat mutexes like the
other waitable objects. A mutex whose owner thread ended
is reported once as abandoned.

See Microsoft's [event object documentation](https://learn.microsoft.com/windows/win32/sync/event-objects).

### Locks, one-time initialization and thread-local storage

These services keep their state in the runtime and key ownership by guest
TEB. With an attached scheduler a call that has to wait blocks only the calling
guest thread ([guest threads](runtime/threads.md)). Without one it stops the
guest with the runtime-limit fault (`IllegalInstruction(0xFE)`) rather than
reporting success. Guest code reaches that fault by entering a critical
section owned by another thread, acquiring a held SRW lock, or beginning a
one-time initialization that another thread has pending.

- Critical sections use the x64 `RTL_CRITICAL_SECTION` layout from
  `winnt.h`. Initialization writes the 40-byte structure. `LockCount` is -1
  when free and -2 when held, also while threads wait; the runtime also updates `RecursionCount` and
  `OwningThread`. The owner may enter recursively. `TryEnterCriticalSection`
  returns FALSE when another thread owns it. Leaving a section the caller
  does not own, or using one that was never initialized, stops the guest.
  The runtime holds up to 4,096 sections.
- SRW locks allow any number of shared holders or one exclusive holder. The
  try forms return FALSE instead of waiting. Exclusive acquisition is not
  recursive. Releasing a mode the caller does not hold stops the guest.
- Condition variables check that the caller holds the named lock. A
  zero-timeout sleep returns FALSE with `ERROR_TIMEOUT` and leaves the lock
  held in its original mode. With a scheduler, longer sleeps release the lock,
  block and return with it held again: TRUE when woken, FALSE with
  `ERROR_TIMEOUT` otherwise. `WakeConditionVariable` wakes the thread that has
  slept longest, and `WakeAllConditionVariable` wakes all. A wake-up with no
  sleeper is not remembered. Sleeping with a section entered more than once
  stops the guest. Without a scheduler longer sleeps return
  `ERROR_NOT_SUPPORTED`.
- `InitOnceBeginInitialize` and `InitOnceComplete` support the synchronous
  mode, `INIT_ONCE_CHECK_ONLY` and `INIT_ONCE_INIT_FAILED`. The completed
  context is stored in the `INIT_ONCE` word, so later calls read it back.
  Asynchronous mode returns `ERROR_NOT_SUPPORTED`. `InitOnceExecuteOnce`
  calls the guest initializer once with the object, the parameter and a
  context pointer. A FALSE result, or a context that uses the two reserved
  low bits, leaves the object uninitialized so a later call can retry.
- Interlocked SLists use the x64 `SLIST_HEADER` layout. The low 16 bits hold
  the depth, and bits 4 to 63 of the second quadword hold the first entry.
  Headers and entries must be 16-byte aligned. Updates are atomic with
  respect to other services. They are not atomic with respect to guest
  instructions that modify the header directly on another host thread.
- TLS provides the documented 1,088 indexes. FLS provides the 128
  `FLS_MAXIMUM_AVAILABLE` slots defined in the MinGW-w64 headers. Values are
  per guest thread, new indexes read as zero everywhere, and successful
  `TlsGetValue` calls clear the last error; `TlsGetValue2` leaves it unchanged.
  Values live in the runtime, not in the TEB
  `TlsSlots` array, so guest code that reads the TEB directly does not see
  them. `FlsFree` releases the slot, then calls its cleanup callback on the
  calling thread for each thread's nonnull value, in TEB order.

### System information, calendar time and sleeping

The guest sees a simulated machine described by `GuestSystemProfile` on
`ServicesState`, and never the host's hardware. `HostCapabilities::detect`
reports the Mac's logical processors, physical memory and page size
separately, for diagnostics.

- `GetCurrentProcessorNumber` reports virtual processor zero, consistent with the guest scheduler and affinity model (#1201).
- `GetSystemInfo` and `GetNativeSystemInfo` report an AMD64 processor
  (`PROCESSOR_ARCHITECTURE_AMD64`, `PROCESSOR_AMD_X8664`), 4 KiB pages,
  64 KiB allocation granularity and the x64 user address range
  `0x10000`–`0x7FFFFFFEFFFF`. The processor count comes from the profile and
  defaults to one, because guest code runs on one thread at a time. The
  processor level and revision are zero, because no CPU model is simulated.
- `GlobalMemoryStatusEx` requires `dwLength` to be 64. Guest physical memory is
  the virtual-allocation and heap budgets together, 128 MiB. Available memory
  and `dwMemoryLoad` reflect current guest allocations. There is no paging
  file, and the virtual totals cover the x64 user range.
- `GetSystemTime`, `GetLocalTime` and `GetSystemTimePreciseAsFileTime` read
  the injected clock. The guest time zone is UTC, so local time equals system
  time. `FileTimeToSystemTime` and `SystemTimeToFileTime` convert using the
  proleptic Gregorian calendar. They reject FILETIME values with the top bit
  set and invalid dates (years outside 1601–30827), ignore the day of week on
  input, and return `ERROR_INVALID_PARAMETER` without writing output.
- `QueryUnbiasedInterruptTime` reports 100 ns ticks since the service state
  was created.
- `Sleep` and `SleepEx` suspend the calling thread through the clock, so the
  mock clock advances instead of waiting. With a scheduler other guest threads
  run meanwhile, zero gives up the rest of the turn, and any duration is
  accepted. No APCs exist, so an alertable sleep always returns zero. Without a
  scheduler, `INFINITE` and sleeps longer than 10 seconds stop the guest with
  the runtime-limit fault, because a single guest thread could not be woken.

### Pointer encoding

`EncodePointer` and `DecodePointer` are exact inverses over a synthetic
per-process cookie derived from the guest process id. Public Windows
documentation does not specify a stable cookie algorithm, so Xenora chooses
XOR with a mixed process id followed by a 13-bit rotation and marks both
exports partial. Encoded pointers are stable within one guest process, differ
between process ids, and are not Windows-compatible values or cryptographic
protection. An original generated PE image imports both exports and round-trips
a pointer through the translated service path. Local Apple Silicon verification
only; no Windows comparison is claimed.

### Services that call guest code

A service registered as a callback task can call guest functions before it
returns. The dispatcher reserves 72 bytes of guest stack below the caller's
return address. That space holds the callback's return address, its 32-byte
home area and 16 bytes of scratch owned by the service, and it keeps RSP at 8
modulo 16 on entry, as after a CALL. Each callback receives up to four
integer register arguments and must preserve the Win64 nonvolatile
registers, or the guest stops with `ServiceAbiViolation`. The callback's RAX
is passed to the task, which either calls guest code again or returns a value
to the original caller with its RSP restored. Up to 32 callback frames may be
active. Callback entry points must be executable. The earlier one-shot
dispatch used by the GDK task queue is unchanged.

The CRT uses this for:

- `qsort` and `qsort_s`, which sort up to 1 MiB in place with a guest
  comparator. Elements stay in place while the comparator runs and are
  permuted once at the end. `qsort_s` passes its context as the first
  comparator argument.
- `bsearch` and `bsearch_s`, which return a pointer to a matching element
  or null.
- `_initterm` and `_initterm_e`, which call each nonnull entry of an
  initializer table in order. `_initterm_e` stops at the first nonzero
  result and returns it. Tables hold at most 65,536 entries.

- `_initialize_onexit_table`, `_register_onexit_function` and
  `_execute_onexit_table` manage `_onexit_table_t` tables. Their storage is
  on the default guest heap, and they hold at most 65,536 entries. Execution
  resets the table first, then calls the functions in reverse order of
  registration. `atexit` and `_crt_atexit` record process exit functions,
  which `_cexit` runs in reverse order and returns. `exit` runs them and
  then ends the process; see "PE32+ fixture startup" above.

Null comparators, null arrays with a nonzero count, and reversed or
misaligned tables would reach the CRT invalid-parameter handler. That
handler is not modeled, so these inputs stop the guest with the
runtime-limit fault.

API-set aliases follow Microsoft's
[Win32 APIs for UWP apps](https://learn.microsoft.com/uwp/win32-and-com/win32-apis)
listing: critical sections, SRW locks and mutexes use
`api-ms-win-core-synch-l1-1-0`; condition variables and one-time
initialization use `api-ms-win-core-synch-l1-2-0`; SLists use
`api-ms-win-core-interlocked-l1-1-0`; TLS uses
`api-ms-win-core-processthreads-l1-1-0`, with `TlsGetValue2` also in
`api-ms-win-core-processthreads-l1-1-8`; and FLS uses
`api-ms-win-core-fibers-l1-1-0`.

### C runtime startup configuration

A C program's startup code configures the C runtime before `main`. Nine
services record what it sets and return what their public documentation says.
The startup settings are declared in the typed registry
(`docs/runtime/services.md`). Each has the scope shown below.

| Service | Returns | Not provided |
| --- | --- | --- |
| `_set_app_type(type)` | nothing | Nothing depends on the type |
| `_set_new_mode(mode)` | the previous mode; -1 and `errno` `EINVAL` unless the mode is 0 or 1 | `malloc` never calls a new handler |
| `_configthreadlocale(request)` | the setting before the call (1 enabled, 2 disabled; a program starts disabled); -1 and `errno` `EINVAL` unless the request is 0, 1 or 2 | There is no locale |
| `__setusermatherr(handler)` | nothing | The handler is never called |
| `_set_invalid_parameter_handler(handler)` | the previous global handler, null at first | The two explicit invalid-parameter entry points use the global handler. Thread-local overrides are unavailable |
| `__p__fmode()`, `__p__commode()` | the address of the guest `int` `_fmode` (initially `_O_TEXT`, `0x4000`, as documented) or `_commode` (initially 0; its documentation gives no initial value) | Nothing reads either until stdio exists |
| `signal(sig, handler)` | the previous handler, `SIG_DFL` at first; `SIG_ERR` and `errno` `EINVAL` for a signal other than `SIGINT`, `SIGILL`, `SIGFPE`, `SIGSEGV`, `SIGTERM` and `SIGABRT` | No signal is ever raised. One table serves the process |
| `SetUnhandledExceptionFilter(filter)` | the previous filter, null at first | Called at the end of an unhandled search (see "Structured exceptions and CPU faults"); no debugger or error-mode handling |

The UCRT and `api-ms-win-crt-runtime-l1-1-0.dll` provide
`_invalid_parameter_noinfo` and `_invalid_parameter_noinfo_noreturn`. They
call the installed global handler with five zero arguments. A returning
handler lets the ordinary call return. The nonreturning entry point
terminates even if its handler returns. Both terminate when no handler is
installed. Xenora models termination with `STATUS_INVALID_CRUNTIME_PARAMETER`
(`0xC0000417`). Existing CRT validations keep their service-specific error
paths. Fast-fail exceptions, debugger dispatch and Watson reporting are
outside this model.

`_fmode` and `_commode` share one 8-byte block allocated from the process heap
on the first call to either. `ServicesState::crt_app_type` and
`ServicesState::crt_user_math_error` let a host read the two values no service
returns. `signal.h` also defines `SIGBREAK` and `SIGABRT_COMPAT`, which the
documentation of `signal` does not list; they are refused, and whether Windows
accepts them was not checked. `memcpy` also resolves through
`api-ms-win-crt-private-l1-1-0.dll`, the API set the mingw-w64 runtime imports
it from. None of this has been compared with Windows.

## Synthetic tiled textures

The texture crate reads original fixtures in an array-layer-major layout. Each
layer stores a consecutive mip chain. Within each mip, row-major 2×2 tiles store
four row-major Block Compression 1 (BC1) blocks, including slots beyond the
logical edge. The reader validates the full byte length, rejects padding
coordinates and can decode each logical block to sixteen RGBA8 texels.
The decoder uses bit replication to expand 5:6:5 endpoints and rounds integer
palette interpolation down. This layout is specific to Xenora fixtures. The block encoding follows the
[Direct3D BC1 description](https://learn.microsoft.com/en-us/windows/win32/direct3d10/d3d10-graphics-programming-guide-resources-block-compression).

`TiledBc1::linearize` strips the tile padding from one selected subresource
while retaining complete compressed blocks at logical image edges.
`NativeCompute::read_tiled_bc1` checks the pixel budget and the Metal device's
BC texture capability, then uploads the selected blocks as a single
BC1 RGBA texture. A fixed Metal compute kernel reads each texel and returns
row-major RGBA8 words. The texture path uses authored MSL and takes its
input from the host fixture.

## Persistent guest graphics resources (X9)

A separate fixed-base PE32+ test profile exposes `xenora_resource`. RCX
points to a readable, four-byte-aligned request of five little-endian
32-bit words (operation, handle, offset, length and kind). RDX carries a
guest data address for uploads and readback. Other operations require it
to be zero. Handle values encode a slot and generation. Every guest run
owns a separate eight-slot table. Slots can be reused only with a new
generation. Guest addresses and handles never expose host pointers.

| Operation | Request data |
| --- | --- |
| 1, create buffer | Length in bytes and kind 1 (compute words) or 2 (draw vertices). RDX points to initial data. |
| 2, update buffer | Handle, byte offset and length. RDX points to source bytes. |
| 3, destroy resource | Handle. A queued snapshot retains its bytes after destruction. |
| 4, queue compute | Handle, byte offset and length. The selected view binds the original translated XOR compute fixture. |
| 5, complete and read back | Exact result length and a writable RDX destination. |
| 6, queue draw | Handle, byte offset, length 96 and program ID 1 (constant color) or 2 (interpolated color). The input contains three float4 clip positions followed by three float4 colors. Readback is 4×3 row-major RGBA8. |
| 7, create texture | Length of compressed data in bytes. RDX points to eight descriptor words followed immediately by the compressed data. |
| 8, queue texture read | Handle, array layer in the offset field and mip index in the length field. Completion returns row-major RGBA8. |

The texture descriptor contains width, height, mip count, layer count,
format (1 for BC1), usage (1 for sampling), row pitch and slice pitch.
The row pitch is aligned to the eight-byte BC1 block size. Each mip
occupies one slice and uses the same pitches. Slices appear in mip order
within each layer. The whole descriptor and payload must occupy one
readable guest span. Textures are immutable. This is an original linear
upload contract for the test profile. Opcode 8 uploads the selected
subresource and uses an authored Metal texel reader.

Buffers and compressed texture payloads are limited to 4096 bytes.
Queueing captures one immutable view. Completion validates the guest
destination before submitting GPU work and waits for Metal before writing
the result. An update or destruction after queueing cannot change the
captured bytes. Guest exit drops resources and any queued view. Data persists
across guest calls in host memory and is uploaded to Metal for execution.
Persistent device allocations and GPU work in flight across guest calls
are outside this interface.

### Translated offscreen stages

`compile_graphics` decodes two original gfx1030 byte streams and links
one vertex position export, an optional four-component parameter export,
and one pixel color export. Buffer 0 supplies positions to vertex vector
registers 0–3 and buffer 1 supplies colors to registers 4–7. The pixel
stage can consume parameter zero through matching, adjacent interpolation
phase pairs. This maps to center-perspective interpolation in Metal.
The vertex stage supports a bounded set of 32-bit floating-point add and
multiply forms. The graphics ABI also supports register and finite
literal moves. Unsupported stage instructions or export combinations
fail explicitly. The Xbox graphics ABI, hardware-specific floating-point
modes, image instructions, and additional varyings remain unsupported.

## Graphics draw and blend contracts

`NativeCompute::render_indexed` issues one real `drawIndexedPrimitives` call
per draw (up to 16) on a 16- or 32-bit index buffer with a start index and a
signed base vertex, into an offscreen RGBA8 target. A draw can sample an
original BC1 texture uploaded natively. Before encoding anything it rejects
malformed draws; execution checks each draw in turn.

`NativeCompute::render_blend` draws up to 16 flat-coloured triangles in order
into an offscreen RGBA8 target. Each draw has its own colour write mask and
either blending disabled or separate RGB and alpha blend factors and
operations. Colours are compared per channel against expectations derived
independently from the public Metal blend equations.

`NativeCompute::render_depth` draws up to 16 triangles in order with an
optional `Depth32Float` attachment, a chosen clear depth and a per-draw depth
compare function. Colour and the stored depth are both read back.

These passes are checked on the GPU with Metal validation against expectations
derived independently from the public semantics; synthetic fixtures only.

## Hosted C++ guests and the cooperative scheduler

`run_synthetic_startup` runs the guest's entry point directly on the calling
thread, so a guest that called `CreateThread` was refused with
`ERROR_NOT_SUPPORTED`: the thread services require a scheduler, because they
run a guest thread and let it wait for another.

`run_synthetic_startup_scheduled` runs the same startup under the
[deterministic cooperative scheduler](../crates/loader/src/scheduler.rs). The
entry point and every thread it creates take turns, one guest thread at a
time, and share one instruction budget. The state passed to it must be the one
the import registry was built with, because the scheduler finds the guest's
threads through it. A guest that exits the process still reports its own exit
status.

A hosted C++ guest additionally needs the C++ runtime services. `libstdc++-6.dll`
provides the scalar and array `operator new` and `operator delete` imports,
which reuse the same guest heap the C runtime's `malloc` and `free` use,
`std::string`'s out-of-line `_M_dispose` and `_S_copy`, and libstdc++'s error
paths. On the 64-bit Windows target the public Itanium C++ ABI names the array
forms `_Znay` and `_ZdaPv`; Xenora implements their allocation and release
contract, while any array cookie for a non-trivially destructible element type
is emitted by the compiler. Those error paths are noreturn functions: Xenora
implements no C++ exception machinery, so they stop the guest with the
runtime-limit fault instead of returning.

The scalar and array C++17 aligned allocation operators are also registered:
`_ZnwySt11align_val_t`, `_ZnaySt11align_val_t`, `_ZdlPvSt11align_val_t` and
`_ZdaPvSt11align_val_t`. The alignment must be a nonzero power of two. The
shared guest heap places the block at that alignment when it is representable,
including alignments above Xenora's 64 KiB allocation granularity, and release
uses exact block ownership: null deletion is harmless, while an interior or
foreign pointer faults instead of releasing memory. An invalid alignment makes
allocation return null with `EINVAL`; invalid aligned deletion stops the guest
without releasing the block. Sized aligned deletion, exception propagation and
`std::bad_alloc` remain unimplemented. An original no-CRT C++ fixture exercises
compiler-emitted scalar and array forms at O0/O1/O2/Os, distinct live blocks,
zero-size blocks, null deletion and an invalid-interior control. Local
verification only; no Windows comparison or independent acceptance is claimed.

`libgcc_s_seh-1.dll!__emutls_get_address` provides GCC's emulated
thread-local storage. The compiler emits a descriptor holding one variable's
size and alignment and passes the descriptor's address; the runtime returns the
calling thread's own block for that descriptor, so two guest threads never
share a thread-local variable.

`libstdc++-6.dll` also provides the three guard-variable services of the public
[Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#guard-variables)
for thread-safe function-local statics. `__cxa_guard_acquire` reads one byte at
the aligned guest guard address through bounded guest memory: it returns 1 when
the caller takes ownership, 0 when the guard is already initialized, and -1 with
`ERROR_INVALID_PARAMETER` for a null, unaligned, unmapped or contended guard.
`__cxa_guard_release` writes the initialized byte and clears ownership;
`__cxa_guard_abort` clears ownership without writing it. Ownership is keyed by
guest guard address and the calling thread's TEB; no guest address is treated as
a host pointer. A release or abort by any other thread stops the guest with the
runtime-limit fault. Because the scheduler runs one guest thread at a time,
Xenora refuses contention and recursive acquisition instead of blocking; this
is a documented deviation from a general host ABI implementation. An original
no-CRT C++ fixture exercises the compiler-emitted guard calls and all three
services directly, and the hosted C++ fixture now uses the default thread-safe
initialization.

C++ exceptions and stack unwinding are **not** implemented. They need a
guest-side SEH unwinder that walks the guest stack through its
`RUNTIME_FUNCTION` tables, not a service, so a C++ guest is built with
`-fno-exceptions` until that milestone lands.

## Guest graphics command path

`xenora_graphics.dll` exposes the graphics runtime to guest code, so a guest
program can author graphics work instead of receiving one fixed draw. The
exports cover device, command queue, command allocator and command list
creation; buffer and render-target resources; viewport, render-target, vertex
and index binding; draws; execution; framebuffer readback into guest memory;
and ordered destruction. Every export takes Win64 arguments, returns an
`HRESULT`, and passes generation-checked opaque handles, never host pointers.

A guest draw travels from the loaded executable through the import binding and
the service layer into `GraphicsContext`, out to a backend that renders
through the translated gfx1030 stages, and back as pixels in a render-target
resource the guest can read. The native Metal path crosses the existing
`BackendRenderer` closure boundary, so the loader stays free of a direct Metal
dependency and the deterministic software reference rasteriser remains the
default on a host without a GPU.

Destruction is ordered and enforced: a device outlives its queues, allocators,
command lists and resources, an allocator outlives its command lists, a
resource outlives the recording lists that reference it, and a recording list
must be closed before it is destroyed. A refusal is an explicit error.

The exact exports, arguments and limits are in the
[guest graphics command path](runtime/guest-graphics.md).

### Guest texture binding (descriptor tables)

`GraphicsContext` lets a guest command list sample one texture in the pixel
stage through a D3D12-shaped binding. A draw samples only if a root signature
is bound. Draws without one keep the flat-colour path. The supported subset
is fixed. Anything outside it fails with `GraphicsError::Unsupported` when the
object is created, or with an error at execution. A rejected draw never
reaches the backend. Draws recorded before it in the same list have already
run.

| Object | Supported |
| --- | --- |
| `create_descriptor_heap` | Shader-visible `CBV_SRV_UAV` (0) or `SAMPLER` (1) heaps of 1–64 descriptors. RTV, DSV and CPU-only heaps are unsupported. |
| `create_committed_texture2d` | One level of `R8G8B8A8_UNORM` (28) or `BC1_UNORM` (71), 1–64 texels per side. BC1 sizes must be multiples of four. Rows are linear: 4 bytes per texel, or 8 bytes per 4×4 block. Xbox tiling is not handled. |
| `create_shader_resource_view` | A `Texture2D` view of mip 0 of a single-level, single-slice 2D texture, in the resource's own format. |
| `create_sampler` | Point filtering (`MIN_MAG_MIP_POINT`), clamp addressing on U, V and W, no LOD bias and a minimum LOD of 0. |
| `create_root_signature` | Exactly two pixel-visibility descriptor tables, in either order: one with a single SRV range for `t0`, and one with a single sampler range for `s0` (one descriptor each, space 0). Root constants, root descriptors, CBV and UAV ranges, extra tables or ranges and static samplers are unsupported. |
| `cmd_set_descriptor_heaps` | At most one heap of each type. |
| `cmd_set_graphics_root_descriptor_table` | The base must be a GPU handle to a slot of the bound heap of the table's type. The slot must hold a descriptor when a draw reads it. Changing the heaps or binding a different root signature clears every table. Setting the same heaps or the same root signature again keeps them. |

Descriptor handles follow D3D12 pointer arithmetic: the heap start plus
`index × GetDescriptorHandleIncrementSize` (32 here; guests must query the
value). `offset` returns `None` rather than carry into the next heap. CPU and
GPU handles are separate spaces. A textured draw is a `DrawInstanced` of
one instance of three vertices with start instance 0, starting at any vertex. Zero vertices or
instances draw nothing. The sampled texture must be in `COMMON` or a read-only state that includes
`PIXEL_SHADER_RESOURCE`. The software reference draws at most 4096 pixels. Each vertex record holds a float4 position
at byte 0 and a float4 texture coordinate at byte 16, with a stride of at
least 32. Textured indexed draws are unsupported.

The native backend receives a `TexturedDraw` with the bound level and must
bind it to fragment texture 0 and sampler 0, which are the `tex0` and `samp0` arguments of
the translated `image_sample_lz` pixel stage. `NativeCompute::render_rgba8_sampled_bc1`
binds a BC1 level natively for that purpose. The software reference has no
clipping or depth test. A pixel is covered when its centre lies inside or on
an edge of the triangle. The texture coordinate is interpolated affinely, so
`w = 1` is required, and point sampled with
`min(floor(clamp(u, 0, 1) × width), width − 1)`. It decodes BC1 with the
spec-exact `xenora_texture::decode_bc1`. Apple's hardware rounds BC1's two
interpolated palette entries differently (171/84 against 170/85, measured
on an M5 Pro), so the tests use endpoint colours only. Pipeline
state objects do not exist yet, so the backend, not the guest, chooses the
pixel shader. These entry points are not yet wired to guest imports.

## Bounded GPU workload resource budget

This is the consolidated description of the resource limits implemented today
across the guest graphics command path, the persistent X9 resource profile,
native compute submission and staged texture upload. It cross-references the
[guest graphics command path](#guest-graphics-command-path),
[guest texture binding](#guest-texture-binding-descriptor-tables),
[persistent guest graphics resources](#persistent-guest-graphics-resources-x9),
[synthetic tiled textures](#synthetic-tiled-textures), [graphics draw and blend
contracts](#graphics-draw-and-blend-contracts), and the
[guest graphics service ABI](runtime/guest-graphics.md). The source of truth is
the validation code and named constants in `crates/loader/src/graphics.rs`,
`crates/loader/src/services/graphics.rs`, `experiments/x1/src/x9.rs`,
`crates/metal/src/compute.rs`, `crates/metal/src/render.rs`,
`crates/metal/src/texture_pipeline.rs` and `crates/texture/src/upload.rs`;
this section collects their existing contracts, not a new API. The limits are
independent per-subsystem caps, not
one shared CPU/GPU ledger or a claim about a platform-wide allocation
guarantee. A common accounting interface remains separate work.

Failure is explicit where a bound is enforced. Recording-time checks reject an
operation before it is appended; execution-time checks reject a draw, dispatch
or transfer before it submits GPU work or writes a result. The caller sees an
`HRESULT` from `xenora_graphics.dll`, a `FaultKind` from the X9 resource
service, a `GraphicsError` from the loader API or a `MetalError` from the native
backend. A rejection is never a silent clamp, an empty success, or a fallback
to a smaller workload. If a command list fails during execution, commands
already completed stay completed and the rejected command does not run. The
guest command path refuses destruction while a queue, allocator or
still-recording command list holds an object. The X9 profile instead retires a
slot on destruction while a queued immutable view keeps its bytes. Each backend
validates the inputs it consumes before execution; this section does not claim
that every backend performs every check in the same place.

### Guest-visible resource limits

- The `xenora_graphics.dll` command path exposes opaque, generation-checked
  handles, not host pointers. One draw is at most one triangle with one
  instance: `DrawInstanced` accepts three vertices and one instance, and
  `DrawIndexedInstanced` accepts three indices and one instance. A nonempty
  flat draw also requires zero `startVertex` and `startInstance`; a textured
  draw requires zero `startInstance` and allows any `startVertex`. The
  non-indexed paths skip zero vertex or instance counts, and the indexed path
  skips zero index or instance counts only after rejecting an instance count
  above one or a nonzero start instance. Each vertex holds a `float4` position
  plus, for a textured draw, a `float4` texture coordinate; sampling is point
  filtering with clamp addressing. Render targets are `R8G8B8A8_UNORM`;
  sampled textures are `R8G8B8A8_UNORM` or `BC1_UNORM`. Both are at most 64
  texels per side, and BC1 dimensions must be multiples of four. Viewports
  accept dimensions from 1 through 4096. Shader-visible descriptor heaps hold
  1 through 64 descriptors, with a 32-byte handle increment. Root signatures
  consist of exactly one shader-resource-view table at `t0` and one sampler
  table at `s0`; constant buffers, unordered-access views, render-target
  views, depth views, upload heaps and readback heaps are not exposed.
- At most 16 timeline fences are live in one graphics context and eight
  distinct fences may be pending on one queue. A host wait is bounded to one
  second and reports a timeout with the completed value when the target is not
  reached. A queue wait whose producer has not signalled also reports a
  timeout and keeps the dependency so the guest can signal and retry. The
  maximum `u64` fence value is reserved, and decreasing signals are refused.
- The X9 resource service gives each guest run eight generation-checked slots.
  Buffers and compressed texture payloads are at most 4096 bytes; a view's
  offset and length must be nonzero multiples of four and lie inside the
  resource. At most one submission may be pending and at most 16 readbacks are
  retained per profile. Queueing captures one immutable view, so a later
  update or destruction cannot change queued bytes. Exhaustion returns
  `ResourceLimit` or `SubmissionPending`; no new queue or readback is
  performed. Guest exit drops the run's slots and queued views.

### Native submission and compilation limits

- `NativeCompute` inputs hold from one to 4096 words. The default threadgroup
  width is at most 64 threads and no dispatch may require more than 64 groups;
  an explicit width is bounded by the device and pipeline limits. An MSL source
  string is at most 64 KiB and entry names must be nonempty. A batch accepts
  one to eight commands in one command buffer and completion wait; distinct
  output slots stay independent, a reused slot shares one output buffer, and a
  buffer-scope barrier follows every dispatch except the last so a later
  command sees an earlier write. Outputs are read after the whole batch
  completes, so a shared slot yields its final contents rather than one
  command's intermediate value. At most 16 compute submissions may be in
  flight and at most 128 queued commands may be outstanding across them;
  batch size and queue depth are checked before encoding, and a rejected batch
  releases every buffer it acquired.
- Idle shared Metal buffers are pooled only up to 32 buffers and 1 MiB of
  idle storage. A buffer beyond that pool is released after use rather than
  retained, so a large fixture cannot grow the pool without bound.
- Each `NativeCompute` context caches at most 16 compute pipelines, keyed by
  the exact source, entry and shader-validation setting with least-recently-
  used eviction. Concurrent misses for one key share one build. A valid key
  too large to own is compiled but not cached; source validation still applies.
  This is a compute cache only. No render-pipeline cache, cross-process cache
  or persisted shader artifact is part of this contract.
- Native offscreen render passes accept at most 4096 output pixels. Blend and
  depth passes accept at most 16 draws. Indexed passes accept at most 1024
  vertices and 4096 indices, and reject index or resolved vertex ranges that
  leave their buffers. These are bounded fixture paths, not a general
  Direct3D implementation.

### Texture staging and transfer limits

- A `StagingBudget` must be a nonzero multiple of the four-byte RGBA8 texel
  size. A fresh staged upload supplies whole rows of every mip level in level
  order; an update may supply a subset and omitted levels keep their contents.
  No submission exceeds its budget. A budget smaller than one row, a missing
  level in a fresh upload, a repeated level or a row-length violation is
  rejected before GPU work starts.
- The RGBA8 texture planner rejects dimensions whose total pixel count
  overflows or exceeds its 16,384-times-16,384 structural cap. Guest-visible
  texture and software textured-draw limits are smaller and bind first.
- Native BC1 readback uses the 4096-texel compute limit. Original guest BC1
  levels also use the guest's 64-texel side limit. Native BC7 readback uses one
  word per texel at the same 4096-texel limit; BC6H returns four 32-bit words
  per texel and is therefore limited to 1024 texels per level. Compressed
  uploads keep their declared pitches and reject lengths that do not satisfy
  the pitched layout.

### Compatibility and future work

The original fixtures described in the linked contracts stay within these
bounds. A workload outside a listed bound is unsupported until a separate
interface change defines it; none of these limits is a new GPU result. The
backend identifier reported to the guest distinguishes a software frame from a
native Metal frame; a synthetic service name alone does not establish GPU
execution.

Indirect draws and dispatches are not implemented. If they are added, argument
buffers must be range-checked when recorded, and counts written by the GPU
must be checked before consumption, either by device-side predication or by a
bounded readback followed by explicit rejection. An over-budget count must not
be clamped, truncated, or allowed to launch an unbounded workload. A future
synthetic fixture should cover one in-budget GPU-written command that produces
the expected output and one over-budget count that is rejected or suppressed
before a draw or dispatch runs; no such fixture exists today. This is a future
requirement, not current behavior.

No game execution, Xbox graphics ABI, Windows driver behavior, all-device GPU
capability or independent acceptance follows from this description. Hardware
differences already recorded for BC decoding remain per-device observations.

## Native app: running an executable and the Metal HUD

`Xenora.app` runs a chosen executable only through the `xenora run` worker,
which `scripts/build-app.sh` bundles as `Contents/MacOS/xenora-cli` (not
`xenora`: the default macOS file system ignores case, so that name would be
the app's own `Xenora`). The Run action passes `run --experimental --pe
<file>`, then `--trace` when the Metal HUD is on, then `--` and the program
arguments typed in the window. The worker's separate process and 15-second
wall deadline apply exactly as on the command line, where a program has no
step limit unless `--max-steps` gives one (#448), and the app
adds no execution path of its own. The app shows the worker's exit status
(the program's own; 124 is the wall deadline, 125 any other runner or guest
failure, 2 a refused command line), the last `trace stage=` it printed, and
up to 256 KiB of each output stream. `XENORA_CLI` names another worker, for
`swift run`.

The optional guest file export takes an absolute path on the synthetic C:
drive and a new host filename chosen in the Run Program panel. The app passes
both to `--export-guest-file` before the guest arguments. The CLI exports at
most 16 MiB from a successful run and preserves any existing destination.
The Run panel shows export errors in the worker output.

To exercise this path with the original file-writing guest, build it with
`sh tests/compat_fixtures/build-guest-file-export.sh "$PWD/artifacts/app-guest-export"`,
then set `XENORA_GUEST_FILE_EXPORT_FIXTURE="$PWD/artifacts/app-guest-export/guest-file-export.exe"`
and `XENORA_CLI="$PWD/build/Xenora.app/Contents/MacOS/xenora-cli"` when running
`scripts/build-app.sh --test`.

The Metal HUD switch (View > Show Metal HUD, Shift-Command-H, or the Display
section) is off by default and is stored in the app's defaults as
`MetalHUDEnabled`. It overlays the Metal device, frame size, frame counters
and host-measured timings on fixture frames. A program run has no draw path
yet and `xenora run` takes `--metal-hud` for the embedded fixtures only, so
for a program the switch turns on tracing instead. Apple's Metal Performance
HUD cannot attach to these frames, which are read back from offscreen Metal
targets and drawn as images.

### Native app frame journal

The original guest for the app's persistent frame loop opens
`C:\xenora-app-frames.bin` on its synthetic drive. The guest keeps the file
open across frame requests and pauses, seeks back to the beginning during
teardown, checks its readback, and closes the file before confirming
completion. The host derives the expected journal from accepted frames and
the directions sampled at frame admission. A successful run requires an
exact match and no remaining runtime handles at the guest's confirmation.

The app shows the verified record count after the loop finishes or stops. C callers can
read the finalized bytes through `xenora_session_frame_loop_journal` from the
same session. Each byte represents one frame. Its low two bits identify the
column, and the other bits are `0x10` for standard mode or `0x20`, `0x24`,
and `0x28` for interactive neutral, right, and left respectively. A clean
stop before the first frame produces a valid empty journal. Active or failed
loops have no finalized journal. A short buffer receives the required size
without receiving partial contents. The journal never uses the host filesystem.

### Module file names

`GetModuleFileNameA` and `GetModuleFileNameW` answer the path the program was
started with - the same string the command line is built from - for a null
module handle or the main image base. A small buffer receives the documented
truncation form: what fits, terminated, with the capacity itself as the
answer and ERROR_INSUFFICIENT_BUFFER. A foreign module fails with
ERROR_MOD_NOT_FOUND because no library is ever loaded into the address
space as an image. This is implemented behaviour verified through the unit
tests. Nothing here was compared with Windows or with an Xbox console.

### The registry is honestly empty

Advapi32 provides `RegOpenKeyW`, `RegOpenKeyExA/W`, `RegQueryValueExA/W`
and `RegCloseKey` against the synthetic guest registry. A null or empty
subkey name reopens a predefined root and returns the same handle.
Every named subkey and value is absent and reports `ERROR_FILE_NOT_FOUND`.
The registry is independent of the host. A guest PE test verifies the
three-argument `RegOpenKeyW` entry point alongside the extended forms.

### Memory mappings and process creation

`CreateFileMappingA/W` support paging-file-backed shared memory only:
`INVALID_HANDLE_VALUE` creates an object tracked in the central handle
table, a real file fails honestly with ERROR_NOT_SUPPORTED rather than
serving content writes could not reach. `MapViewOfFile` allocates the
zero-filled view fresh pages document; views from offsets or at chosen
addresses are not modelled. `UnmapViewOfFile` releases the view.
`CreateProcessA/W` fail honestly with ERROR_NOT_SUPPORTED and zero the
process information structure, because the guest is the only process.
This is implemented behaviour verified through the unit tests. Nothing
here was compared with Windows or with an Xbox console.

## XNetworking connectivity, statistics, configuration and preferred-port queries

`xgameruntime.dll!XNetworkingGetConnectivityHint` writes the documented 16-byte `XNetworkingConnectivityHint`: three little-endian 32-bit fields followed by four one-byte boolean fields. Xenora reports `networkInitialized` as true because its bounded networking facility exists, `connectivityLevel` as `None` (1), `connectivityCost` as `Unknown` (0), and `ianaInterfaceType` as IANA `softwareLoopback` (24). The data-limit and roaming booleans are false. This is the honest state of the current machine: it has process-local loopback sockets but no external network route, DNS, proxy, TLS or Internet connectivity truth. The query must not be read as evidence that a title endpoint is reachable.

`xgameruntime.dll!XNetworkingQueryStatistics` accepts the three documented TCP queued-receive-buffer statistic type values 0, 1 and 2. Each writes exactly the documented 40-byte `XNetworkingTcpQueuedReceivedBufferUsageStatistics` structure: current, peak, total, configured-maximum-drop and any-failure-drop byte counters. Xenora has no kernel-mode TCP queued-receive-buffer allocator, so all five counters are honestly zero. These counters do not describe the process-local loopback stream FIFOs in Xenora's Winsock model and do not imply external network capability. Bytes beyond the exact 40-byte substructure are preserved, as the public union contract requires.

`xgameruntime.dll!XNetworkingQueryConfigurationSetting` accepts the three documented maximum TCP queued-receive-buffer setting values 0, 1 and 2 and writes one little-endian `uint64_t`. Zero is the exact limit of this machine rather than the documented Xbox default, because Xenora has no configurable kernel-mode TCP queued-receive-buffer allocator. `XNetworkingSetConfigurationSetting` is absent rather than pretending that a write can reshape the network implementation.

`xgameruntime.dll!XNetworkingQueryPreferredLocalUdpMultiplayerPort` writes exactly one host-endian `uint16_t` containing UDP port 3074, the documented default preferred local multiplayer port. In Xenora this is a fixed property of the process-local loopback network machine: the implementation has no external route, UPnP negotiation, NAT classification, user network-settings override or fallback decision. The value can be used for a loopback UDP bind, but it is not evidence of router configuration, external reachability or Xbox network behavior.

A null, unmapped or partially unwritable output pointer returns `HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER)` and writes no success result. Unknown statistic or configuration values return the same invalid-argument `HRESULT` without modifying the output. Registration, change callbacks, security-information queries, asynchronous preferred-port queries and configuration mutation are not implemented. This is locally verified behavior only; it has not been compared with Windows or Xbox hardware.

Sources: [XNetworkingGetConnectivityHint](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/functions/xnetworkinggetconnectivityhint), [XNetworkingConnectivityHint](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/structs/xnetworkingconnectivityhint), [XNetworkingConnectivityLevelHint](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/enums/xnetworkingconnectivitylevelhint), [XNetworkingQueryStatistics](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/functions/xnetworkingquerystatistics), [XNetworkingStatisticsType](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/enums/xnetworkingstatisticstype), [XNetworkingTcpQueuedReceivedBufferUsageStatistics](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/structs/xnetworkingtcpqueuedreceivedbufferusagestatistics), [XNetworkingQueryConfigurationSetting](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/functions/xnetworkingqueryconfigurationsetting), [XNetworkingConfigurationSetting](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/enums/xnetworkingconfigurationsetting), [XNetworkingQueryPreferredLocalUdpMultiplayerPort](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/networking/xnetworking/functions/xnetworkingquerypreferredlocaludpmultiplayerport), and [network initialization and connectivity](https://docs.xbox.com/build/console-features/networking/initialization-connectivity-networking).

## Opt-in synthetic Gaming Runtime lifecycle

`services::gaming_runtime::register_synthetic_lifecycle` registers partial
`XGameRuntimeInitialize` and `XGameRuntimeUninitialize` services separately
from standard services. This models one linked library: repeated initialize
calls succeed without adding references, and teardown releases that library.
Open GDK queue handles make teardown terminal; future initialization returns
`E_GAMERUNTIME_UNINITIALIZE_ACTIVEOBJECTS` (0x89240105).

Microsoft documents two layers: library initialization is idempotent, while
the underlying DLL counts references from libraries. Xenora does not load
that DLL, implement multi-library reference counts, or expose
InitializeWithOptions. Existing queue operations retain their separate
bounded contract. Leaked queue handles remain usable under that contract.
Concurrent initialization and teardown remain unverified. The queue lock is
held through teardown so the active-object snapshot stays consistent during
the transition. Xbox startup remains unverified.

The lifecycle unit suite builds the original Scarlett fixture with native
ARM64 tools and executes it through the normal startup API twice, checking
binding, exit status and empty output. The runtime-services suite calls bound
lifecycle and queue imports through translated guest code, checking
closed-handle recovery and terminal active-object failure. These are local
synthetic checks. Independent runtime acceptance remains pending.

Sources: [Initialize](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xgameruntimeinit/functions/xgameruntimeinitialize),
[Uninitialize](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xgameruntimeinit/functions/xgameruntimeuninitialize),
[InitializeWithOptions](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xgameruntimeinit/functions/xgameruntimeinitializewithoptions).
