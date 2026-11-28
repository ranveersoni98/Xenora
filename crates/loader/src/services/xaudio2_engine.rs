// SPDX-License-Identifier: GPL-3.0-or-later

//! The IXAudio2 methods of the guest-visible engine object.
//!
//! The thirteen methods of the engine follow the order of the public
//! interface: the three methods of IUnknown, the ten methods of IXAudio2.
//! Every call that names a guest pointer checks it before the core model
//! sees it, and a call that cannot report an error writes nothing.

use super::xaudio2::{
    E_NOINTERFACE, IID_IUNKNOWN, IID_IXAUDIO2, Kind, Method, Object, fault, read_guid, read_struct,
    write_pointer,
};
use crate::cpu::{CpuState, ExitReason};
use crate::imports::Win64Args;
use crate::memory::GuestMemory;
use crate::services::ServicesState;
use xenora_xaudio2::WaveFormat;
use xenora_xaudio2::hresult::{E_NOTIMPL, E_POINTER, S_OK, XAUDIO2_E_INVALID_CALL};

/// The engine methods of IXAudio2, in the order of the public interface.
pub(crate) const ENGINE_METHODS: [(&str, Method); 13] = [
    ("IXAudio2.QueryInterface", query_interface),
    ("IXAudio2.AddRef", add_ref),
    ("IXAudio2.Release", release),
    ("IXAudio2.RegisterForCallbacks", register_for_callbacks),
    ("IXAudio2.UnregisterForCallbacks", unregister_for_callbacks),
    ("IXAudio2.CreateSourceVoice", create_source_voice),
    ("IXAudio2.CreateSubmixVoice", create_submix_voice),
    ("IXAudio2.CreateMasteringVoice", create_mastering_voice),
    ("IXAudio2.StartEngine", start_engine),
    ("IXAudio2.StopEngine", stop_engine),
    ("IXAudio2.CommitChanges", commit_changes),
    ("IXAudio2.GetPerformanceData", get_performance_data),
    ("IXAudio2.SetDebugConfiguration", set_debug_configuration),
];

/// IXAudio2::QueryInterface.
fn query_interface(
    state: &ServicesState,
    memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let this = args.rcx;
    let interface = args.rdx;
    let out = args.r8;
    if out == 0 {
        return Ok(E_POINTER as u64);
    }
    // The out-pointer is nulled before the interface is known, so a refused
    // query never leaves a pointer behind.
    if !write_pointer(memory, out, 0) {
        return Ok(E_POINTER as u64);
    }
    let Some(iid) = read_guid(memory, interface) else {
        return Ok(E_POINTER as u64);
    };
    let mut xaudio2 = state.xaudio2();
    let Some(engine) = xaudio2.engine_of(this) else {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(XAUDIO2_E_INVALID_CALL as u64);
    };
    if iid != IID_IUNKNOWN && iid != IID_IXAUDIO2 {
        return Ok(E_NOINTERFACE as u64);
    }
    let Some(object) = xaudio2.objects.get_mut(&this) else {
        return Ok(XAUDIO2_E_INVALID_CALL as u64);
    };
    object.references = object.references.saturating_add(1);
    if !write_pointer(memory, out, this) {
        object.references -= 1;
        return Ok(E_POINTER as u64);
    }
    let _ = engine;
    Ok(S_OK as u64)
}

/// IXAudio2::AddRef.
fn add_ref(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let mut xaudio2 = state.xaudio2();
    let Some(object) = xaudio2.objects.get_mut(&args.rcx) else {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(0);
    };
    if object.destroyed {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(0);
    }
    object.references = object.references.saturating_add(1);
    Ok(u64::from(object.references))
}

/// IXAudio2::Release.
fn release(
    state: &ServicesState,
    memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let mut xaudio2 = state.xaudio2();
    let Some(object) = xaudio2.objects.get_mut(&args.rcx) else {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(0);
    };
    if object.destroyed {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(0);
    }
    object.references = object.references.saturating_sub(1);
    let remaining = object.references;
    let engine = object.engine;
    if remaining == 0 {
        // The last reference tears the engine and every voice it owns down.
        let _ = xaudio2.runtime.release_engine(engine);
        xaudio2.free_objects(memory, engine);
    }
    Ok(u64::from(remaining))
}

/// IXAudio2::RegisterForCallbacks.
fn register_for_callbacks(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    _args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    state.xaudio2().diagnostics.not_implemented += 1;
    Ok(E_NOTIMPL as u64)
}

/// IXAudio2::UnregisterForCallbacks.
fn unregister_for_callbacks(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    _args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    state.xaudio2().diagnostics.silent += 1;
    Ok(0)
}

/// IXAudio2::CreateSourceVoice.
fn create_source_voice(
    state: &ServicesState,
    memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let this = args.rcx;
    let out = args.rdx;
    let format_address = args.r8;
    let flags = args.r9 as u32;
    let max_ratio = f32::from_bits(args.get(4, memory).map_err(fault)? as u32);
    let callback = args.get(5, memory).map_err(fault)?;
    let send_list = args.get(6, memory).map_err(fault)?;
    let effect_chain = args.get(7, memory).map_err(fault)?;
    if out == 0 {
        return Ok(E_POINTER as u64);
    }
    let mut xaudio2 = state.xaudio2();
    let Some(engine) = xaudio2.engine_of(this) else {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(XAUDIO2_E_INVALID_CALL as u64);
    };
    if !write_pointer(memory, out, 0) {
        xaudio2.diagnostics.pointer += 1;
        return Ok(E_POINTER as u64);
    }
    let Some(tag) = read_struct::<2>(memory, format_address).map(u16::from_le_bytes) else {
        xaudio2.diagnostics.pointer += 1;
        return Ok(E_POINTER as u64);
    };
    let mut bytes = [0; WaveFormat::STRUCTURE_SIZE];
    let header = &mut bytes[..WaveFormat::header_size(tag)];
    if memory.read_bytes(format_address, header).is_err() {
        xaudio2.diagnostics.pointer += 1;
        return Ok(E_POINTER as u64);
    }
    let format = match WaveFormat::parse(header) {
        Ok(format) => format,
        Err(error) => {
            xaudio2.diagnostics.not_implemented += 1;
            return Ok(error.hresult() as u64);
        }
    };
    let voice = match xaudio2.runtime.create_source_voice(
        engine,
        &format,
        flags,
        max_ratio,
        callback,
        send_list,
        effect_chain,
    ) {
        Ok(voice) => voice,
        Err(error) => return Ok(error.hresult() as u64),
    };
    let vtable = xaudio2.source_vtable;
    let Some(address) = xaudio2.allocate(memory, &vtable) else {
        let _ = xaudio2.runtime.destroy_voice(voice);
        return Ok(xenora_xaudio2::hresult::E_OUTOFMEMORY as u64);
    };
    xaudio2.objects.insert(
        address,
        Object {
            kind: Kind::Source,
            engine,
            voice: Some(voice),
            references: 1,
            destroyed: false,
            version: 0,
        },
    );
    if !write_pointer(memory, out, address) {
        xaudio2.objects.remove(&address);
        xaudio2.free(memory, address);
        let _ = xaudio2.runtime.destroy_voice(voice);
        xaudio2.diagnostics.pointer += 1;
        return Ok(E_POINTER as u64);
    }
    Ok(S_OK as u64)
}

/// IXAudio2::CreateSubmixVoice.
fn create_submix_voice(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    _args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    state.xaudio2().diagnostics.not_implemented += 1;
    Ok(E_NOTIMPL as u64)
}

/// IXAudio2::CreateMasteringVoice.
fn create_mastering_voice(
    state: &ServicesState,
    memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let this = args.rcx;
    let out = args.rdx;
    let channels = args.r8 as u32;
    let sample_rate = args.r9 as u32;
    let flags = args.get(4, memory).map_err(fault)? as u32;
    let device = args.get(5, memory).map_err(fault)?;
    let effect_chain = args.get(6, memory).map_err(fault)?;
    let stream_category = args.get(7, memory).map_err(fault)? as u32;
    if out == 0 {
        return Ok(E_POINTER as u64);
    }
    let mut xaudio2 = state.xaudio2();
    let Some(engine) = xaudio2.engine_of(this) else {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(XAUDIO2_E_INVALID_CALL as u64);
    };
    if !write_pointer(memory, out, 0) {
        xaudio2.diagnostics.pointer += 1;
        return Ok(E_POINTER as u64);
    }
    let voice = match xaudio2.runtime.create_mastering_voice(
        engine,
        channels,
        sample_rate,
        flags,
        device,
        effect_chain,
        stream_category,
    ) {
        Ok(voice) => voice,
        Err(error) => return Ok(error.hresult() as u64),
    };
    let vtable = xaudio2.mastering_vtable;
    let Some(address) = xaudio2.allocate(memory, &vtable) else {
        let _ = xaudio2.runtime.destroy_voice(voice);
        return Ok(xenora_xaudio2::hresult::E_OUTOFMEMORY as u64);
    };
    xaudio2.objects.insert(
        address,
        Object {
            kind: Kind::Mastering,
            engine,
            voice: Some(voice),
            references: 1,
            destroyed: false,
            version: 0,
        },
    );
    if !write_pointer(memory, out, address) {
        xaudio2.objects.remove(&address);
        xaudio2.free(memory, address);
        let _ = xaudio2.runtime.destroy_voice(voice);
        xaudio2.diagnostics.pointer += 1;
        return Ok(E_POINTER as u64);
    }
    Ok(S_OK as u64)
}

/// IXAudio2::StartEngine.
fn start_engine(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let mut xaudio2 = state.xaudio2();
    let Some(engine) = xaudio2.engine_of(args.rcx) else {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(XAUDIO2_E_INVALID_CALL as u64);
    };
    match xaudio2.runtime.start_engine(engine) {
        Ok(()) => Ok(S_OK as u64),
        Err(error) => Ok(error.hresult() as u64),
    }
}

/// IXAudio2::StopEngine.
fn stop_engine(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let mut xaudio2 = state.xaudio2();
    let Some(engine) = xaudio2.engine_of(args.rcx) else {
        xaudio2.diagnostics.invalid_call += 1;
        return Ok(0);
    };
    let _ = xaudio2.runtime.stop_engine(engine);
    Ok(0)
}

/// IXAudio2::CommitChanges.
fn commit_changes(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    let operation_set = args.rdx as u32;
    if operation_set != 0 {
        state.xaudio2().diagnostics.not_implemented += 1;
        return Ok(E_NOTIMPL as u64);
    }
    Ok(S_OK as u64)
}

/// IXAudio2::GetPerformanceData.
fn get_performance_data(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    _args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    state.xaudio2().diagnostics.silent += 1;
    Ok(0)
}

/// IXAudio2::SetDebugConfiguration.
fn set_debug_configuration(
    state: &ServicesState,
    _memory: &mut GuestMemory,
    _args: &Win64Args,
    _cpu: &CpuState,
) -> Result<u64, ExitReason> {
    state.xaudio2().diagnostics.silent += 1;
    Ok(0)
}
