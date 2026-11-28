// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-boundary checks for the bounded XAudio2 core (#888).
//!
//! The expected values come from the public XAudio2 documentation and the
//! Windows x64 layout rules (natural alignment, 8-byte pointers), not from the
//! implementation. Where the public documentation is silent, the test names
//! the Xenora choice that `docs/runtime/xaudio2.md` records.

use xenora_xaudio2::consts::*;
use xenora_xaudio2::hresult::*;
use xenora_xaudio2::{BufferDesc, Error, Event, Runtime, SampleFormat, VoiceState, WaveFormat};

/// A WAVEFORMATEX as the guest lays it out: 18 packed little-endian bytes.
fn wave(tag: u16, channels: u16, rate: u32, avg: u32, align: u16, bits: u16) -> [u8; 18] {
    let mut b = [0u8; 18];
    b[0..2].copy_from_slice(&tag.to_le_bytes());
    b[2..4].copy_from_slice(&channels.to_le_bytes());
    b[4..8].copy_from_slice(&rate.to_le_bytes());
    b[8..12].copy_from_slice(&avg.to_le_bytes());
    b[12..14].copy_from_slice(&align.to_le_bytes());
    b[14..16].copy_from_slice(&bits.to_le_bytes());
    b
}

fn pcm16(channels: u16, rate: u32) -> [u8; 18] {
    let align = channels * 2;
    wave(1, channels, rate, rate * u32::from(align), align, 16)
}

fn float32(channels: u16, rate: u32) -> [u8; 18] {
    let align = channels * 4;
    wave(3, channels, rate, rate * u32::from(align), align, 32)
}

/// An XAUDIO2_BUFFER as the guest lays it out on x64 (48 bytes).
#[allow(clippy::too_many_arguments)]
fn buffer_bytes(
    flags: u32,
    audio_bytes: u32,
    data: u64,
    play: (u32, u32),
    looping: (u32, u32, u32),
    context: u64,
) -> [u8; 44] {
    // xaudio2.h packs its structures to one byte: no padding before pContext.
    let mut b = [0u8; 44];
    b[0..4].copy_from_slice(&flags.to_le_bytes());
    b[4..8].copy_from_slice(&audio_bytes.to_le_bytes());
    b[8..16].copy_from_slice(&data.to_le_bytes());
    b[16..20].copy_from_slice(&play.0.to_le_bytes());
    b[20..24].copy_from_slice(&play.1.to_le_bytes());
    b[24..28].copy_from_slice(&looping.0.to_le_bytes());
    b[28..32].copy_from_slice(&looping.1.to_le_bytes());
    b[32..36].copy_from_slice(&looping.2.to_le_bytes());
    b[36..44].copy_from_slice(&context.to_le_bytes());
    b
}

fn buffer(
    audio_bytes: u32,
    play: (u32, u32),
    looping: (u32, u32, u32),
    context: u64,
) -> BufferDesc {
    BufferDesc::parse(&buffer_bytes(
        0,
        audio_bytes,
        0x1_0000,
        play,
        looping,
        context,
    ))
}

/// A started stereo PCM16 48 kHz source voice on a fresh engine with a
/// default mastering voice. One frame is 4 bytes.
fn started_voice() -> (Runtime, xenora_xaudio2::VoiceId) {
    let mut rt = Runtime::new();
    let engine = rt.create_engine(0, XAUDIO2_DEFAULT_PROCESSOR).unwrap();
    rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    let format = WaveFormat::parse(&pcm16(2, 48_000)).unwrap();
    let voice = rt
        .create_source_voice(engine, &format, 0, XAUDIO2_DEFAULT_FREQ_RATIO, 0, 0, 0)
        .unwrap();
    rt.start(voice, 0, XAUDIO2_COMMIT_NOW).unwrap();
    (rt, voice)
}

#[test]
fn public_constants_match_the_documentation() {
    assert_eq!(S_OK, 0);
    assert_eq!(E_INVALIDARG, 0x8007_0057);
    assert_eq!(E_POINTER, 0x8000_4003);
    assert_eq!(E_NOTIMPL, 0x8000_4001);
    assert_eq!(E_OUTOFMEMORY, 0x8007_000E);
    assert_eq!(XAUDIO2_E_INVALID_CALL, 0x8896_0001);
    assert_eq!(XAUDIO2_MAX_BUFFER_BYTES, 0x8000_0000);
    assert_eq!(XAUDIO2_MAX_QUEUED_BUFFERS, 64);
    assert_eq!(XAUDIO2_MAX_AUDIO_CHANNELS, 64);
    assert_eq!(XAUDIO2_MIN_SAMPLE_RATE, 1_000);
    assert_eq!(XAUDIO2_MAX_SAMPLE_RATE, 200_000);
    assert_eq!(XAUDIO2_MAX_VOLUME_LEVEL, 16_777_216.0);
    assert_eq!(XAUDIO2_MIN_FREQ_RATIO, 1.0 / 1024.0);
    assert_eq!(XAUDIO2_MAX_FREQ_RATIO, 1024.0);
    assert_eq!(XAUDIO2_DEFAULT_FREQ_RATIO, 2.0);
    assert_eq!(XAUDIO2_MAX_LOOP_COUNT, 254);
    assert_eq!(XAUDIO2_LOOP_INFINITE, 255);
    assert_eq!(XAUDIO2_NO_LOOP_REGION, 0);
    assert_eq!(XAUDIO2_END_OF_STREAM, 0x40);
    assert_eq!(XAUDIO2_PLAY_TAILS, 0x20);
    assert_eq!(XAUDIO2_VOICE_NOSAMPLESPLAYED, 0x100);
    assert_eq!(XAUDIO2_COMMIT_NOW, 0);
    assert_eq!(XAUDIO2_DEFAULT_PROCESSOR, 1);
    assert_eq!(XAUDIO2_QUANTUM_DENOMINATOR, 100);
}

#[test]
fn errors_map_to_their_hresults() {
    assert_eq!(Error::InvalidArg("x").hresult(), E_INVALIDARG);
    assert_eq!(Error::InvalidCall("x").hresult(), XAUDIO2_E_INVALID_CALL);
    assert_eq!(Error::NotImplemented("x").hresult(), E_NOTIMPL);
    assert_eq!(Error::OutOfMemory("x").hresult(), E_OUTOFMEMORY);
    assert_eq!(Error::Pointer("x").hresult(), E_POINTER);
}

#[test]
fn buffer_desc_reads_the_packed_x64_layout() {
    let bytes = buffer_bytes(
        XAUDIO2_END_OF_STREAM,
        0x1234,
        0x1122_3344_5566_7788,
        (5, 6),
        (7, 8, 9),
        0xAABB_CCDD_EEFF_0011,
    );
    assert_eq!(BufferDesc::SIZE, 44);
    let desc = BufferDesc::parse(&bytes);
    assert_eq!(
        desc,
        BufferDesc {
            flags: XAUDIO2_END_OF_STREAM,
            audio_bytes: 0x1234,
            audio_data: 0x1122_3344_5566_7788,
            play_begin: 5,
            play_length: 6,
            loop_begin: 7,
            loop_length: 8,
            loop_count: 9,
            context: 0xAABB_CCDD_EEFF_0011,
        }
    );
}

#[test]
fn voice_state_writes_the_packed_x64_layout() {
    assert_eq!(VoiceState::SIZE, 20);
    let state = VoiceState {
        current_buffer_context: 0x0102_0304_0506_0708,
        buffers_queued: 0x0A0B_0C0D,
        samples_played: 0x1112_1314_1516_1718,
    };
    let b = state.to_bytes();
    assert_eq!(&b[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&b[8..12], &0x0A0B_0C0Du32.to_le_bytes());
    assert_eq!(&b[12..20], &0x1112_1314_1516_1718u64.to_le_bytes());
}

#[test]
fn supported_wave_formats_parse() {
    for channels in [1u16, 2] {
        for rate in [44_100u32, 48_000] {
            let f = WaveFormat::parse(&pcm16(channels, rate)).unwrap();
            assert_eq!(
                (f.format, f.channels, f.sample_rate, f.block_align),
                (SampleFormat::Pcm16, channels, rate, channels * 2)
            );
            let f = WaveFormat::parse(&float32(channels, rate)).unwrap();
            assert_eq!(
                (f.format, f.channels, f.sample_rate, f.block_align),
                (SampleFormat::Float32, channels, rate, channels * 4)
            );
        }
    }
    // PCM ignores cbSize (WAVEFORMATEX documentation).
    let mut b = pcm16(2, 48_000);
    b[16..18].copy_from_slice(&22u16.to_le_bytes());
    WaveFormat::parse(&b).unwrap();
}

#[test]
fn pcm_does_not_require_the_waveformatex_extension_size() {
    let pcm = pcm16(2, 48_000);
    let expected = WaveFormat::parse(&pcm).unwrap();
    for size in [16, 17] {
        assert_eq!(WaveFormat::parse(&pcm[..size]).unwrap(), expected);
    }
    assert!(matches!(
        WaveFormat::parse(&pcm[..15]),
        Err(Error::InvalidArg(_))
    ));

    let float = float32(2, 48_000);
    assert!(matches!(
        WaveFormat::parse(&float[..17]),
        Err(Error::InvalidArg(_))
    ));
    assert!(WaveFormat::parse(&float).is_ok());
}

#[test]
fn malformed_wave_formats_are_invalid_arguments() {
    let bad: [(&str, [u8; 18]); 9] = [
        ("zero channels", wave(1, 0, 48_000, 0, 0, 16)),
        (
            "too many channels",
            wave(1, 65, 48_000, 48_000 * 130, 130, 16),
        ),
        ("rate below minimum", wave(1, 2, 999, 999 * 4, 4, 16)),
        (
            "rate above maximum",
            wave(1, 2, 200_001, 200_001 * 4, 4, 16),
        ),
        ("block align", wave(1, 2, 48_000, 48_000 * 4, 3, 16)),
        ("byte rate", wave(1, 2, 48_000, 48_000 * 4 + 1, 4, 16)),
        ("pcm bits 0", wave(1, 2, 48_000, 0, 0, 0)),
        ("pcm bits 12", wave(1, 2, 48_000, 48_000 * 3, 3, 12)),
        ("float bits 16", wave(3, 2, 48_000, 48_000 * 4, 4, 16)),
    ];
    for (name, bytes) in bad {
        assert!(
            matches!(WaveFormat::parse(&bytes), Err(Error::InvalidArg(_))),
            "{name}: {:?}",
            WaveFormat::parse(&bytes)
        );
    }
    assert!(matches!(
        WaveFormat::parse(&pcm16(2, 48_000)[..1]),
        Err(Error::InvalidArg(_))
    ));
}

#[test]
fn valid_but_unsupported_formats_are_not_implemented() {
    let unsupported: [(&str, [u8; 18]); 6] = [
        ("8-bit PCM", wave(1, 2, 48_000, 48_000 * 2, 2, 8)),
        ("24-bit PCM", wave(1, 2, 48_000, 48_000 * 6, 6, 24)),
        ("six channels", wave(1, 6, 48_000, 48_000 * 12, 12, 16)),
        ("22.05 kHz", pcm16(2, 22_050)),
        ("ADPCM tag", wave(2, 2, 48_000, 48_000 * 4, 4, 16)),
        (
            "WAVE_FORMAT_EXTENSIBLE",
            wave(0xFFFE, 2, 48_000, 48_000 * 4, 4, 16),
        ),
    ];
    for (name, bytes) in unsupported {
        assert!(
            matches!(WaveFormat::parse(&bytes), Err(Error::NotImplemented(_))),
            "{name}: {:?}",
            WaveFormat::parse(&bytes)
        );
    }
}

#[test]
fn engine_and_mastering_voice_creation_rules() {
    let mut rt = Runtime::new();
    assert!(
        matches!(rt.create_engine(1, 1), Err(Error::NotImplemented(_))),
        "debug engine flag"
    );
    let engine = rt.create_engine(0, XAUDIO2_DEFAULT_PROCESSOR).unwrap();
    let format = WaveFormat::parse(&pcm16(2, 48_000)).unwrap();
    // A source voice needs a mastering voice to send to.
    assert!(matches!(
        rt.create_source_voice(engine, &format, 0, 2.0, 0, 0, 0),
        Err(Error::InvalidCall(_))
    ));
    for (args, expect_ok) in [
        ((3u32, 48_000u32, 0u32, 0u64, 0u64), false), // three channels
        ((2, 22_050, 0, 0, 0), false),                // unsupported rate
        ((2, 48_000, 1, 0, 0), false),                // flags
        ((2, 48_000, 0, 0x1000, 0), false),           // device id string
        ((2, 48_000, 0, 0, 0x1000), false),           // effect chain
    ] {
        let (channels, rate, flags, device, effects) = args;
        let result = rt.create_mastering_voice(engine, channels, rate, flags, device, effects, 6);
        assert_eq!(result.is_ok(), expect_ok, "{args:?}: {result:?}");
        assert!(matches!(
            result,
            Err(Error::NotImplemented(_)) | Err(Error::InvalidArg(_))
        ));
    }
    let master = rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    // Defaults recorded by Xenora: 2 channels at 48 kHz.
    assert_eq!(rt.mastering_format(master).unwrap(), (2, 48_000));
    // Only one mastering voice may exist at a time.
    assert!(matches!(
        rt.create_mastering_voice(engine, 2, 44_100, 0, 0, 0, 6),
        Err(Error::InvalidCall(_))
    ));
    rt.destroy_voice(master).unwrap();
    let master = rt
        .create_mastering_voice(engine, 1, 44_100, 0, 0, 0, 6)
        .unwrap();
    assert_eq!(rt.mastering_format(master).unwrap(), (1, 44_100));
}

#[test]
fn source_voice_creation_validates_every_argument() {
    let mut rt = Runtime::new();
    let engine = rt.create_engine(0, XAUDIO2_DEFAULT_PROCESSOR).unwrap();
    rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    let f = WaveFormat::parse(&float32(1, 44_100)).unwrap();
    assert!(
        matches!(
            rt.create_source_voice(engine, &f, 0x2, 2.0, 0, 0, 0),
            Err(Error::NotImplemented(_))
        ),
        "flags"
    );
    assert!(
        matches!(
            rt.create_source_voice(engine, &f, 0, 2.0, 0x10, 0, 0),
            Err(Error::NotImplemented(_))
        ),
        "callback until #888 PR 3"
    );
    assert!(
        matches!(
            rt.create_source_voice(engine, &f, 0, 2.0, 0, 0x10, 0),
            Err(Error::NotImplemented(_))
        ),
        "send list"
    );
    assert!(
        matches!(
            rt.create_source_voice(engine, &f, 0, 2.0, 0, 0, 0x10),
            Err(Error::NotImplemented(_))
        ),
        "effect chain"
    );
    for ratio in [0.0f32, -1.0, 1.0 / 2048.0, 1024.5, f32::NAN, f32::INFINITY] {
        assert!(
            matches!(
                rt.create_source_voice(engine, &f, 0, ratio, 0, 0, 0),
                Err(Error::InvalidArg(_))
            ),
            "max ratio {ratio}"
        );
    }
    for ratio in [XAUDIO2_MIN_FREQ_RATIO, 1.0, XAUDIO2_MAX_FREQ_RATIO] {
        rt.create_source_voice(engine, &f, 0, ratio, 0, 0, 0)
            .unwrap();
    }
}

#[test]
fn stale_and_wrong_kind_handles_are_invalid_calls() {
    let (mut rt, voice) = started_voice();
    let d = buffer(400, (0, 0), (0, 0, 0), 1);
    rt.destroy_voice(voice).unwrap();
    for result in [
        rt.submit_source_buffer(voice, &d, 0),
        rt.start(voice, 0, 0),
        rt.stop(voice, 0, 0),
        rt.set_volume(voice, 0.5, 0),
        rt.set_frequency_ratio(voice, 1.0, 0),
        rt.destroy_voice(voice),
    ] {
        assert!(matches!(result, Err(Error::InvalidCall(_))), "{result:?}");
    }
    assert!(matches!(rt.state(voice, 0), Err(Error::InvalidCall(_))));
    assert!(matches!(rt.consume(voice, 1), Err(Error::InvalidCall(_))));
    assert!(matches!(
        rt.flush_source_buffers(voice),
        Err(Error::InvalidCall(_))
    ));
    // A new voice in the freed slot is a different handle.
    let engine = rt.create_engine(0, 1).unwrap();
    rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    let format = WaveFormat::parse(&pcm16(2, 48_000)).unwrap();
    let new_voice = rt
        .create_source_voice(engine, &format, 0, 2.0, 0, 0, 0)
        .unwrap();
    assert_ne!(new_voice, voice);
    assert!(matches!(rt.state(voice, 0), Err(Error::InvalidCall(_))));
    rt.state(new_voice, 0).unwrap();
}

#[test]
fn source_operations_on_the_mastering_voice_are_invalid_calls() {
    let mut rt = Runtime::new();
    let engine = rt.create_engine(0, 1).unwrap();
    let master = rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    let d = buffer(400, (0, 0), (0, 0, 0), 1);
    assert!(matches!(
        rt.submit_source_buffer(master, &d, 0),
        Err(Error::InvalidCall(_))
    ));
    assert!(matches!(rt.start(master, 0, 0), Err(Error::InvalidCall(_))));
    assert!(matches!(rt.state(master, 0), Err(Error::InvalidCall(_))));
    assert!(matches!(
        rt.set_frequency_ratio(master, 1.0, 0),
        Err(Error::InvalidCall(_))
    ));
    // Volume applies to every voice, the mastering voice included.
    rt.set_volume(master, 0.25, 0).unwrap();
    assert_eq!(rt.volume(master).unwrap(), 0.25);
}

#[test]
fn destroying_the_mastering_voice_with_live_sources_is_refused() {
    let mut rt = Runtime::new();
    let engine = rt.create_engine(0, 1).unwrap();
    let master = rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    let format = WaveFormat::parse(&pcm16(2, 48_000)).unwrap();
    let source = rt
        .create_source_voice(engine, &format, 0, 2.0, 0, 0, 0)
        .unwrap();
    assert!(matches!(
        rt.destroy_voice(master),
        Err(Error::InvalidCall(_))
    ));
    rt.destroy_voice(source).unwrap();
    rt.destroy_voice(master).unwrap();
}

/// A named submission, and the error it must produce.
type SubmitCase = (&'static str, BufferDesc, fn(&Error) -> bool);

#[test]
fn submit_validates_the_buffer_against_the_voice_format() {
    let (mut rt, voice) = started_voice(); // 4-byte frames, 100 frames below
    let cases: [SubmitCase; 12] = [
        ("zero bytes", buffer(0, (0, 0), (0, 0, 0), 1), |e| {
            matches!(e, Error::InvalidArg(_))
        }),
        ("partial frame", buffer(402, (0, 0), (0, 0, 0), 1), |e| {
            matches!(e, Error::InvalidArg(_))
        }),
        (
            "play beyond end",
            buffer(400, (90, 11), (0, 0, 0), 1),
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "whole buffer needs begin 0",
            buffer(400, (5, 0), (0, 0, 0), 1),
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "loop region without count",
            buffer(400, (0, 0), (10, 10, 0), 1),
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "loop count above max",
            buffer(400, (0, 0), (0, 0, 256), 1),
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "loop beyond play end",
            buffer(400, (0, 50), (40, 20, 1), 1),
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "loop starts at play end",
            buffer(400, (0, 50), (50, 1, 1), 1),
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "loop ends before play begin",
            buffer(400, (20, 50), (0, 20, 1), 1),
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "unknown flag",
            BufferDesc {
                flags: 0x1,
                ..buffer(400, (0, 0), (0, 0, 0), 1)
            },
            |e| matches!(e, Error::InvalidArg(_)),
        ),
        (
            "null data",
            BufferDesc {
                audio_data: 0,
                ..buffer(400, (0, 0), (0, 0, 0), 1)
            },
            |e| matches!(e, Error::Pointer(_)),
        ),
        (
            "address overflow",
            BufferDesc {
                audio_data: u64::MAX - 100,
                ..buffer(400, (0, 0), (0, 0, 0), 1)
            },
            |e| matches!(e, Error::InvalidArg(_)),
        ),
    ];
    for (name, desc, expected) in cases {
        let result = rt.submit_source_buffer(voice, &desc, 0);
        assert!(result.as_ref().is_err_and(expected), "{name}: {result:?}");
    }
    assert!(
        matches!(
            rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), 1), 0x1000),
            Err(Error::NotImplemented(_))
        ),
        "WMA buffer"
    );
    // Nothing invalid reached the queue.
    assert_eq!(rt.state(voice, 0).unwrap().buffers_queued, 0);
    // A loop region may begin before the play region if it ends inside it.
    rt.submit_source_buffer(voice, &buffer(400, (20, 50), (10, 30, 1), 1), 0)
        .unwrap();
}

#[test]
fn the_queue_holds_at_most_the_documented_buffer_count() {
    let (mut rt, voice) = started_voice();
    for i in 0..XAUDIO2_MAX_QUEUED_BUFFERS {
        rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), u64::from(i)), 0)
            .unwrap();
    }
    assert!(matches!(
        rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), 99), 0),
        Err(Error::InvalidCall(_))
    ));
    assert_eq!(
        rt.state(voice, 0).unwrap().buffers_queued,
        XAUDIO2_MAX_QUEUED_BUFFERS
    );
}

#[test]
fn consumption_plays_buffers_in_order_and_reports_state() {
    let (mut rt, voice) = started_voice();
    rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), 0xA), 0)
        .unwrap();
    rt.submit_source_buffer(voice, &buffer(400, (10, 20), (0, 0, 0), 0xB), 0)
        .unwrap();
    let s = rt.state(voice, 0).unwrap();
    assert_eq!(
        (s.current_buffer_context, s.buffers_queued, s.samples_played),
        (0xA, 2, 0)
    );

    assert_eq!(
        rt.consume(voice, 60).unwrap(),
        vec![Event::BufferStart { context: 0xA }]
    );
    let s = rt.state(voice, 0).unwrap();
    assert_eq!(
        (s.current_buffer_context, s.buffers_queued, s.samples_played),
        (0xA, 2, 60)
    );
    // 40 frames finish A, then the 20-frame play region of B, then 15 spare.
    assert_eq!(
        rt.consume(voice, 75).unwrap(),
        vec![
            Event::BufferEnd { context: 0xA },
            Event::BufferStart { context: 0xB },
            Event::BufferEnd { context: 0xB },
        ]
    );
    let s = rt.state(voice, 0).unwrap();
    assert_eq!(
        (s.current_buffer_context, s.buffers_queued, s.samples_played),
        (0, 0, 120)
    );
    assert_eq!(rt.consume(voice, 0).unwrap(), vec![]);
    // NOSAMPLESPLAYED leaves the counter at zero.
    assert_eq!(
        rt.state(voice, XAUDIO2_VOICE_NOSAMPLESPLAYED)
            .unwrap()
            .samples_played,
        0
    );
    assert!(matches!(rt.state(voice, 0x1), Err(Error::InvalidArg(_))));
}

#[test]
fn a_stopped_voice_does_not_advance_and_resumes_where_it_stopped() {
    let (mut rt, voice) = started_voice();
    rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), 7), 0)
        .unwrap();
    rt.consume(voice, 30).unwrap();
    rt.stop(voice, 0, 0).unwrap();
    rt.stop(voice, XAUDIO2_PLAY_TAILS, 0).unwrap(); // repeated stop is harmless
    assert_eq!(rt.consume(voice, 1_000).unwrap(), vec![]);
    assert_eq!(rt.state(voice, 0).unwrap().samples_played, 30);
    rt.start(voice, 0, 0).unwrap();
    rt.start(voice, 0, 0).unwrap(); // repeated start is harmless
    assert_eq!(
        rt.consume(voice, 70).unwrap(),
        vec![Event::BufferEnd { context: 7 }]
    );
    // Xenora choice: Stop/Start do not reset SamplesPlayed.
    assert_eq!(rt.state(voice, 0).unwrap().samples_played, 100);
    assert!(matches!(rt.start(voice, 0x1, 0), Err(Error::InvalidArg(_))));
    assert!(matches!(rt.stop(voice, 0x1, 0), Err(Error::InvalidArg(_))));
    assert!(
        matches!(rt.start(voice, 0, 5), Err(Error::NotImplemented(_))),
        "operation sets"
    );
}

#[test]
fn a_buffer_submitted_to_a_stopped_voice_waits_for_start() {
    let mut rt = Runtime::new();
    let engine = rt.create_engine(0, 1).unwrap();
    rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    let format = WaveFormat::parse(&pcm16(2, 48_000)).unwrap();
    let voice = rt
        .create_source_voice(engine, &format, 0, 2.0, 0, 0, 0)
        .unwrap();
    rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), 3), 0)
        .unwrap();
    assert_eq!(rt.consume(voice, 100).unwrap(), vec![]);
    rt.start(voice, 0, 0).unwrap();
    assert_eq!(
        rt.consume(voice, 100).unwrap(),
        vec![
            Event::BufferStart { context: 3 },
            Event::BufferEnd { context: 3 }
        ]
    );
}

#[test]
fn finite_loops_repeat_the_loop_region_then_finish_the_play_region() {
    let (mut rt, voice) = started_voice();
    // Play 0..100, loop back over 20..50 twice: 50 + 30 + 80 = 160 frames.
    rt.submit_source_buffer(voice, &buffer(400, (0, 0), (20, 30, 2), 9), 0)
        .unwrap();
    assert_eq!(
        rt.consume(voice, 50).unwrap(),
        vec![
            Event::BufferStart { context: 9 },
            Event::LoopEnd { context: 9 },
        ]
    );
    assert_eq!(
        rt.consume(voice, 30).unwrap(),
        vec![Event::LoopEnd { context: 9 }]
    );
    assert_eq!(rt.consume(voice, 79).unwrap(), vec![]);
    assert_eq!(
        rt.consume(voice, 1).unwrap(),
        vec![Event::BufferEnd { context: 9 }]
    );
    assert_eq!(rt.state(voice, 0).unwrap().samples_played, 160);
}

#[test]
fn loop_length_zero_loops_the_whole_play_region() {
    let (mut rt, voice) = started_voice();
    // Xenora reading of "a loop length of zero loops the entire sample": the
    // loop region runs from LoopBegin to the end of the play region.
    rt.submit_source_buffer(voice, &buffer(400, (10, 40), (10, 0, 1), 4), 0)
        .unwrap();
    // Play 10..50 once, loop back once over 10..50: 80 frames.
    let events = rt.consume(voice, 80).unwrap();
    assert_eq!(
        events,
        vec![
            Event::BufferStart { context: 4 },
            Event::LoopEnd { context: 4 },
            Event::BufferEnd { context: 4 },
        ]
    );
}

#[test]
fn an_infinite_loop_never_ends_by_itself() {
    let (mut rt, voice) = started_voice();
    rt.submit_source_buffer(
        voice,
        &buffer(400, (0, 0), (0, 100, XAUDIO2_LOOP_INFINITE), 5),
        0,
    )
    .unwrap();
    let events = rt.consume(voice, 100 * 300 + 7).unwrap();
    assert_eq!(events.first(), Some(&Event::BufferStart { context: 5 }));
    assert_eq!(
        events
            .iter()
            .filter(|e| **e == Event::LoopEnd { context: 5 })
            .count(),
        300
    );
    assert!(!events.contains(&Event::BufferEnd { context: 5 }));
    assert_eq!(rt.state(voice, 0).unwrap().buffers_queued, 1);
}

#[test]
fn end_of_stream_signals_the_stream_end_and_resets_samples_played() {
    let (mut rt, voice) = started_voice();
    let eos = BufferDesc {
        flags: XAUDIO2_END_OF_STREAM,
        ..buffer(400, (0, 0), (0, 0, 0), 2)
    };
    rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), 1), 0)
        .unwrap();
    rt.submit_source_buffer(voice, &eos, 0).unwrap();
    rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), 3), 0)
        .unwrap();
    let events = rt.consume(voice, 210).unwrap();
    assert_eq!(
        events,
        vec![
            Event::BufferStart { context: 1 },
            Event::BufferEnd { context: 1 },
            Event::BufferStart { context: 2 },
            Event::BufferEnd { context: 2 },
            Event::StreamEnd,
            Event::BufferStart { context: 3 },
        ]
    );
    // The counter restarts with the next stream (public SamplesPlayed text).
    assert_eq!(rt.state(voice, 0).unwrap().samples_played, 10);
}

#[test]
fn flush_on_a_started_voice_keeps_the_playing_buffer() {
    let (mut rt, voice) = started_voice();
    for context in 1..=3 {
        rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), context), 0)
            .unwrap();
    }
    rt.consume(voice, 10).unwrap();
    assert_eq!(
        rt.flush_source_buffers(voice).unwrap(),
        vec![
            Event::BufferEnd { context: 2 },
            Event::BufferEnd { context: 3 }
        ]
    );
    let s = rt.state(voice, 0).unwrap();
    assert_eq!((s.current_buffer_context, s.buffers_queued), (1, 1));
}

#[test]
fn flush_on_a_stopped_voice_removes_every_buffer() {
    let (mut rt, voice) = started_voice();
    for context in 1..=2 {
        rt.submit_source_buffer(voice, &buffer(400, (0, 0), (0, 0, 0), context), 0)
            .unwrap();
    }
    rt.consume(voice, 10).unwrap();
    rt.stop(voice, 0, 0).unwrap();
    assert_eq!(
        rt.flush_source_buffers(voice).unwrap(),
        vec![
            Event::BufferEnd { context: 1 },
            Event::BufferEnd { context: 2 }
        ]
    );
    let s = rt.state(voice, 0).unwrap();
    assert_eq!((s.current_buffer_context, s.buffers_queued), (0, 0));
}

#[test]
fn volume_and_frequency_ratio_are_bounded() {
    let (mut rt, voice) = started_voice();
    assert_eq!(rt.volume(voice).unwrap(), 1.0);
    assert_eq!(rt.frequency_ratio(voice).unwrap(), 1.0);
    for v in [
        0.0f32,
        -1.0,
        0.5,
        XAUDIO2_MAX_VOLUME_LEVEL,
        -XAUDIO2_MAX_VOLUME_LEVEL,
    ] {
        rt.set_volume(voice, v, 0).unwrap();
        assert_eq!(rt.volume(voice).unwrap(), v);
    }
    for v in [f32::NAN, f32::INFINITY, XAUDIO2_MAX_VOLUME_LEVEL * 2.0] {
        assert!(
            matches!(rt.set_volume(voice, v, 0), Err(Error::InvalidArg(_))),
            "volume {v}"
        );
    }
    // The voice was created with a maximum ratio of 2.0.
    for r in [XAUDIO2_MIN_FREQ_RATIO, 0.5, 2.0] {
        rt.set_frequency_ratio(voice, r, 0).unwrap();
        assert_eq!(rt.frequency_ratio(voice).unwrap(), r);
    }
    for r in [0.0f32, 2.001, f32::NAN, -1.0] {
        assert!(
            matches!(
                rt.set_frequency_ratio(voice, r, 0),
                Err(Error::InvalidArg(_))
            ),
            "ratio {r}"
        );
    }
    assert!(matches!(
        rt.set_volume(voice, 1.0, 9),
        Err(Error::NotImplemented(_))
    ));
}

#[test]
fn source_sample_rate_requires_an_empty_queue_and_stays_in_range() {
    let (mut rt, voice) = started_voice();
    assert_eq!(rt.voice_format(voice).unwrap(), (2, 48_000));

    for rate in [1_000, 22_050, 44_100, 200_000] {
        rt.set_source_sample_rate(voice, rate).unwrap();
        assert_eq!(rt.voice_format(voice).unwrap(), (2, rate));
    }
    for rate in [0, 999, 200_001] {
        assert!(
            matches!(
                rt.set_source_sample_rate(voice, rate),
                Err(Error::InvalidArg(_))
            ),
            "rate {rate}"
        );
        assert_eq!(rt.voice_format(voice).unwrap(), (2, 200_000));
    }

    rt.submit_source_buffer(voice, &buffer(4, (0, 0), (0, 0, 0), 1), 0)
        .unwrap();
    assert!(matches!(
        rt.set_source_sample_rate(voice, 48_000),
        Err(Error::InvalidCall(_))
    ));
    assert_eq!(rt.voice_format(voice).unwrap(), (2, 200_000));

    rt.stop(voice, 0, 0).unwrap();
    rt.flush_source_buffers(voice).unwrap();
    rt.set_source_sample_rate(voice, 48_000).unwrap();
    assert_eq!(rt.voice_format(voice).unwrap(), (2, 48_000));
}

#[test]
fn releasing_the_engine_invalidates_its_voices() {
    let (mut rt, voice) = started_voice();
    let engine = rt.engine_of(voice).unwrap();
    rt.release_engine(engine).unwrap();
    assert!(matches!(rt.state(voice, 0), Err(Error::InvalidCall(_))));
    assert!(matches!(
        rt.release_engine(engine),
        Err(Error::InvalidCall(_))
    ));
}

#[test]
fn repeated_initialization_and_teardown_leaks_nothing() {
    let mut rt = Runtime::new();
    for round in 0..500u64 {
        let engine = rt.create_engine(0, 1).unwrap();
        rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
        let format = WaveFormat::parse(&float32(2, 44_100)).unwrap();
        let voice = rt
            .create_source_voice(engine, &format, 0, 2.0, 0, 0, 0)
            .unwrap();
        rt.submit_source_buffer(voice, &buffer(800, (0, 0), (0, 0, 0), round), 0)
            .unwrap();
        let d = rt.diagnostics();
        assert_eq!(
            (
                d.engines,
                d.mastering_voices,
                d.source_voices,
                d.queued_buffers,
                d.queued_bytes
            ),
            (1, 1, 1, 1, 800)
        );
        if round % 2 == 0 {
            rt.release_engine(engine).unwrap(); // tears down voices with it
        } else {
            rt.destroy_voice(voice).unwrap();
            rt.release_engine(engine).unwrap();
        }
        let d = rt.diagnostics();
        assert_eq!(
            (
                d.engines,
                d.mastering_voices,
                d.source_voices,
                d.queued_buffers,
                d.queued_bytes
            ),
            (0, 0, 0, 0, 0)
        );
    }
}

#[test]
fn engine_and_voice_counts_are_bounded() {
    let mut rt = Runtime::new();
    let engines: Vec<_> = (0..xenora_xaudio2::MAX_ENGINES)
        .map(|_| rt.create_engine(0, 1).unwrap())
        .collect();
    assert!(matches!(rt.create_engine(0, 1), Err(Error::OutOfMemory(_))));
    let engine = engines[0];
    rt.create_mastering_voice(engine, 0, 0, 0, 0, 0, 6).unwrap();
    let format = WaveFormat::parse(&pcm16(1, 48_000)).unwrap();
    for _ in 0..xenora_xaudio2::MAX_SOURCE_VOICES {
        rt.create_source_voice(engine, &format, 0, 2.0, 0, 0, 0)
            .unwrap();
    }
    assert!(matches!(
        rt.create_source_voice(engine, &format, 0, 2.0, 0, 0, 0),
        Err(Error::OutOfMemory(_))
    ));
}
