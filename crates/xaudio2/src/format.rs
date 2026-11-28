// SPDX-License-Identifier: GPL-3.0-or-later

//! The wave formats a source voice accepts.
//!
//! The guest hands XAudio2 a PCMWAVEFORMAT or WAVEFORMATEX structure.
//! This module validates the header for the bounded audio model.

use crate::consts::{XAUDIO2_MAX_AUDIO_CHANNELS, XAUDIO2_MAX_SAMPLE_RATE, XAUDIO2_MIN_SAMPLE_RATE};
use crate::hresult::Error;

const PCM_TAG: u16 = 1;

/// The sample encoding of a wave format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFormat {
    /// Linear PCM with 16 bits per sample.
    Pcm16,
    /// IEEE float with 32 bits per sample.
    Float32,
}

/// The wave format of a source voice.
///
/// The fields mirror the format supplied to `IXAudio2::CreateSourceVoice`.
/// The model keeps the fields common to PCMWAVEFORMAT and WAVEFORMATEX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaveFormat {
    /// The sample encoding.
    pub format: SampleFormat,
    /// The number of channels.
    pub channels: u16,
    /// The sample rate in hertz.
    pub sample_rate: u32,
    /// The size of one frame in bytes.
    pub block_align: u16,
}

impl WaveFormat {
    /// The number of bytes a WAVEFORMATEX structure occupies on the wire.
    pub const STRUCTURE_SIZE: usize = 18;

    /// Minimum readable header for the given format tag. PCM can use the
    /// 16-byte PCMWAVEFORMAT structure, which has no `cbSize` field.
    pub const fn header_size(format_tag: u16) -> usize {
        match format_tag {
            PCM_TAG => 16,
            _ => Self::STRUCTURE_SIZE,
        }
    }

    /// Reads a PCMWAVEFORMAT or WAVEFORMATEX header from the guest bytes.
    ///
    /// The checks run in the order the public documentation implies: the
    /// format tag first, then the channel count, the sample rate, the bit
    /// depth, the block alignment and the average byte rate. A structure that
    /// is well formed but outside the modelled subset is refused with
    /// Error::NotImplemented, and a structure that contradicts itself is
    /// refused with Error::InvalidArg.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let Some(tag) = bytes.first_chunk::<2>() else {
            return Err(Error::InvalidArg("a wave format needs a format tag"));
        };
        let tag = u16::from_le_bytes(*tag);
        if bytes.len() < Self::header_size(tag) {
            return Err(Error::InvalidArg("the wave format header is incomplete"));
        }
        let channels = read_u16(bytes, 2);
        let sample_rate = read_u32(bytes, 4);
        let average_bytes = read_u32(bytes, 8);
        let block_align = read_u16(bytes, 12);
        let bits = read_u16(bytes, 14);

        // The public documentation names two tags the model supports. WAVE_FORMAT_EXTENSIBLE
        // and every compressed tag are well formed but unmodelled.
        let format = match tag {
            PCM_TAG => SampleFormat::Pcm16,
            3 => SampleFormat::Float32,
            _ => {
                return Err(Error::NotImplemented(
                    "only PCM and IEEE float wave formats are modelled",
                ));
            }
        };

        if channels == 0 || u32::from(channels) > XAUDIO2_MAX_AUDIO_CHANNELS {
            return Err(Error::InvalidArg("the channel count is out of range"));
        }
        if !(XAUDIO2_MIN_SAMPLE_RATE..=XAUDIO2_MAX_SAMPLE_RATE).contains(&sample_rate) {
            return Err(Error::InvalidArg("the sample rate is out of range"));
        }

        let bits = match format {
            SampleFormat::Pcm16 => {
                if bits == 0 || !bits.is_multiple_of(8) {
                    return Err(Error::InvalidArg(
                        "a PCM bit depth must be a nonzero multiple of 8",
                    ));
                }
                bits
            }
            SampleFormat::Float32 => {
                if bits != 32 {
                    return Err(Error::InvalidArg(
                        "an IEEE float wave format must be 32 bits",
                    ));
                }
                bits
            }
        };

        let expected_align = u32::from(channels) * u32::from(bits) / 8;
        if u32::from(block_align) != expected_align {
            return Err(Error::InvalidArg(
                "the block alignment does not match the format",
            ));
        }
        let expected_average = sample_rate
            .checked_mul(expected_align)
            .ok_or(Error::InvalidArg("the average byte rate overflows"))?;
        if average_bytes != expected_average {
            return Err(Error::InvalidArg(
                "the average byte rate does not match the format",
            ));
        }

        // The modelled subset: 16-bit PCM or 32-bit float, mono or stereo, at 44.1 or 48 kHz.
        let modelled = match format {
            SampleFormat::Pcm16 => bits == 16,
            SampleFormat::Float32 => true,
        } && (channels == 1 || channels == 2)
            && (sample_rate == 44_100 || sample_rate == 48_000);
        if !modelled {
            return Err(Error::NotImplemented(
                "only 16-bit PCM and 32-bit float, mono or stereo, at 44100 or 48000 hertz are modelled",
            ));
        }

        Ok(WaveFormat {
            format,
            channels,
            sample_rate,
            block_align,
        })
    }
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
