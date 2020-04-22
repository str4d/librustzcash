//! Core traits and structs for Transparent Zcash Extensions.

use byteorder::{ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::fmt;
use std::io::{self, Read, Write};

use crate::serialize::{CompactSize, Vector};

pub trait ToPayload {
    /// Returns a serialized payload and its corresponding mode.
    fn to_payload(&self) -> (usize, Vec<u8>);
}

/// A condition that can be used to encumber transparent funds .
#[derive(Debug)]
pub struct Predicate {
    pub extension_id: usize,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Predicate {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let extension_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        Ok(Predicate {
            extension_id,
            mode,
            payload,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.extension_id)?;
        CompactSize::write(&mut writer, self.mode)?;
        Vector::write(&mut writer, &self.payload, |w, b| w.write_u8(*b))
    }

    pub fn from<P: ToPayload>(extension_id: usize, value: &P) -> Predicate {
        let (mode, payload) = value.to_payload();
        Predicate {
            extension_id,
            mode,
            payload,
        }
    }
}

/// Data that satisfies the program for prior encumbered funds, enabling them to be spent.
#[derive(Debug)]
pub struct Witness {
    pub extension_id: usize,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Witness {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let extension_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        Ok(Witness {
            extension_id,
            mode,
            payload,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.extension_id)?;
        CompactSize::write(&mut writer, self.mode)?;
        Vector::write(&mut writer, &self.payload, |w, b| w.write_u8(*b))
    }

    pub fn from<P: ToPayload>(extension_id: usize, value: &P) -> Witness {
        let (mode, payload) = value.to_payload();
        Witness {
            extension_id,
            mode,
            payload,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Error<E> {
    InvalidForEpoch(u32, usize),
    InvalidExtensionId(usize),
    ProgramError(E),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidForEpoch(cid, ptype) => write!(
                f,
                "Program type {} is invalid for consensus branch id {}",
                ptype, cid
            ),

            Error::InvalidExtensionId(extension_id) => {
                write!(f, "Unrecognized program type id {}", extension_id)
            }

            Error::ProgramError(err) => write!(f, "Program error: {}", err),
        }
    }
}

pub trait Extension<C> {
    type P;
    type W;
    type Error;

    fn verify_inner(
        &self,
        predicate: &Self::P,
        witness: &Self::W,
        context: &C,
    ) -> Result<(), Self::Error>;

    // TODO: is the lifetime specifier here actually necessary?
    fn verify<'a>(
        &self,
        predicate: &'a Predicate,
        witness: &'a Witness,
        context: &C,
    ) -> Result<(), Self::Error>
    where
        Self::P: TryFrom<(usize, &'a [u8]), Error = Self::Error>,
        Self::W: TryFrom<(usize, &'a [u8]), Error = Self::Error>,
    {
        let p0 = Self::P::try_from((predicate.mode, &predicate.payload))?;
        let w0 = Self::W::try_from((witness.mode, &witness.payload))?;
        self.verify_inner(&p0, &w0, &context)
    }
}

