//! Core traits and structs for Transparent Zcash Extensions.

use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};

use crate::serialize::{CompactSize, Vector};

pub trait ToPayload {
    /// Returns a serialized payload and its corresponding mode.
    fn to_payload(&self) -> (usize, Vec<u8>);
}

/// The set of programs that have assigned type IDs within the Zcash ecosystem.
pub enum ProgramType {
    Unknown(usize),
}

impl From<usize> for ProgramType {
    fn from(t: usize) -> Self {
        match t {
            n => ProgramType::Unknown(n),
        }
    }
}

impl From<ProgramType> for usize {
    fn from(type_id: ProgramType) -> usize {
        match type_id {
            ProgramType::Unknown(n) => n,
        }
    }
}

/// A condition that can be used to encumber transparent funds.
#[derive(Debug)]
pub enum Predicate {
    /// A predicate for an unknown program type. This allows the current parser to parse
    /// future transactions containing new program types, while ensuring that they cannot
    /// be considered valid.
    Unknown {
        type_id: usize,
        mode: usize,
        payload: Vec<u8>,
    },
}

impl Predicate {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let type_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        match type_id.into() {
            ProgramType::Unknown(type_id) => Ok(Predicate::Unknown {
                type_id,
                mode,
                payload,
            }),
        }
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        let inner = |mut w: W, type_id: ProgramType, mode, payload| {
            CompactSize::write(&mut w, type_id.into())?;
            CompactSize::write(&mut w, mode)?;
            Vector::write(&mut w, payload, |w, b| w.write_u8(*b))
        };

        match self {
            Predicate::Unknown {
                type_id,
                mode,
                payload,
            } => inner(writer, ProgramType::Unknown(*type_id), *mode, payload),
        }
    }
}

/// Data that satisfies the program for prior encumbered funds, enabling them to be spent.
#[derive(Debug)]
pub enum Witness {
    /// A witness for an unknown program type. This allows the current parser to parse
    /// future transactions containing new program types, while ensuring that they cannot
    /// be considered valid.
    Unknown {
        type_id: usize,
        mode: usize,
        payload: Vec<u8>,
    },
}

impl Witness {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let type_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        match type_id.into() {
            ProgramType::Unknown(type_id) => Ok(Witness::Unknown {
                type_id,
                mode,
                payload,
            }),
        }
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        let inner = |mut w: W, type_id: ProgramType, mode, payload| {
            CompactSize::write(&mut w, type_id.into())?;
            CompactSize::write(&mut w, mode)?;
            Vector::write(&mut w, payload, |w, b| w.write_u8(*b))
        };

        match self {
            Witness::Unknown {
                type_id,
                mode,
                payload,
            } => inner(writer, ProgramType::Unknown(*type_id), *mode, payload),
        }
    }
}
