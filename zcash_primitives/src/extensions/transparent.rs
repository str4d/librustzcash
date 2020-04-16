//! Core traits and structs for Transparent Zcash Extensions.

use byteorder::{ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::fmt;
use std::io::{self, Read, Write};

use crate::serialize::{CompactSize, Vector};
use crate::transaction::Transaction;

pub(crate) mod demo;

pub trait ToPayload {
    /// Returns a serialized payload and its corresponding mode.
    fn to_payload(&self) -> (usize, Vec<u8>);
}

/// The set of programs that have assigned type IDs within the Zcash ecosystem.
#[derive(Debug, Clone, Copy)]
pub enum ProgramType {
    Demo,
    Unknown(usize),
}

impl From<usize> for ProgramType {
    fn from(t: usize) -> Self {
        match t {
            0 => ProgramType::Demo,
            n => ProgramType::Unknown(n),
        }
    }
}

impl From<ProgramType> for usize {
    fn from(type_id: ProgramType) -> usize {
        match type_id {
            ProgramType::Demo => 0,
            ProgramType::Unknown(n) => n,
        }
    }
}

/// A condition that can be used to encumber transparent funds.
#[derive(Debug)]
pub struct Predicate {
    pub type_id: ProgramType,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Predicate {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let type_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        Ok(Predicate {
            type_id: type_id.into(),
            mode,
            payload,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.type_id.into())?;
        CompactSize::write(&mut writer, self.mode)?;
        Vector::write(&mut writer, &self.payload, |w, b| w.write_u8(*b))
    }
}

/// Data that satisfies the program for prior encumbered funds, enabling them to be spent.
#[derive(Debug)]
pub struct Witness {
    pub type_id: ProgramType,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Witness {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let type_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        Ok(Witness {
            type_id: type_id.into(),
            mode,
            payload,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.type_id.into())?;
        CompactSize::write(&mut writer, self.mode)?;
        Vector::write(&mut writer, &self.payload, |w, b| w.write_u8(*b))
    }
}

#[derive(Debug, PartialEq)]
pub enum ExtErr<E: fmt::Display> {
    InvalidEpoch,
    TypeMismatch,
    Program(E),
}

impl<E: fmt::Display> fmt::Display for ExtErr<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtErr::InvalidEpoch => write!(f, "Program type is invalid for this epoch"),
            ExtErr::TypeMismatch => write!(f, "Predicate and witness types do not match"),
            ExtErr::Program(err) => write!(f, "Program error: {}", err),
        }
    }
}

pub trait Extension {
    type P;
    type W;
    type Error: fmt::Display;

    fn verify_inner(&self, predicate: &Self::P, witness: &Self::W) -> Result<(), Self::Error>;

    fn verify<'a>(&self, predicate: &'a Predicate, witness: &'a Witness) -> Result<(), Self::Error>
    where
        Self::P: TryFrom<(usize, &'a [u8]), Error = Self::Error>,
        Self::W: TryFrom<(usize, &'a [u8]), Error = Self::Error>,
    {
        let p0 = Self::P::try_from((predicate.mode, &predicate.payload))?;
        let w0 = Self::W::try_from((witness.mode, &witness.payload))?;
        self.verify_inner(&p0, &w0)
    }
}

pub struct Context<'a> {
    pub height: i32,
    pub tx: &'a Transaction,
}

impl<'a> Context<'a> {
    fn new(height: i32, tx: &'a Transaction) -> Self {
        Context { height, tx }
    }
}

pub trait Epoch<E: fmt::Display> {
    fn verify<'a>(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        ctx: &Context<'a>,
    ) -> Result<(), ExtErr<E>>;
}
