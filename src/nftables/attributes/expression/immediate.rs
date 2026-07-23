// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32_be, parse_u32_be, DecodeError, DefaultNla, Emitable as _,
    ErrorContext as _, Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};

use crate::nftables::attributes::{expression::Register, DataAttribute};

const NFTA_IMMEDIATE_UNSPEC: u16 = 0;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Immediate {
    Unspecified,
    DestinationRegister(Register),
    /// Data to load.
    Data(DataAttribute),
    Other(DefaultNla),
}

impl Nla for Immediate {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::DestinationRegister(_) => 4,
            Self::Data(data) => data.buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_IMMEDIATE_UNSPEC,
            Self::DestinationRegister(_) => NFTA_IMMEDIATE_DREG,
            Self::Data(_) => NFTA_IMMEDIATE_DATA | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) => {
                emit_u32_be(buffer, (*reg).into()).unwrap()
            }
            Self::Data(data) => data.emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Data(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Immediate {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_IMMEDIATE_UNSPEC => Self::Unspecified,
            NFTA_IMMEDIATE_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_IMMEDIATE_DREG value")?
                    .into(),
            ),
            NFTA_IMMEDIATE_DATA => Self::Data(
                DataAttribute::parse(&NlaBuffer::new(payload)).context(
                    format!("invalid NFTA_IMMEDIATE_DATA {:?}", payload),
                )?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
