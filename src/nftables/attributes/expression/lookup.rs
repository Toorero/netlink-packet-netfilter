// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, emit_u32_be, parse_string, parse_u32, parse_u32_be, DecodeError,
    DefaultNla, ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;

const NFTA_LOOKUP_UNSPEC: u16 = 0;
const NFTA_LOOKUP_SET: u16 = 1;
const NFTA_LOOKUP_SREG: u16 = 2;
const NFTA_LOOKUP_DREG: u16 = 3;
const NFTA_LOOKUP_SET_ID: u16 = 4;
const NFTA_LOOKUP_FLAGS: u16 = 5;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Lookup {
    Unspecified,
    /// Name of the set to look in.
    Set(String),
    /// Source register containing data to look up.
    SourceRegister(Register),
    DestinationRegister(Register),
    /// Uniquely identifies a set in a transaction.
    SetId(u32),
    /// Lookup flags.
    Flags(u32),
    Other(DefaultNla),
}

impl Nla for Lookup {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Set(string) => string.len() + 1,
            Self::SourceRegister(_)
            | Self::DestinationRegister(_)
            | Self::SetId(_)
            | Self::Flags(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_LOOKUP_UNSPEC,
            Self::Set(_) => NFTA_LOOKUP_SET,
            Self::SourceRegister(_) => NFTA_LOOKUP_SREG,
            Self::DestinationRegister(_) => NFTA_LOOKUP_DREG,
            Self::SetId(_) => NFTA_LOOKUP_SET_ID,
            Self::Flags(_) => NFTA_LOOKUP_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Set(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::SourceRegister(reg) | Self::DestinationRegister(reg) => {
                emit_u32_be(buffer, (*reg).into()).unwrap()
            }
            Self::SetId(value) | Self::Flags(value) => {
                emit_u32(buffer, *value).unwrap()
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Lookup {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_LOOKUP_UNSPEC => Self::Unspecified,
            NFTA_LOOKUP_SET => Self::Set(
                parse_string(payload)
                    .context("invalid NFTA_LOOKUP_SET value")?,
            ),
            NFTA_LOOKUP_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOOKUP_SREG value")?
                    .into(),
            ),
            NFTA_LOOKUP_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOOKUP_DREG value")?
                    .into(),
            ),
            NFTA_LOOKUP_SET_ID => Self::SetId(
                parse_u32(payload)
                    .context("invalid NFTA_LOOKUP_SET_ID value")?,
            ),
            NFTA_LOOKUP_FLAGS => Self::Flags(
                parse_u32(payload)
                    .context("invalid NFTA_LOOKUP_FLAGS value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
