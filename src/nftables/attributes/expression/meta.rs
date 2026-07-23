// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, emit_u32_be, parse_u32, parse_u32_be, DecodeError, DefaultNla,
    ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;

const NFTA_META_UNSPEC: u16 = 0;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_META_SREG: u16 = 3;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Meta {
    Unspecified,
    DestinationRegister(Register),
    /// Meta data item to load.
    Key(u32),
    SourceRegister(Register),
    Other(DefaultNla),
}

impl Nla for Meta {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::DestinationRegister(_)
            | Self::Key(_)
            | Self::SourceRegister(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_META_UNSPEC,
            Self::DestinationRegister(_) => NFTA_META_DREG,
            Self::Key(_) => NFTA_META_KEY,
            Self::SourceRegister(_) => NFTA_META_SREG,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) | Self::SourceRegister(reg) => {
                emit_u32_be(buffer, (*reg).into()).unwrap()
            }
            Self::Key(value) => emit_u32(buffer, *value).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Meta {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_META_UNSPEC => Self::Unspecified,
            NFTA_META_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_META_DREG value")?
                    .into(),
            ),
            NFTA_META_KEY => Self::Key(
                parse_u32(payload).context("invalid NFTA_META_KEY value")?,
            ),
            NFTA_META_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_META_SREG value")?
                    .into(),
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
