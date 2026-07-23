// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, emit_u32_be, parse_u32, parse_u32_be, DecodeError, DefaultNla,
    ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;

const NFTA_PAYLOAD_UNSPEC: u16 = 0;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_PAYLOAD_SREG: u16 = 5;
const NFTA_PAYLOAD_CSUM_TYPE: u16 = 6;
const NFTA_PAYLOAD_CSUM_OFFSET: u16 = 7;
const NFTA_PAYLOAD_CSUM_FLAGS: u16 = 8;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Payload {
    Unspecified,
    DestinationRegister(Register),
    /// Payload base.
    Base(u32),
    /// Payload offset relative to base.
    Offset(u32),
    /// Payload length.
    Len(u32),
    SourceRegister(Register),
    CsumType(u32),
    /// Checksum offset relative to base.
    CsumOffset(u32),
    CsumFlags(u32),
    Other(DefaultNla),
}

impl Nla for Payload {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::DestinationRegister(_)
            | Self::Base(_)
            | Self::Offset(_)
            | Self::Len(_)
            | Self::SourceRegister(_)
            | Self::CsumType(_)
            | Self::CsumOffset(_)
            | Self::CsumFlags(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_PAYLOAD_UNSPEC,
            Self::DestinationRegister(_) => NFTA_PAYLOAD_DREG,
            Self::Base(_) => NFTA_PAYLOAD_BASE,
            Self::Offset(_) => NFTA_PAYLOAD_OFFSET,
            Self::Len(_) => NFTA_PAYLOAD_LEN,
            Self::SourceRegister(_) => NFTA_PAYLOAD_SREG,
            Self::CsumType(_) => NFTA_PAYLOAD_CSUM_TYPE,
            Self::CsumOffset(_) => NFTA_PAYLOAD_CSUM_OFFSET,
            Self::CsumFlags(_) => NFTA_PAYLOAD_CSUM_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) | Self::SourceRegister(reg) => {
                emit_u32_be(buffer, (*reg).into()).unwrap()
            }
            Self::Base(value)
            | Self::Offset(value)
            | Self::Len(value)
            | Self::CsumType(value)
            | Self::CsumOffset(value)
            | Self::CsumFlags(value) => emit_u32(buffer, *value).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Payload {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_PAYLOAD_UNSPEC => Self::Unspecified,
            NFTA_PAYLOAD_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_DREG value")?
                    .into(),
            ),
            NFTA_PAYLOAD_BASE => Self::Base(
                parse_u32(payload)
                    .context("invalid NFTA_PAYLOAD_BASE value")?,
            ),
            NFTA_PAYLOAD_OFFSET => Self::Offset(
                parse_u32(payload)
                    .context("invalid NFTA_PAYLOAD_OFFSET value")?,
            ),
            NFTA_PAYLOAD_LEN => Self::Len(
                parse_u32(payload).context("invalid NFTA_PAYLOAD_LEN value")?,
            ),
            NFTA_PAYLOAD_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_SREG value")?
                    .into(),
            ),
            NFTA_PAYLOAD_CSUM_TYPE => Self::CsumType(
                parse_u32(payload)
                    .context("invalid NFTA_PAYLOAD_CSUM_TYPE value")?,
            ),
            NFTA_PAYLOAD_CSUM_OFFSET => Self::CsumOffset(
                parse_u32(payload)
                    .context("invalid NFTA_PAYLOAD_CSUM_OFFSET value")?,
            ),
            NFTA_PAYLOAD_CSUM_FLAGS => Self::CsumFlags(
                parse_u32(payload)
                    .context("invalid NFTA_PAYLOAD_CSUM_FLAGS value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
