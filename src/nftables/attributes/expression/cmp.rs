// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, emit_u32_be, parse_u32, parse_u32_be, DecodeError, DefaultNla,
    Emitable as _, ErrorContext as _, Nla, NlaBuffer, NlasIterator, Parseable,
    NLA_F_NESTED,
};

use crate::nftables::attributes::expression::Register;

const NFTA_CMP_UNSPEC: u16 = 0;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Cmp {
    Unspecified,
    SourceRegister(Register),
    /// Comparison operation.
    Op(u32),
    /// Data to compare against.
    Data(Vec<DefaultNla>),
    Other(DefaultNla),
}

impl Nla for Cmp {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::SourceRegister(_) | Self::Op(_) => 4,
            Self::Data(attrs) => attrs.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_CMP_UNSPEC,
            Self::SourceRegister(_) => NFTA_CMP_SREG,
            Self::Op(_) => NFTA_CMP_OP,
            Self::Data(_) => NFTA_CMP_DATA | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::SourceRegister(reg) => {
                emit_u32_be(buffer, (*reg).into()).unwrap()
            }
            Self::Op(value) => emit_u32(buffer, *value).unwrap(),
            Self::Data(attrs) => attrs.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Data(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Cmp {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_CMP_UNSPEC => Self::Unspecified,
            NFTA_CMP_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_CMP_SREG value")?
                    .into(),
            ),
            NFTA_CMP_OP => Self::Op(
                parse_u32(payload).context("invalid NFTA_CMP_OP value")?,
            ),
            NFTA_CMP_DATA => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context(format!(
                        "invalid NFTA_CMP_DATA {:?}",
                        payload
                    ))?;
                    nlas.push(DefaultNla::parse(&nla)?);
                }
                Self::Data(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
