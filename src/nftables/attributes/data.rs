// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable as _, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::nftables::attributes::VerdictAttribute;

const NFTA_DATA_UNSPEC: u16 = 0;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DataAttribute {
    Unspec,
    /// Generic data.
    Value(Vec<u8>),
    Verdict(Vec<VerdictAttribute>),
    Other(DefaultNla),
}

impl Nla for DataAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspec => 0,
            Self::Value(bytes) => bytes.len(),
            Self::Verdict(attrs) => attrs.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_DATA_UNSPEC,
            Self::Value(_) => NFTA_DATA_VALUE,
            Self::Verdict(_) => NFTA_DATA_VERDICT | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspec => {}
            Self::Value(bytes) => buffer[..bytes.len()].copy_from_slice(bytes),
            Self::Verdict(attr) => attr.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Verdict(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for DataAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_DATA_UNSPEC => Self::Unspec,
            NFTA_DATA_VALUE => Self::Value(payload.to_vec()),
            NFTA_DATA_VERDICT => {
                let error_msg = "invalid NFTA_DATA_VERDICT";
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(error_msg)?;
                    let parsed =
                        VerdictAttribute::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::Verdict(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
