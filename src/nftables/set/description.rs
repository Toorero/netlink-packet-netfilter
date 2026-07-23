// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, DefaultNla, Emitable as _, ErrorContext,
    Nla, NlaBuffer, NlasIterator, Parseable,
};

const NFTA_SET_DESC_UNSPEC: u16 = 0;
const NFTA_SET_DESC_SIZE: u16 = 1;
const NFTA_SET_DESC_CONCAT: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum SetDescription {
    Unspec,
    /// Number of elements in the set
    Size(u32),
    /// Concatenation description
    Concat(Vec<DefaultNla>),
    Other(DefaultNla),
}

impl Nla for SetDescription {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspec => 0,
            Self::Size(_) => 4,
            Self::Concat(concat) => concat.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_SET_DESC_UNSPEC,
            Self::Size(_) => NFTA_SET_DESC_SIZE,
            Self::Concat(_) => NFTA_SET_DESC_CONCAT,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspec => {}
            Self::Size(value) => emit_u32(buffer, *value).unwrap(),
            Self::Concat(concat) => concat.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for SetDescription
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_SET_DESC_UNSPEC => Self::Unspec,
            NFTA_SET_DESC_SIZE => Self::Size(
                parse_u32(payload).context("invalid NFTA_SET_DESC_SIZE")?,
            ),
            NFTA_SET_DESC_CONCAT => {
                let error_msg = "invalid NFTA_SET_DESC_CONCAT";
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(error_msg)?;
                    let parsed = DefaultNla::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::Concat(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

pub(crate) struct VecSetDescription(pub(crate) Vec<SetDescription>);

impl<T: AsRef<[u8]> + Debug + ?Sized> Parseable<T> for VecSetDescription {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf) {
            let nla =
                nla.context(format!("invalid NFTA_SET_DESC {:?}", buf))?;
            nlas.push(SetDescription::parse(&nla)?);
        }
        Ok(Self(nlas))
    }
}
