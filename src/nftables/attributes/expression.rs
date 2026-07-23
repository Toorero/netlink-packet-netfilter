// SPDX-License-Identifier: MIT

use std::fmt::Debug;

mod cmp;
mod immediate;
mod lookup;
mod meta;
mod payload;
mod register;

pub use self::{
    cmp::Cmp, immediate::Immediate, lookup::Lookup, meta::Meta,
    payload::Payload, register::Register,
};

use netlink_packet_core::{
    parse_string, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, ParseableParametrized, NLA_F_NESTED,
};

const NFTA_EXPR_UNSPEC: u16 = 0;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Expressions {
    Cmp(Vec<Cmp>),
    Immediate(Vec<Immediate>),
    Lookup(Vec<Lookup>),
    Meta(Vec<Meta>),
    Payload(Vec<Payload>),
    Unknown(Vec<DefaultNla>),
    Other {
        expression_type: String,
        attributes: Vec<DefaultNla>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExpressionAttribute {
    Unspec,
    /// Name of the expression type.
    Name(String),
    /// Type specific data.
    Data(Expressions),
    Other(DefaultNla),
}

impl Emitable for Expressions {
    fn buffer_len(&self) -> usize {
        match self {
            Self::Cmp(attrs) => attrs.as_slice().buffer_len(),
            Self::Immediate(attrs) => attrs.as_slice().buffer_len(),
            Self::Lookup(attrs) => attrs.as_slice().buffer_len(),
            Self::Meta(attrs) => attrs.as_slice().buffer_len(),
            Self::Payload(attrs) => attrs.as_slice().buffer_len(),
            Self::Unknown(attrs) => attrs.as_slice().buffer_len(),
            Self::Other { attributes, .. } => {
                attributes.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Cmp(attrs) => attrs.as_slice().emit(buffer),
            Self::Immediate(attrs) => attrs.as_slice().emit(buffer),
            Self::Lookup(attrs) => attrs.as_slice().emit(buffer),
            Self::Meta(attrs) => attrs.as_slice().emit(buffer),
            Self::Payload(attrs) => attrs.as_slice().emit(buffer),
            Self::Unknown(attrs) => attrs.as_slice().emit(buffer),
            Self::Other { attributes, .. } => {
                attributes.as_slice().emit(buffer)
            }
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized + Debug> ParseableParametrized<T, Option<String>>
    for Expressions
{
    fn parse_with_param(
        buf: &T,
        name: Option<String>,
    ) -> Result<Self, DecodeError> {
        Ok(match name {
            None => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(buf) {
                    let nla = nla
                        .context(format!("invalid NFTA_EXPR_DATA {:?}", buf))?;
                    nlas.push(DefaultNla::parse(&nla)?);
                }

                Self::Unknown(nlas)
            }
            Some(name) => match name.as_str() {
                "cmp" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Cmp::parse(&nla)?);
                    }
                    Self::Cmp(nlas)
                }
                "immediate" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Immediate::parse(&nla)?);
                    }
                    Self::Immediate(nlas)
                }
                "lookup" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Lookup::parse(&nla)?);
                    }
                    Self::Lookup(nlas)
                }
                "meta" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Meta::parse(&nla)?);
                    }
                    Self::Meta(nlas)
                }
                "payload" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Payload::parse(&nla)?);
                    }
                    Self::Payload(nlas)
                }
                name => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(DefaultNla::parse(&nla)?);
                    }
                    Self::Other {
                        expression_type: name.to_string(),
                        attributes: nlas,
                    }
                }
            },
        })
    }
}

impl Nla for ExpressionAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspec => 0,
            Self::Name(string) => string.len() + 1,
            Self::Data(exps) => exps.buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_EXPR_UNSPEC,
            Self::Name(_) => NFTA_EXPR_NAME,
            Self::Data(_) => NFTA_EXPR_DATA | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspec => {}
            Self::Name(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::Data(exps) => exps.emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Data(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NlaBuffer<&'a T>, Option<String>>
    for ExpressionAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        name: Option<String>,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_EXPR_UNSPEC => Self::Unspec,
            NFTA_EXPR_NAME => Self::Name(
                parse_string(payload).context("invalid NFTA_EXPR_NAME")?,
            ),
            NFTA_EXPR_DATA => Self::Data(
                Expressions::parse_with_param(payload, name)
                    .context("invalid NFTA_EXPR_DATA")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
