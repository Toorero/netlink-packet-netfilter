// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32_be, parse_string, parse_u32_be, DecodeError, DefaultNla,
    ErrorContext as _, Nla, NlaBuffer, Parseable,
};

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_tables.h
const NFTA_GEN_UNSPEC: u16 = 0;
const NFTA_GEN_ID: u16 = 1;
const NFTA_GEN_PROC_PID: u16 = 2;
const NFTA_GEN_PROC_NAME: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum GenAttribute {
    Unspecified,
    /// Ruleset generation id.
    Id(u32),
    ProcPid(u32),
    ProcName(String),
    Other(DefaultNla),
}

impl Nla for GenAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Id(_) | GenAttribute::ProcPid(_) => 4,
            Self::ProcName(string) => string.len() + 1,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_GEN_UNSPEC,
            Self::Id(_) => NFTA_GEN_ID,
            Self::ProcPid(_) => NFTA_GEN_PROC_PID,
            Self::ProcName(_) => NFTA_GEN_PROC_NAME,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Id(value) | GenAttribute::ProcPid(value) => {
                emit_u32_be(buffer, *value).unwrap()
            }
            Self::ProcName(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for GenAttribute {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_GEN_UNSPEC => Self::Unspecified,
            NFTA_GEN_ID => Self::Id(
                parse_u32_be(payload).context("invalid NFTA_GEN_ID value")?,
            ),
            NFTA_GEN_PROC_PID => Self::ProcPid(
                parse_u32_be(payload)
                    .context("invalid NFTA_GEN_PROC_PID value")?,
            ),
            NFTA_GEN_PROC_NAME => Self::ProcName(
                parse_string(payload)
                    .context("invalid NFTA_GEN_PROC_NAME value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
