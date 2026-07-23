// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32_be, emit_u64_be, parse_string, parse_u32_be, parse_u64_be,
    DecodeError, DefaultNla, Emitable, ErrorContext as _, Nla, NlaBuffer,
    NlasIterator, Parseable, ParseableParametrized, NLA_F_NESTED,
};

use crate::nftables::chain::{hook::HookType, ChainFlags, Hook};

const NFTA_CHAIN_UNSPEC: u16 = 0;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_HANDLE: u16 = 2;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_USE: u16 = 6;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_CHAIN_COUNTERS: u16 = 8;
//const NFTA_CHAIN_PAD: u16 = 9;
const NFTA_CHAIN_FLAGS: u16 = 10;
const NFTA_CHAIN_ID: u16 = 11;
const NFTA_CHAIN_USERDATA: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum ChainAttribute {
    Unspecified,
    /// Name of the table containing the chain.
    Table(String),
    /// Numeric handle of the chain.
    Handle(u64),
    /// Name of the chain.
    Name(String),
    /// Hook specification for basechains.
    Hook(Vec<Hook>),
    /// Numeric policy of the chain.
    Policy(u32),
    /// Number of references to this chain.
    Use(u32),
    /// Type name of the string.
    Type(String),
    /// Conter specification of the chain.
    Counter(Vec<DefaultNla>),
    Flags(ChainFlags),
    /// Uniquely identifies a chain in a transaction.
    Id(u32),
    /// Custom user data attached to the rule.
    UserData(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for ChainAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Table(string) | Self::Name(string) | Self::Type(string) => {
                string.len() + 1
            }
            Self::Handle(_) => 8,
            Self::Hook(attrs) => attrs.as_slice().buffer_len(),
            Self::Policy(_) | Self::Use(_) | Self::Flags(_) | Self::Id(_) => 4,
            Self::Counter(attrs) => attrs.as_slice().buffer_len(),
            Self::UserData(bytes) => bytes.len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_CHAIN_UNSPEC,
            Self::Table(_) => NFTA_CHAIN_TABLE,
            Self::Handle(_) => NFTA_CHAIN_HANDLE,
            Self::Name(_) => NFTA_CHAIN_NAME,
            Self::Hook(_) => NFTA_CHAIN_HOOK | NLA_F_NESTED,
            Self::Policy(_) => NFTA_CHAIN_POLICY,
            Self::Use(_) => NFTA_CHAIN_USE,
            Self::Type(_) => NFTA_CHAIN_TYPE,
            Self::Counter(_) => NFTA_CHAIN_COUNTERS | NLA_F_NESTED,
            Self::Flags(_) => NFTA_CHAIN_FLAGS,
            Self::Id(_) => NFTA_CHAIN_ID,
            Self::UserData(_) => NFTA_CHAIN_USERDATA,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Table(string) | Self::Name(string) | Self::Type(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::Handle(value) => emit_u64_be(buffer, *value).unwrap(),
            Self::Hook(attrs) => attrs.as_slice().emit(buffer),
            Self::Policy(value) | Self::Use(value) | Self::Id(value) => {
                emit_u32_be(buffer, *value).unwrap()
            }
            Self::Flags(flags) => emit_u32_be(buffer, flags.bits()).unwrap(),
            Self::Counter(attrs) => attrs.as_slice().emit(buffer),
            Self::UserData(bytes) => {
                buffer[..bytes.len()].copy_from_slice(bytes.as_slice())
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Hook(_) | Self::Counter(_))
            || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for ChainAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_CHAIN_UNSPEC => Self::Unspecified,
            NFTA_CHAIN_TABLE => Self::Table(
                parse_string(payload)
                    .context("invalid NFTA_CHAIN_TABLE value")?,
            ),
            NFTA_CHAIN_HANDLE => Self::Handle(
                parse_u64_be(payload)
                    .context("invalid NFTA_CHAIN_HANDLE value")?,
            ),
            NFTA_CHAIN_NAME => Self::Name(
                parse_string(payload)
                    .context("invalid NFTA_CHAIN_NAME value")?,
            ),
            NFTA_CHAIN_HOOK => {
                let mut nlas = vec![];
                let mut hook_type = HookType::default();
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context(format!(
                        "invalid NFTA_CHAIN_HOOK payload {:?}",
                        payload
                    ))?;
                    let hook = Hook::parse_with_param(&nla, hook_type)?;
                    match hook {
                        Hook::NetDeviceName(_) | Hook::NetDevices(_) => {
                            hook_type = HookType::Dev
                        }
                        _ => {}
                    }
                    nlas.push(hook);
                }
                Self::Hook(nlas)
            }
            NFTA_CHAIN_POLICY => Self::Policy(
                parse_u32_be(payload)
                    .context("invalid NFTA_CHAIN_POLICY value")?,
            ),
            NFTA_CHAIN_USE => Self::Use(
                parse_u32_be(payload)
                    .context("invalid NFTA_CHAIN_USE value")?,
            ),
            NFTA_CHAIN_TYPE => Self::Type(
                parse_string(payload)
                    .context("invalid NFTA_CHAIN_TYPE value")?,
            ),
            NFTA_CHAIN_COUNTERS => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context(format!(
                        "invalid NFTA_CHAIN_COUNTERS payload {:?}",
                        payload
                    ))?;
                    nlas.push(DefaultNla::parse(&nla)?);
                }
                Self::Counter(nlas)
            }
            NFTA_CHAIN_FLAGS => Self::Flags(ChainFlags::from_bits_retain(
                parse_u32_be(payload)
                    .context("invalid NFTA_CHAIN_FLAGS value")?,
            )),
            NFTA_CHAIN_ID => Self::Id(
                parse_u32_be(payload).context("invalid NFTA_CHAIN_ID value")?,
            ),
            NFTA_CHAIN_USERDATA => Self::UserData(payload.to_vec()),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
