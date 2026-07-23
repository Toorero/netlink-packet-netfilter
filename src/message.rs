// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    buffer, fields, getter, setter, DecodeError, DefaultNla, Emitable,
    NetlinkDeserializable, NetlinkHeader, NetlinkPayload, NetlinkSerializable,
    Parseable, ParseableParametrized,
};

use crate::{
    buffer::NetfilterBuffer, conntrack::ConntrackMessage, nflog::ULogMessage,
    nftables::NfTablesMessage, none::ControlMessage,
};

// ProtoFamily represents a protocol family in the Netfilter header (nfgenmsg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoFamily {
    Unspec,
    Inet,
    IPv4,
    ARP,
    NetDev,
    Bridge,
    IPv6,
    DECNet,
    Other(u8),
}

const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_ARP: u8 = 3;
const NFPROTO_NETDEV: u8 = 5;
const NFPROTO_BRIDGE: u8 = 7;
const NFPROTO_IPV6: u8 = 10;
const NFPROTO_DECNET: u8 = 12;

impl From<ProtoFamily> for u8 {
    fn from(proto_family: ProtoFamily) -> Self {
        match proto_family {
            ProtoFamily::Unspec => NFPROTO_UNSPEC,
            ProtoFamily::Inet => NFPROTO_INET,
            ProtoFamily::IPv4 => NFPROTO_IPV4,
            ProtoFamily::ARP => NFPROTO_ARP,
            ProtoFamily::NetDev => NFPROTO_NETDEV,
            ProtoFamily::Bridge => NFPROTO_BRIDGE,
            ProtoFamily::IPv6 => NFPROTO_IPV6,
            ProtoFamily::DECNet => NFPROTO_DECNET,
            ProtoFamily::Other(p) => p,
        }
    }
}

impl From<u8> for ProtoFamily {
    fn from(proto_family_num: u8) -> Self {
        match proto_family_num {
            NFPROTO_UNSPEC => ProtoFamily::Unspec,
            NFPROTO_INET => ProtoFamily::Inet,
            NFPROTO_IPV4 => ProtoFamily::IPv4,
            NFPROTO_ARP => ProtoFamily::ARP,
            NFPROTO_NETDEV => ProtoFamily::NetDev,
            NFPROTO_BRIDGE => ProtoFamily::Bridge,
            NFPROTO_IPV6 => ProtoFamily::IPv6,
            NFPROTO_DECNET => ProtoFamily::DECNet,
            _ => ProtoFamily::Other(proto_family_num),
        }
    }
}

pub(crate) const NETFILTER_HEADER_LEN: usize = 4;

buffer!(NetfilterHeaderBuffer(NETFILTER_HEADER_LEN) {
    family: (u8, 0),
    version: (u8, 1),
    res_id: (u16, 2..4),
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetfilterHeader {
    pub family: ProtoFamily,
    pub version: u8,
    pub res_id: u16,
}

impl NetfilterHeader {
    pub fn new(family: ProtoFamily, version: u8, res_id: u16) -> Self {
        Self {
            family,
            version,
            res_id,
        }
    }
}

impl Emitable for NetfilterHeader {
    fn buffer_len(&self) -> usize {
        NETFILTER_HEADER_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = NetfilterHeaderBuffer::new(buf);
        buf.set_family(self.family.into());
        buf.set_version(self.version);
        buf.set_res_id(self.res_id.to_be());
    }
}

impl<T: AsRef<[u8]>> Parseable<NetfilterHeaderBuffer<T>> for NetfilterHeader {
    fn parse(buf: &NetfilterHeaderBuffer<T>) -> Result<Self, DecodeError> {
        buf.check_buffer_length()?;
        Ok(NetfilterHeader {
            family: buf.family().into(),
            version: buf.version(),
            res_id: u16::from_be(buf.res_id()),
        })
    }
}

// Defined in Linux kernel: include/uapi/linux/netfilter/nfnetlink.h
pub const NFNL_SUBSYS_NONE: u8 = 0;
pub const NFNL_SUBSYS_CTNETLINK: u8 = 1;
pub const NFNL_SUBSYS_ULOG: u8 = 4;
pub const NFNL_SUBSYS_NFTABLES: u8 = 10;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Subsystem {
    None,
    ULog,
    Conntrack,
    NfTables,
    Other(u8),
}

impl From<u8> for Subsystem {
    fn from(value: u8) -> Self {
        match value {
            NFNL_SUBSYS_NONE => Self::None,
            NFNL_SUBSYS_ULOG => Self::ULog,
            NFNL_SUBSYS_CTNETLINK => Self::Conntrack,
            NFNL_SUBSYS_NFTABLES => Self::NfTables,
            v => Self::Other(v),
        }
    }
}

impl From<Subsystem> for u8 {
    fn from(value: Subsystem) -> Self {
        match value {
            Subsystem::None => NFNL_SUBSYS_NONE,
            Subsystem::ULog => NFNL_SUBSYS_ULOG,
            Subsystem::Conntrack => NFNL_SUBSYS_CTNETLINK,
            Subsystem::NfTables => NFNL_SUBSYS_NFTABLES,
            Subsystem::Other(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NetfilterMessageInner {
    None(ControlMessage),
    ULog(ULogMessage),
    Conntrack(ConntrackMessage),
    NfTables(NfTablesMessage),
    Other {
        subsys: Subsystem,
        message_type: u8,
        attributes: Vec<DefaultNla>,
    },
}

impl From<ULogMessage> for NetfilterMessageInner {
    fn from(message: ULogMessage) -> Self {
        Self::ULog(message)
    }
}
impl From<ConntrackMessage> for NetfilterMessageInner {
    fn from(message: ConntrackMessage) -> Self {
        Self::Conntrack(message)
    }
}

impl From<NfTablesMessage> for NetfilterMessageInner {
    fn from(message: NfTablesMessage) -> Self {
        Self::NfTables(message)
    }
}

impl From<ControlMessage> for NetfilterMessageInner {
    fn from(message: ControlMessage) -> Self {
        Self::None(message)
    }
}

impl Emitable for NetfilterMessageInner {
    fn buffer_len(&self) -> usize {
        match self {
            NetfilterMessageInner::None(message) => message.buffer_len(),
            NetfilterMessageInner::ULog(message) => message.buffer_len(),
            NetfilterMessageInner::Conntrack(message) => message.buffer_len(),
            NetfilterMessageInner::NfTables(message) => message.buffer_len(),
            NetfilterMessageInner::Other { attributes, .. } => {
                attributes.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            NetfilterMessageInner::None(message) => message.emit(buffer),
            NetfilterMessageInner::ULog(message) => message.emit(buffer),
            NetfilterMessageInner::Conntrack(message) => message.emit(buffer),
            NetfilterMessageInner::NfTables(message) => message.emit(buffer),
            NetfilterMessageInner::Other { attributes, .. } => {
                attributes.as_slice().emit(buffer)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct NetfilterMessage {
    pub header: NetfilterHeader,
    pub inner: NetfilterMessageInner,
}

impl NetfilterMessage {
    pub fn new<T: Into<NetfilterMessageInner>>(
        header: NetfilterHeader,
        inner: T,
    ) -> Self {
        Self {
            header,
            inner: inner.into(),
        }
    }

    pub fn subsys(&self) -> Subsystem {
        match self.inner {
            NetfilterMessageInner::None(_) => Subsystem::None,
            NetfilterMessageInner::ULog(_) => Subsystem::ULog,
            NetfilterMessageInner::Conntrack(_) => Subsystem::Conntrack,
            NetfilterMessageInner::NfTables(_) => Subsystem::NfTables,
            NetfilterMessageInner::Other { subsys, .. } => subsys,
        }
    }

    fn message_type(&self) -> u8 {
        match self.inner {
            NetfilterMessageInner::None(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::ULog(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::Conntrack(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::NfTables(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::Other { message_type, .. } => message_type,
        }
    }
}

impl Emitable for NetfilterMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.inner.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.inner.emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl NetlinkSerializable for NetfilterMessage {
    fn message_type(&self) -> u16 {
        ((u8::from(self.subsys()) as u16) << 8) | self.message_type() as u16
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable for NetfilterMessage {
    type Error = DecodeError;
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, Self::Error> {
        match NetfilterBuffer::new_checked(payload) {
            Err(e) => Err(e),
            Ok(buffer) => match NetfilterMessage::parse_with_param(
                &buffer,
                header.message_type,
            ) {
                Err(e) => Err(e),
                Ok(message) => Ok(message),
            },
        }
    }
}

impl From<NetfilterMessage> for NetlinkPayload<NetfilterMessage> {
    fn from(message: NetfilterMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
