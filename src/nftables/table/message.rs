// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::buffer::NetfilterBuffer;
use crate::nftables::table::TableAttribute;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TableMessage {
    pub attributes: Vec<TableAttribute>,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetfilterBuffer<&'a T>>
    for TableMessage
{
    fn parse(buf: &NetfilterBuffer<&'a T>) -> Result<Self, DecodeError> {
        let attributes = buf
            .parse_all_nlas(|buf| TableAttribute::parse(&buf))
            .context("failed to parse table message nla")?;
        Ok(Self { attributes })
    }
}
