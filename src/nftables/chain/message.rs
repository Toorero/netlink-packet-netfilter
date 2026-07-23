// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::buffer::NetfilterBuffer;
use crate::nftables::chain::ChainAttribute;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainMessage {
    pub attributes: Vec<ChainAttribute>,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetfilterBuffer<&'a T>>
    for ChainMessage
{
    fn parse(buf: &NetfilterBuffer<&'a T>) -> Result<Self, DecodeError> {
        let attributes = buf
            .parse_all_nlas(|buf| ChainAttribute::parse(&buf))
            .context("failed to parse chain message nla")?;
        Ok(Self { attributes })
    }
}
