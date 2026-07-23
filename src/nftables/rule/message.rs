// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::buffer::NetfilterBuffer;
use crate::nftables::rule::RuleAttribute;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleMessage {
    pub attributes: Vec<RuleAttribute>,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetfilterBuffer<&'a T>>
    for RuleMessage
{
    fn parse(buf: &NetfilterBuffer<&'a T>) -> Result<Self, DecodeError> {
        let attributes = buf
            .parse_all_nlas(|buf| RuleAttribute::parse(&buf))
            .context("failed to parse rule message nla")?;
        Ok(Self { attributes })
    }
}
