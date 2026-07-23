// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::buffer::NetfilterBuffer;
use crate::nftables::set::SetAttribute;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SetMessage {
    pub attributes: Vec<SetAttribute>,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetfilterBuffer<&'a T>>
    for SetMessage
{
    fn parse(buf: &NetfilterBuffer<&'a T>) -> Result<Self, DecodeError> {
        let attributes = buf
            .parse_all_nlas(|buf| SetAttribute::parse(&buf))
            .context("failed to parse set message nla")?;
        Ok(Self { attributes })
    }
}
