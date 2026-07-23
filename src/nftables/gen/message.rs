// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::buffer::NetfilterBuffer;
use crate::nftables::gen::GenAttribute;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GenMessage {
    pub attributes: Vec<GenAttribute>,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetfilterBuffer<&'a T>>
    for GenMessage
{
    fn parse(buf: &NetfilterBuffer<&'a T>) -> Result<Self, DecodeError> {
        let attributes = buf
            .parse_all_nlas(|buf| GenAttribute::parse(&buf))
            .context("failed to parse gen message nla")?;
        Ok(Self { attributes })
    }
}
