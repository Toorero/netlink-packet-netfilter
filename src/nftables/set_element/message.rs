// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::buffer::NetfilterBuffer;
use crate::nftables::set_element::list::SetElementList;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SetElementMessage {
    // Contrary to the [kernel header doc] SetElementMessages are build out of
    // `nft_set_elem_list_attributes` instead of `nft_set_elem_attributes`
    //
    // [kernel doc]: include/uapi/linux/netfilter/nf_tables.h
    pub attributes: Vec<SetElementList>,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetfilterBuffer<&'a T>>
    for SetElementMessage
{
    fn parse(buf: &NetfilterBuffer<&'a T>) -> Result<Self, DecodeError> {
        let attributes = buf
            .parse_all_nlas(|buf| SetElementList::parse(&buf))
            .context("failed to parse set element message nla")?;
        Ok(Self { attributes })
    }
}
