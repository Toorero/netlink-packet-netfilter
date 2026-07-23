// SPDX-License-Identifier: MIT

use bitflags::bitflags;

const NFT_CHAIN_BASE: u32 = 0x01;
const NFT_CHAIN_HW_OFFLOAD: u32 = 0x02;
const NFT_CHAIN_BINDING: u32 = 0x04;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct ChainFlags: u32 {
        const Base = NFT_CHAIN_BASE;
        const HwOffload =NFT_CHAIN_HW_OFFLOAD;
        const Binding =NFT_CHAIN_BINDING;
        const _ = !0;
    }
}
