// SPDX-License-Identifier: MIT

use bitflags::bitflags;

const NFT_SET_ANONYMOUS: u32 = 0x1;
const NFT_SET_CONSTANT: u32 = 0x2;
const NFT_SET_INTERVAL: u32 = 0x4;
const NFT_SET_MAP: u32 = 0x8;
const NFT_SET_TIMEOUT: u32 = 0x10;
const NFT_SET_EVAL: u32 = 0x20;
const NFT_SET_OBJECT: u32 = 0x40;
const NFT_SET_CONCAT: u32 = 0x80;
const NFT_SET_EXPR: u32 = 0x100;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct SetFlags: u32 {
        /// Name allocation, automatic cleanup on unlink.
        const Anonymous = NFT_SET_ANONYMOUS;
        /// Set contents may not change while bound.
        const Constant = NFT_SET_CONSTANT;
        /// Set contains intervals.
        const Interval = NFT_SET_INTERVAL;
        /// Set is used as a dictionary.
        const Map = NFT_SET_MAP;
        /// Set uses timeouts.
        const Timeout = NFT_SET_TIMEOUT;
        /// Set can be updated from the evaluation path.
        const Eval = NFT_SET_EVAL;
        /// Set contains stateful objects.
        const Object = NFT_SET_OBJECT;
        /// Set contains a concatenation.
        const Concat = NFT_SET_CONCAT;
        /// Set contains expressions.
        const Expression = NFT_SET_EXPR;
        const _ = !0;
    }
}
