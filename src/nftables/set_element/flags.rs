// SPDX-License-Identifier: MIT

use bitflags::bitflags;

const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;
const NFT_SET_ELEM_CATCHALL: u32 = 0x2;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct SetElementFlags: u32 {
        /// Element ends the previous interval.
        const IntervalEnd = NFT_SET_ELEM_INTERVAL_END;
        /// Special catch-all element.
        const CatchAll = NFT_SET_ELEM_CATCHALL;
        const _ = !0;
    }
}
