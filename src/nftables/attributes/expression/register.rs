// SPDX-License-Identifier: MIT

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_tables.h
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_REG_2: u32 = 2;
const NFT_REG_3: u32 = 3;
const NFT_REG_4: u32 = 4;
const __NFT_REG_MAX: u32 = 5;

const NFT_REG32_00: u32 = 8;
const NFT_REG32_01: u32 = 9;
const NFT_REG32_02: u32 = 10;
const NFT_REG32_03: u32 = 11;
const NFT_REG32_04: u32 = 12;
const NFT_REG32_05: u32 = 13;
const NFT_REG32_06: u32 = 14;
const NFT_REG32_07: u32 = 15;
const NFT_REG32_08: u32 = 16;
const NFT_REG32_09: u32 = 17;
const NFT_REG32_10: u32 = 18;
const NFT_REG32_11: u32 = 19;
const NFT_REG32_12: u32 = 20;
const NFT_REG32_13: u32 = 21;
const NFT_REG32_14: u32 = 22;
const NFT_REG32_15: u32 = 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u32)]
pub enum Register {
    Verdict = NFT_REG_VERDICT,
    Reg1 = NFT_REG_1,
    Reg2 = NFT_REG_2,
    Reg3 = NFT_REG_3,
    Reg4 = NFT_REG_4,
    Reg32_00 = NFT_REG32_00,
    Reg32_01 = NFT_REG32_01,
    Reg32_02 = NFT_REG32_02,
    Reg32_03 = NFT_REG32_03,
    Reg32_04 = NFT_REG32_04,
    Reg32_05 = NFT_REG32_05,
    Reg32_06 = NFT_REG32_06,
    Reg32_07 = NFT_REG32_07,
    Reg32_08 = NFT_REG32_08,
    Reg32_09 = NFT_REG32_09,
    Reg32_10 = NFT_REG32_10,
    Reg32_11 = NFT_REG32_11,
    Reg32_12 = NFT_REG32_12,
    Reg32_13 = NFT_REG32_13,
    Reg32_14 = NFT_REG32_14,
    Reg32_15 = NFT_REG32_15,
    Other(u32),
}

impl From<Register> for u32 {
    fn from(reg: Register) -> Self {
        match reg {
            Register::Verdict => NFT_REG_VERDICT,
            Register::Reg1 => NFT_REG_1,
            Register::Reg2 => NFT_REG_2,
            Register::Reg3 => NFT_REG_3,
            Register::Reg4 => NFT_REG_4,
            Register::Reg32_00 => NFT_REG32_00,
            Register::Reg32_01 => NFT_REG32_01,
            Register::Reg32_02 => NFT_REG32_02,
            Register::Reg32_03 => NFT_REG32_03,
            Register::Reg32_04 => NFT_REG32_04,
            Register::Reg32_05 => NFT_REG32_05,
            Register::Reg32_06 => NFT_REG32_06,
            Register::Reg32_07 => NFT_REG32_07,
            Register::Reg32_08 => NFT_REG32_08,
            Register::Reg32_09 => NFT_REG32_09,
            Register::Reg32_10 => NFT_REG32_10,
            Register::Reg32_11 => NFT_REG32_11,
            Register::Reg32_12 => NFT_REG32_12,
            Register::Reg32_13 => NFT_REG32_13,
            Register::Reg32_14 => NFT_REG32_14,
            Register::Reg32_15 => NFT_REG32_15,
            Register::Other(val) => val,
        }
    }
}

impl From<u32> for Register {
    fn from(val: u32) -> Self {
        match val {
            NFT_REG_VERDICT => Self::Verdict,
            NFT_REG_1 => Self::Reg1,
            NFT_REG_2 => Self::Reg2,
            NFT_REG_3 => Self::Reg3,
            NFT_REG_4 => Self::Reg4,
            NFT_REG32_00 => Self::Reg32_00,
            NFT_REG32_01 => Self::Reg32_01,
            NFT_REG32_02 => Self::Reg32_02,
            NFT_REG32_03 => Self::Reg32_03,
            NFT_REG32_04 => Self::Reg32_04,
            NFT_REG32_05 => Self::Reg32_05,
            NFT_REG32_06 => Self::Reg32_06,
            NFT_REG32_07 => Self::Reg32_07,
            NFT_REG32_08 => Self::Reg32_08,
            NFT_REG32_09 => Self::Reg32_09,
            NFT_REG32_10 => Self::Reg32_10,
            NFT_REG32_11 => Self::Reg32_11,
            NFT_REG32_12 => Self::Reg32_12,
            NFT_REG32_13 => Self::Reg32_13,
            NFT_REG32_14 => Self::Reg32_14,
            NFT_REG32_15 => Self::Reg32_15,
            other => Self::Other(other),
        }
    }
}
