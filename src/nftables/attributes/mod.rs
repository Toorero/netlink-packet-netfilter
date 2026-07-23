// SPDX-License-Identifier: MIT

//! Commonly used attributes by the different Nftable message kinds.

mod data;
pub mod expression;
pub(crate) mod list;

pub use self::{
    data::DataAttribute, expression::ExpressionAttribute, list::ListAttribute,
};
