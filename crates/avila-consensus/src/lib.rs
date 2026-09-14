//! Independent Bitcoin consensus primitives.
//!
//! This crate performs no filesystem, socket, clock, or GUI operations. Time is
//! always an explicit input. Every decoder is bounded by its input length.

pub mod arith;
pub mod block;
pub mod chain;
pub mod check;
pub mod connect;
pub mod encode;
pub mod hash;
pub mod header;
pub mod hex;
pub mod interpreter;
pub mod merkle;
pub mod params;
pub mod pow;
pub mod rules;
pub mod script;
pub mod transaction;
