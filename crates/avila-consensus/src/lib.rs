//! Independent Bitcoin consensus primitives.
//!
//! This crate performs no filesystem, socket, clock, or GUI operations. Time is
//! always an explicit input. Every decoder is bounded by its input length.

pub mod address;
pub mod arith;
pub mod bip9;
pub mod block;
pub mod chain;
pub mod chainstate;
pub mod check;
pub mod coinsdb;
pub mod coinstats;
pub mod connect;
pub mod descriptor;
pub mod encode;
pub mod extended_key;
pub mod gcs;
pub mod hash;
pub mod header;
pub mod hex;
pub mod interpreter;
pub mod merkle;
pub mod message;
pub mod miniscript;
pub mod muhash;
pub mod params;
pub mod pow;
pub mod psbt;
pub mod rules;
pub mod script;
pub mod sigchecker;
pub mod sign;
pub mod signet;
pub mod silent;
pub mod store;
pub mod transaction;
pub mod utxo_snapshot;
