//! QED Script runtime: a purpose-built `#![no_std]`, zero-allocation, `#![forbid(unsafe_code)]`
//! WebAssembly interpreter (i32-only MVP subset) plus the restricted host API.
//!
//! Why not Wasmi: it is not vendored in this repository and cannot be fetched/audited in the build
//! environment, and its fuel/memory/import model would still need wrapping. The subset interpreter
//! here is small enough to audit and to bound-check with Kani. See `docs/QED_SCRIPT.md`.
#![no_std]
#![forbid(unsafe_code)]

pub mod host;
pub mod ops;
mod validate;
pub mod wasm;

pub use host::{content_type_str, execute, resolver, Clock, Method, NoClock, Outcome, Reason, Request};
pub use wasm::{Host, Instance, LoadError, Memory, Module, Trap};

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
#[cfg(kani)]
mod proofs;
