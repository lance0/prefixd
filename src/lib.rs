#![forbid(unsafe_code)]
#![deny(clippy::allow_attributes_without_reason)]
#![allow(
    clippy::collapsible_if,
    reason = "Nested authorization and lifecycle guards keep validation boundaries explicit"
)]

pub mod alerting;
pub mod api;
pub mod auth;
pub mod bgp;
pub mod config;
pub mod correlation;
pub mod db;
pub mod domain;
pub mod error;
pub mod fence;
pub mod guardrails;
pub mod observability;
pub mod policy;
pub mod scheduler;
pub mod ws;

mod state;

pub use config::*;
pub use state::*;
