// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Hook contract: versioned JSON events, interface match, debounce, dispatch.

pub mod debounce;
pub mod dispatch;
pub mod event;
pub mod explain;
pub mod journal;
pub mod match_iface;
pub mod ratelimit;
pub mod service;

pub use dispatch::HookDispatchOpts;
pub use event::HookEventV1;
pub use journal::EventLog;
pub use match_iface::InterfaceSelector;
pub use service::spawn_with_log as spawn_service_with_log;
