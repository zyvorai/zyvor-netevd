// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//! NetworkManager DBus listener

pub mod dbus;

// Re-export the main listener function
pub use dbus::listen_networkmanager;
