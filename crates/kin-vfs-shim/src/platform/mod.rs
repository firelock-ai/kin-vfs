// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Platform-specific helpers.
//!
//! - **Linux/macOS**: `fill_stat_buf` for libc stat struct population.
//! - **Windows**: `ProjFsProvider` for Projected File System virtualization.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::ProjFsProvider;
