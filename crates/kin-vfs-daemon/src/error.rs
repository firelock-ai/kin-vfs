// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("provider error: {0}")]
    Provider(#[from] kin_vfs_core::VfsError),

    #[error("serialization error: {0}")]
    Serialization(String),
}
