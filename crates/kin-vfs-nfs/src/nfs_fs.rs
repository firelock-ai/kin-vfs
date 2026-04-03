// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! NFS filesystem adapter.
//!
//! Implements `nfsserve::vfs::NFSFileSystem` backed by a single
//! `ContentProvider`. Translates NFS operations (GETATTR, LOOKUP,
//! READ, READDIR, etc.) into ContentProvider calls.

// TODO: implement in task #3
