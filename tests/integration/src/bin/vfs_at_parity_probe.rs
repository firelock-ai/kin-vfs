// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Differential probe for native `*at` path, dirfd, flag, mode, and errno
//! behavior. The parent runs the same binary against libc and against the
//! injected KinVFS shim, then compares the complete result stream.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

#[cfg(target_os = "linux")]
extern "C" {
    #[link_name = "__open_2"]
    fn fortified_open_2(path: *const libc::c_char, flags: libc::c_int) -> libc::c_int;
    #[link_name = "__open64_2"]
    fn fortified_open64_2(path: *const libc::c_char, flags: libc::c_int) -> libc::c_int;
    #[link_name = "__openat_2"]
    fn fortified_openat_2(
        dirfd: libc::c_int,
        path: *const libc::c_char,
        flags: libc::c_int,
    ) -> libc::c_int;
    #[link_name = "__openat64_2"]
    fn fortified_openat64_2(
        dirfd: libc::c_int,
        path: *const libc::c_char,
        flags: libc::c_int,
    ) -> libc::c_int;
    #[link_name = "__xstat"]
    fn versioned_xstat(
        ver: libc::c_int,
        path: *const libc::c_char,
        buf: *mut libc::stat,
    ) -> libc::c_int;
    #[link_name = "__lxstat"]
    fn versioned_lxstat(
        ver: libc::c_int,
        path: *const libc::c_char,
        buf: *mut libc::stat,
    ) -> libc::c_int;
    #[link_name = "__fxstat"]
    fn versioned_fxstat(ver: libc::c_int, fd: libc::c_int, buf: *mut libc::stat) -> libc::c_int;
    #[link_name = "stat64"]
    fn direct_stat64(path: *const libc::c_char, buf: *mut libc::stat64) -> libc::c_int;
    #[link_name = "lstat64"]
    fn direct_lstat64(path: *const libc::c_char, buf: *mut libc::stat64) -> libc::c_int;
    #[link_name = "fstat64"]
    fn direct_fstat64(fd: libc::c_int, buf: *mut libc::stat64) -> libc::c_int;
    #[link_name = "__xstat64"]
    fn versioned_xstat64(
        ver: libc::c_int,
        path: *const libc::c_char,
        buf: *mut libc::stat64,
    ) -> libc::c_int;
    #[link_name = "__lxstat64"]
    fn versioned_lxstat64(
        ver: libc::c_int,
        path: *const libc::c_char,
        buf: *mut libc::stat64,
    ) -> libc::c_int;
    #[link_name = "__fxstat64"]
    fn versioned_fxstat64(ver: libc::c_int, fd: libc::c_int, buf: *mut libc::stat64)
        -> libc::c_int;
    #[link_name = "getdents64"]
    fn direct_getdents64(
        fd: libc::c_int,
        buf: *mut libc::c_void,
        count: libc::size_t,
    ) -> libc::ssize_t;
}

#[cfg(target_os = "macos")]
extern "C" {
    #[link_name = "__getdirentries64"]
    fn getdirentries64_probe(
        fd: libc::c_int,
        buf: *mut libc::c_char,
        nbytes: libc::size_t,
        basep: *mut libc::c_long,
    ) -> libc::ssize_t;
}

const INVALID_DIRFD: libc::c_int = 0x3fff_ffff;
const INVALID_AT_FLAG: libc::c_int = 0x0100_0000;
const EXTRA_ACCESS_MODE_BIT: libc::c_int = 0x08;
const ALL_ACCESS_MODE_BITS: libc::c_int = -1;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NATIVE_STAT_VERSION: libc::c_int = 1;
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
const NATIVE_STAT_VERSION: libc::c_int = 0;

#[cfg(target_os = "macos")]
const O_RESOLVE_BENEATH_VALUE: libc::c_int = 0x0000_1000;
#[cfg(target_os = "macos")]
const O_UNIQUE_VALUE: libc::c_int = 0x0000_2000;
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW_ANY_VALUE: libc::c_int = 0x0800;
#[cfg(target_os = "macos")]
const AT_RESOLVE_BENEATH_VALUE: libc::c_int = 0x2000;
#[cfg(target_os = "macos")]
const AT_UNIQUE_VALUE: libc::c_int = 0x8000;
#[cfg(target_os = "macos")]
const AT_REALDEV_VALUE: libc::c_int = 0x0200;
#[cfg(target_os = "macos")]
const AT_FDONLY_VALUE: libc::c_int = 0x0400;

#[cfg(any(target_os = "linux", target_os = "android"))]
const AT_EMPTY_PATH_VALUE: libc::c_int = libc::AT_EMPTY_PATH;
// Darwin has no AT_EMPTY_PATH. This otherwise-unused bit must be rejected with
// the same EINVAL as libSystem.
#[cfg(target_os = "macos")]
const AT_EMPTY_PATH_VALUE: libc::c_int = 0x1000;

#[inline]
unsafe fn set_errno(value: libc::c_int) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        *libc::__errno_location() = value;
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error() = value;
    }
}

#[inline]
unsafe fn errno() -> libc::c_int {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        *libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error()
    }
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("probe path contains no NUL")
}

unsafe fn report_fd(label: &str, fd: libc::c_int) {
    if fd >= 0 {
        println!("{label}=ok");
        if libc::close(fd) != 0 {
            eprintln!("close after {label} failed: {}", errno());
            std::process::exit(3);
        }
    } else {
        println!("{label}=err:{}", errno());
    }
}

#[cfg(target_os = "linux")]
unsafe fn report_opath_ignored_fd(label: &str, fd: libc::c_int) {
    if fd < 0 {
        println!("{label}=err:{}", errno());
        return;
    }
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags < 0
        || flags & libc::O_PATH == 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & (libc::O_TRUNC | libc::O_CREAT) != 0
    {
        fail_extra(format!(
            "{label} retained flags Linux ignores under O_PATH: {flags:#x}"
        ));
    }
    println!("{label}=ok");
    if libc::close(fd) != 0 {
        fail_extra(format!("close after {label}: {}", errno()));
    }
}

unsafe fn report_created_fd(label: &str, fd: libc::c_int, path: *const libc::c_char) {
    if fd >= 0 {
        println!("{label}=ok");
        if libc::close(fd) != 0 || libc::unlink(path) != 0 {
            eprintln!("cleanup after {label} failed: {}", errno());
            std::process::exit(3);
        }
    } else {
        println!("{label}=err:{}", errno());
    }
}

unsafe fn report_status(label: &str, result: libc::c_int) {
    if result == 0 {
        println!("{label}=ok");
    } else {
        println!("{label}=err:{}", errno());
    }
}

unsafe fn report_stat(label: &str, result: libc::c_int, stat: libc::stat) {
    if result == 0 {
        println!("{label}=ok:{:o}", stat.st_mode as u32 & libc::S_IFMT as u32);
    } else {
        println!("{label}=err:{}", errno());
    }
}

unsafe fn report_readlink(label: &str, result: libc::ssize_t, buffer: &[u8]) {
    if result < 0 {
        println!("{label}=err:{}", errno());
    } else {
        println!(
            "{label}=ok:{}",
            String::from_utf8_lossy(&buffer[..result as usize])
        );
    }
}

fn fail_extra(message: impl std::fmt::Display) -> ! {
    eprintln!("graph-owned parity assertion failed: {message}");
    std::process::exit(5);
}

unsafe fn expect_errno(label: &str, result: libc::c_int, expected: libc::c_int) {
    let actual = errno();
    if result != -1 || actual != expected {
        fail_extra(format!(
            "{label}: expected -1/{expected}, got {result}/{actual}"
        ));
    }
}

fn expected_vfd_base() -> libc::c_int {
    unsafe {
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0
            && limit.rlim_cur != libc::RLIM_INFINITY
        {
            return (limit.rlim_cur as libc::c_int)
                .saturating_add(1000)
                .max(10_000);
        }
    }
    100_000
}

#[cfg(target_os = "macos")]
unsafe fn directory_entry_inode(fd: libc::c_int, name: &[u8]) -> u64 {
    let duplicate = libc::dup(fd);
    if duplicate < 0 {
        fail_extra(format!(
            "dup directory for inode parity failed: {}",
            errno()
        ));
    }
    let mut bytes = vec![0u8; 64 * 1024];
    let mut basep = 0;
    let read = getdirentries64_probe(
        duplicate,
        bytes.as_mut_ptr().cast(),
        bytes.len(),
        &mut basep,
    );
    libc::close(duplicate);
    if read < 0 {
        fail_extra(format!(
            "getdirentries for inode parity failed: {}",
            errno()
        ));
    }
    let mut offset = 0usize;
    while offset < read as usize {
        let record = bytes.as_ptr().add(offset);
        let inode = (record as *const u64).read_unaligned();
        let reclen = (record.add(16) as *const u16).read_unaligned() as usize;
        let namlen = (record.add(18) as *const u16).read_unaligned() as usize;
        if reclen < 21 || offset + reclen > read as usize || 21 + namlen > reclen {
            fail_extra("malformed getdirentries record in inode parity probe");
        }
        if std::slice::from_raw_parts(record.add(21), namlen) == name {
            return inode;
        }
        offset += reclen;
    }
    fail_extra(format!(
        "getdirentries did not return inode-parity entry {:?}",
        String::from_utf8_lossy(name)
    ));
}

#[cfg(target_os = "linux")]
unsafe fn directory_entry_inode(fd: libc::c_int, name: &[u8]) -> u64 {
    let duplicate = libc::dup(fd);
    if duplicate < 0 {
        fail_extra(format!(
            "dup directory for inode parity failed: {}",
            errno()
        ));
    }
    let mut bytes = vec![0u8; 64 * 1024];
    let read = direct_getdents64(duplicate, bytes.as_mut_ptr().cast(), bytes.len());
    libc::close(duplicate);
    if read < 0 {
        fail_extra(format!("getdents64 for inode parity failed: {}", errno()));
    }
    let mut offset = 0usize;
    while offset < read as usize {
        let record = bytes.as_ptr().add(offset);
        let inode = (record as *const u64).read_unaligned();
        let reclen = (record.add(16) as *const u16).read_unaligned() as usize;
        if reclen < 20 || offset + reclen > read as usize {
            fail_extra("malformed getdents64 record in inode parity probe");
        }
        let name_region = std::slice::from_raw_parts(record.add(19), reclen - 19);
        let namlen = name_region
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_region.len());
        if &name_region[..namlen] == name {
            return inode;
        }
        offset += reclen;
    }
    fail_extra(format!(
        "getdents64 did not return inode-parity entry {:?}",
        String::from_utf8_lossy(name)
    ));
}

unsafe fn run_fstatat(
    label: &str,
    dirfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
) {
    let mut stat = std::mem::zeroed::<libc::stat>();
    set_errno(0);
    let result = libc::fstatat(dirfd, path, &mut stat, flags);
    report_stat(label, result, stat);
}

unsafe fn run_faccessat(
    label: &str,
    dirfd: libc::c_int,
    path: *const libc::c_char,
    mode: libc::c_int,
    flags: libc::c_int,
) {
    set_errno(0);
    let result = libc::faccessat(dirfd, path, mode, flags);
    report_status(label, result);
}

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(first) = arguments.next() else {
        eprintln!("usage: vfs_at_parity_probe <fixture-root>");
        std::process::exit(2);
    };
    if first == "--exec-read-fd" {
        let fd = arguments
            .next()
            .and_then(|value| value.to_string_lossy().parse::<libc::c_int>().ok())
            .unwrap_or_else(|| {
                eprintln!("missing inherited descriptor");
                std::process::exit(2);
            });
        let expected = arguments
            .next()
            .and_then(|value| value.as_bytes().first().copied())
            .unwrap_or_else(|| {
                eprintln!("missing inherited descriptor byte");
                std::process::exit(2);
            });
        let mut byte = 0u8;
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read != 1 || byte != expected {
            eprintln!(
                "exec-inherited descriptor returned read={read}, byte={byte}, expected={expected}"
            );
            std::process::exit(5);
        }
        return;
    }
    let root = first;
    let root = Path::new(&root);

    if let Ok(expected) = std::env::var("KIN_EXPECT_CANARY") {
        if std::env::var("KIN_VFS_INTERPOSE_ACTIVE").as_deref() != Ok(expected.as_str()) {
            eprintln!("shim did not stamp the expected interposition canary");
            std::process::exit(4);
        }
    }
    let graph_owned = std::env::var_os("KIN_EXPECT_GRAPH_OWNED").is_some();
    let expected_first = if graph_owned { b'g' } else { b'd' };
    let expected_second = if graph_owned { b'r' } else { b'i' };

    let root_c = c_path(root);

    #[cfg(target_os = "linux")]
    if let Ok(kind) = std::env::var("KIN_FORTIFY_ABORT_KIND") {
        let flags = libc::O_TMPFILE | libc::O_RDWR;
        unsafe {
            match kind.as_str() {
                "open" => {
                    fortified_open_2(root_c.as_ptr(), flags);
                }
                "open64" => {
                    fortified_open64_2(root_c.as_ptr(), flags);
                }
                "openat" => {
                    fortified_openat_2(libc::AT_FDCWD, root_c.as_ptr(), flags);
                }
                "openat64" => {
                    fortified_openat64_2(libc::AT_FDCWD, root_c.as_ptr(), flags);
                }
                _ => fail_extra(format!("unknown fortified abort kind {kind}")),
            }
        }
        fail_extra(format!(
            "fortified {kind} returned instead of enforcing __OPEN_NEEDS_MODE"
        ));
    }

    let file_absolute = c_path(&root.join("file.txt"));
    let link_absolute = c_path(&root.join("link.txt"));
    let dangling_link_absolute = c_path(&root.join("dangling-link.txt"));
    let racy_readlink_absolute = c_path(&root.join("racy-readlink.txt"));
    let readonly_absolute = c_path(&root.join("readonly.txt"));
    let writeonly_absolute = c_path(&root.join("writeonly.txt"));
    let noaccess_absolute = c_path(&root.join("noaccess.txt"));
    let create_0555_absolute = c_path(&root.join("create-0555/new-open.txt"));
    let create_0333_absolute = c_path(&root.join("create-0333/new-open.txt"));
    let create_0000_absolute = c_path(&root.join("create-0000/new-open.txt"));
    let create_0555_exclusive_absolute = c_path(&root.join("create-0555/new-exclusive.txt"));
    let create_0333_exclusive_absolute = c_path(&root.join("create-0333/new-exclusive.txt"));
    let create_0000_exclusive_absolute = c_path(&root.join("create-0000/new-exclusive.txt"));
    let create_0555_at_absolute = c_path(&root.join("create-0555/new-openat.txt"));
    let create_0333_at_absolute = c_path(&root.join("create-0333/new-openat.txt"));
    let create_0000_at_absolute = c_path(&root.join("create-0000/new-openat.txt"));
    let create_0555_at_exclusive_absolute =
        c_path(&root.join("create-0555/new-openat-exclusive.txt"));
    let create_0333_at_exclusive_absolute =
        c_path(&root.join("create-0333/new-openat-exclusive.txt"));
    let create_0000_at_exclusive_absolute =
        c_path(&root.join("create-0000/new-openat-exclusive.txt"));
    let directory_absolute = c_path(&root.join("dir"));
    let nosearch_child_absolute = c_path(&root.join("nosearch/child.txt"));
    #[cfg(target_os = "macos")]
    let dir_absolute = c_path(&root.join("dir"));
    let nested_absolute = c_path(&root.join("dir-link").join("nested.txt"));
    let file_relative = CString::new("file.txt").expect("static file name");
    let nested_relative =
        CString::new("dir-link/nested.txt").expect("static intermediate-link path");
    let graph_only_relative = CString::new("graph-only.txt").expect("static graph-only name");
    let graph_only_parent_absolute = c_path(&root.join("dir/../graph-only.txt"));
    let graph_only_parent_relative =
        CString::new("dir/../graph-only.txt").expect("static parent-traversal graph path");
    #[cfg(target_os = "linux")]
    let missing_relative = CString::new("missing.txt").expect("static missing path");
    #[cfg(target_os = "linux")]
    let readonly_relative = CString::new("readonly.txt").expect("static readonly name");
    #[cfg(target_os = "linux")]
    let writeonly_relative = CString::new("writeonly.txt").expect("static writeonly name");
    #[cfg(target_os = "linux")]
    let noaccess_relative = CString::new("noaccess.txt").expect("static noaccess name");
    let racy_at_cwd_relative = CString::new("racy-at-cwd.txt").expect("static racy cwd link");
    let racy_at_dirfd_from_parent = {
        let root_name = root
            .file_name()
            .expect("fixture root has a basename")
            .as_bytes();
        let mut path = root_name.to_vec();
        path.extend_from_slice(b"/racy-at-dirfd.txt");
        CString::new(path).expect("racy real-dirfd path contains no NUL")
    };
    let concurrent_relative = CString::new("concurrent.bin").expect("static concurrent-read name");
    let stateful_relative = CString::new("stateful.bin").expect("static stateful name");
    let unlinked_relative = CString::new("unlinked.bin").expect("static unlinked name");
    let renamed_relative = CString::new("renamed.bin").expect("static renamed name");
    let moved_relative = CString::new("moved.bin").expect("static moved name");
    let renamed_dir_relative = CString::new("renamed-dir").expect("static renamed directory");
    let moved_dir_relative = CString::new("moved-dir").expect("static moved directory");
    let renamed_dir_child_relative =
        CString::new("child.txt").expect("static renamed-directory child");
    let trigger_relative = CString::new("trigger.txt").expect("static trigger name");
    #[cfg(target_os = "macos")]
    let multi_relative = CString::new("multi.txt").expect("static multi-link name");
    let dir_relative = CString::new("dir").expect("static directory name");
    #[cfg(target_os = "macos")]
    let beneath_escape_relative =
        CString::new("../dir/nested.txt").expect("static beneath escape path");
    #[cfg(target_os = "macos")]
    let beneath_bounce_relative =
        CString::new("bounce-link").expect("static beneath bounce-link name");
    #[cfg(target_os = "macos")]
    let beneath_order_relative =
        CString::new("order-link/../file.txt").expect("static ordered symlink-parent path");
    #[cfg(target_os = "macos")]
    let parent_relative = CString::new("../").expect("static parent path");
    let child_relative = CString::new("child").expect("static child name");
    let link_relative = CString::new("link.txt").expect("static link name");
    #[cfg(target_os = "linux")]
    let dot_relative = CString::new(".").expect("static dot path");
    let empty = CString::new("").expect("empty C string");
    let mut link_buf = [0u8; 64];

    unsafe {
        set_errno(0);
        let rootfd = libc::open(root_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if rootfd < 0 {
            eprintln!("open fixture root failed: {}", errno());
            std::process::exit(3);
        }

        set_errno(0);
        let filefd = libc::openat(
            rootfd,
            file_relative.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK,
        );
        if filefd < 0 {
            eprintln!("open fixture file failed: {}", errno());
            std::process::exit(3);
        }
        let initial_file_status = libc::fcntl(filefd, libc::F_GETFL);
        if initial_file_status < 0 || initial_file_status & libc::O_NONBLOCK == 0 {
            fail_extra(format!(
                "initial F_GETFL lost supplied status flags: {}",
                errno()
            ));
        }
        println!("fcntl-status-before-bridge=ok");

        let mut directory_byte = 0u8;
        set_errno(0);
        if libc::read(rootfd, (&mut directory_byte as *mut u8).cast(), 1) != -1
            || errno() != libc::EISDIR
        {
            fail_extra(format!(
                "read on directory did not return EISDIR: {}",
                errno()
            ));
        }
        set_errno(0);
        if libc::pread(rootfd, (&mut directory_byte as *mut u8).cast(), 1, 0) != -1
            || errno() != libc::EISDIR
        {
            fail_extra(format!(
                "pread on directory did not return EISDIR: {}",
                errno()
            ));
        }
        println!("directory-read-pread-eisdir=ok");

        let mut run_descriptor_state_matrix = || {
            // Synthetic directory duplicates share one open-file-description
            // cursor. The native bridge remains intentionally fail-closed
            // until a mounted graph namespace or exec-rehydration contract can
            // preserve nested paths, symlinks, writes, cookies, and lifetime.
            let directory_duplicate = libc::dup(rootfd);
            if directory_duplicate < 0 {
                fail_extra(format!("dup directory for rewind proof: {}", errno()));
            }
            set_errno(0);
            if libc::read(
                directory_duplicate,
                (&mut directory_byte as *mut u8).cast(),
                1,
            ) != -1
                || errno() != libc::EISDIR
            {
                fail_extra(format!(
                    "read on duplicated directory did not return EISDIR: {}",
                    errno()
                ));
            }
            set_errno(0);
            if libc::pread(
                directory_duplicate,
                (&mut directory_byte as *mut u8).cast(),
                1,
                0,
            ) != -1
                || errno() != libc::EISDIR
            {
                fail_extra(format!(
                    "pread on duplicated directory did not return EISDIR: {}",
                    errno()
                ));
            }
            if libc::lseek(rootfd, 0, libc::SEEK_SET) != 0 {
                fail_extra(format!(
                    "prepare directory cursor for shared rewind proof: {}",
                    errno()
                ));
            }
            let first_directory_inode = directory_entry_inode(directory_duplicate, b"file.txt");
            if libc::lseek(rootfd, 0, libc::SEEK_SET) != 0 {
                fail_extra(format!("rewind directory after enumeration: {}", errno()));
            }
            let rewound_directory_inode = directory_entry_inode(rootfd, b"file.txt");
            if first_directory_inode == 0 || rewound_directory_inode != first_directory_inode {
                fail_extra("directory lseek did not rewind the shared enumeration cursor");
            }
            if libc::lseek(rootfd, 0, libc::SEEK_SET) != 0 {
                fail_extra(format!(
                    "restore directory cursor after rewind proof: {}",
                    errno()
                ));
            }
            println!("directory-duplicate-rewind=ok");
            libc::close(directory_duplicate);

            let mut directory_target = [0; 2];
            if libc::pipe(directory_target.as_mut_ptr()) != 0 {
                fail_extra(format!("create status-flags dup2 target: {}", errno()));
            }
            libc::close(directory_target[1]);
            if libc::dup2(filefd, directory_target[0]) != directory_target[0] {
                fail_extra(format!("bridge status-flags low target: {}", errno()));
            }
            let bridged_status = libc::fcntl(filefd, libc::F_GETFL);
            if bridged_status < 0
                || bridged_status & (libc::O_APPEND | libc::O_NONBLOCK)
                    != initial_file_status & (libc::O_APPEND | libc::O_NONBLOCK)
            {
                fail_extra(format!(
                    "F_GETFL status drifted after lazy bridge: {}",
                    errno()
                ));
            }
            println!("fcntl-status-after-bridge=ok");
            let status_child = libc::fork();
            if status_child < 0 {
                fail_extra(format!("fork status-flags child: {}", errno()));
            }
            if status_child == 0 {
                libc::_exit(
                    if libc::fcntl(
                        directory_target[0],
                        libc::F_SETFL,
                        bridged_status | libc::O_APPEND,
                    ) == 0
                    {
                        0
                    } else {
                        20
                    },
                );
            }
            let mut status_child_result = 0;
            if libc::waitpid(status_child, &mut status_child_result, 0) != status_child
                || status_child_result != 0
            {
                fail_extra(format!(
                    "child F_SETFL failed: status={status_child_result}"
                ));
            }
            let child_updated_status = libc::fcntl(filefd, libc::F_GETFL);
            if child_updated_status < 0
                || child_updated_status & libc::O_APPEND == 0
                || child_updated_status & libc::O_NONBLOCK == 0
            {
                fail_extra("parent F_GETFL did not observe child F_SETFL");
            }
            if libc::fcntl(filefd, libc::F_SETFL, bridged_status) != 0 {
                fail_extra(format!("restore status after child F_SETFL: {}", errno()));
            }
            println!("fcntl-setfl-shared-across-fork=ok");
            if libc::fcntl(
                directory_target[0],
                libc::F_SETFL,
                bridged_status | libc::O_APPEND,
            ) != 0
            {
                fail_extra(format!("F_SETFL through low duplicate failed: {}", errno()));
            }
            let updated_original = libc::fcntl(filefd, libc::F_GETFL);
            if updated_original < 0
                || updated_original & libc::O_APPEND == 0
                || updated_original & libc::O_NONBLOCK == 0
            {
                fail_extra("F_SETFL through low duplicate was not shared with the source");
            }
            if libc::fcntl(filefd, libc::F_SETFL, bridged_status) != 0 {
                fail_extra(format!("restore shared F_SETFL status: {}", errno()));
            }
            let restored_duplicate = libc::fcntl(directory_target[0], libc::F_GETFL);
            if restored_duplicate < 0
                || restored_duplicate & (libc::O_APPEND | libc::O_NONBLOCK)
                    != bridged_status & (libc::O_APPEND | libc::O_NONBLOCK)
            {
                fail_extra("F_SETFL through source was not shared with the low duplicate");
            }
            println!("fcntl-setfl-shared-across-duplicates=ok");
            if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
                fail_extra(format!("reset file after low-target reuse: {}", errno()));
            }
            let mut reused_byte = 0u8;
            if libc::read(directory_target[0], (&mut reused_byte as *mut u8).cast(), 1) != 1
                || reused_byte != expected_first
            {
                fail_extra("low target did not preserve graph file bytes");
            }
            println!("file-low-bridge-read=ok");
            libc::close(directory_target[0]);
            if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
                fail_extra(format!("reset file after status matrix: {}", errno()));
            }
        };

        // The provider replaces each racy symlink after its metadata lookup.
        // Native disk keeps the old target. Snapshot-correct interposition must
        // therefore still report the same old bytes in all three path modes.
        let mut racy_buf = [0u8; 64];
        set_errno(0);
        let result = libc::readlink(
            racy_readlink_absolute.as_ptr(),
            racy_buf.as_mut_ptr().cast(),
            racy_buf.len(),
        );
        report_readlink("readlink-snapshot-race", result, &racy_buf);

        let saved_cwd = libc::open(c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if saved_cwd < 0 || libc::chdir(root_c.as_ptr()) != 0 {
            fail_extra(format!("prepare AT_FDCWD readlink race: {}", errno()));
        }
        racy_buf.fill(0);
        set_errno(0);
        let result = libc::readlinkat(
            libc::AT_FDCWD,
            racy_at_cwd_relative.as_ptr(),
            racy_buf.as_mut_ptr().cast(),
            racy_buf.len(),
        );
        report_readlink("readlinkat-cwd-snapshot-race", result, &racy_buf);
        if libc::fchdir(saved_cwd) != 0 || libc::close(saved_cwd) != 0 {
            fail_extra(format!("restore cwd after readlink race: {}", errno()));
        }

        let parent = root.parent().expect("fixture root has a parent");
        let parent_c = c_path(parent);
        let real_parent_fd = libc::open(parent_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if real_parent_fd < 0 {
            fail_extra(format!("open real parent dirfd: {}", errno()));
        }
        racy_buf.fill(0);
        set_errno(0);
        let result = libc::readlinkat(
            real_parent_fd,
            racy_at_dirfd_from_parent.as_ptr(),
            racy_buf.as_mut_ptr().cast(),
            racy_buf.len(),
        );
        report_readlink("readlinkat-real-dirfd-snapshot-race", result, &racy_buf);
        if libc::close(real_parent_fd) != 0 {
            fail_extra(format!("close real parent dirfd: {}", errno()));
        }

        // Ordinary access modes must be enforced from graph metadata before a
        // writable staging file can accidentally grant stronger rights.
        for (surface, path, dirfd, name) in [
            (
                "open",
                readonly_absolute.as_ptr(),
                libc::AT_FDCWD,
                readonly_absolute.as_ptr(),
            ),
            (
                "openat",
                readonly_absolute.as_ptr(),
                libc::AT_FDCWD,
                readonly_absolute.as_ptr(),
            ),
        ] {
            for (mode_label, flags) in [
                ("rdonly", libc::O_RDONLY),
                ("wronly", libc::O_WRONLY),
                ("rdwr", libc::O_RDWR),
            ] {
                let label = format!("{surface}-readonly-{mode_label}");
                set_errno(0);
                let fd = if surface == "open" {
                    libc::open(path, flags)
                } else {
                    libc::openat(dirfd, name, flags)
                };
                report_fd(&label, fd);
            }
        }
        for (surface, path) in [
            ("open", writeonly_absolute.as_ptr()),
            ("openat", writeonly_absolute.as_ptr()),
        ] {
            for (mode_label, flags) in [
                ("rdonly", libc::O_RDONLY),
                ("wronly", libc::O_WRONLY),
                ("rdwr", libc::O_RDWR),
            ] {
                let label = format!("{surface}-writeonly-{mode_label}");
                set_errno(0);
                let fd = if surface == "open" {
                    libc::open(path, flags)
                } else {
                    libc::openat(libc::AT_FDCWD, path, flags)
                };
                report_fd(&label, fd);
            }
        }

        for (mode, absolute, exclusive) in [
            (
                "0555",
                create_0555_absolute.as_ptr(),
                create_0555_exclusive_absolute.as_ptr(),
            ),
            (
                "0333",
                create_0333_absolute.as_ptr(),
                create_0333_exclusive_absolute.as_ptr(),
            ),
            (
                "0000",
                create_0000_absolute.as_ptr(),
                create_0000_exclusive_absolute.as_ptr(),
            ),
        ] {
            set_errno(0);
            let fd = libc::open(absolute, libc::O_CREAT | libc::O_WRONLY, 0o600);
            report_created_fd(&format!("open-create-parent-{mode}"), fd, absolute);

            set_errno(0);
            let fd = libc::open(
                exclusive,
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
                0o600,
            );
            report_created_fd(
                &format!("open-create-exclusive-parent-{mode}"),
                fd,
                exclusive,
            );
        }
        for (mode, absolute, exclusive) in [
            (
                "0555",
                &create_0555_at_absolute,
                &create_0555_at_exclusive_absolute,
            ),
            (
                "0333",
                &create_0333_at_absolute,
                &create_0333_at_exclusive_absolute,
            ),
            (
                "0000",
                &create_0000_at_absolute,
                &create_0000_at_exclusive_absolute,
            ),
        ] {
            set_errno(0);
            let fd = libc::openat(
                libc::AT_FDCWD,
                absolute.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY,
                0o600,
            );
            report_created_fd(
                &format!("openat-create-parent-{mode}"),
                fd,
                absolute.as_ptr(),
            );

            set_errno(0);
            let fd = libc::openat(
                libc::AT_FDCWD,
                exclusive.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
                0o600,
            );
            report_created_fd(
                &format!("openat-create-exclusive-parent-{mode}"),
                fd,
                exclusive.as_ptr(),
            );
        }
        for (surface, path) in [
            ("open", noaccess_absolute.as_ptr()),
            ("openat", noaccess_absolute.as_ptr()),
        ] {
            for (mode_label, flags) in [
                ("rdonly", libc::O_RDONLY),
                ("wronly", libc::O_WRONLY),
                ("rdwr", libc::O_RDWR),
            ] {
                let label = format!("{surface}-noaccess-{mode_label}");
                set_errno(0);
                let fd = if surface == "open" {
                    libc::open(path, flags)
                } else {
                    libc::openat(libc::AT_FDCWD, path, flags)
                };
                report_fd(&label, fd);
            }
        }
        for (label, path, flags, at) in [
            (
                "open-directory-wronly",
                directory_absolute.as_ptr(),
                libc::O_WRONLY,
                false,
            ),
            (
                "open-directory-rdwr",
                directory_absolute.as_ptr(),
                libc::O_RDWR,
                false,
            ),
            (
                "openat-directory-wronly",
                directory_absolute.as_ptr(),
                libc::O_WRONLY,
                true,
            ),
            (
                "openat-directory-rdwr",
                directory_absolute.as_ptr(),
                libc::O_RDWR,
                true,
            ),
            (
                "open-no-search-child",
                nosearch_child_absolute.as_ptr(),
                libc::O_RDONLY,
                false,
            ),
            (
                "openat-no-search-child",
                nosearch_child_absolute.as_ptr(),
                libc::O_RDONLY,
                true,
            ),
        ] {
            set_errno(0);
            let fd = if at {
                libc::openat(libc::AT_FDCWD, path, flags)
            } else {
                libc::open(path, flags)
            };
            report_fd(label, fd);
        }

        for (surface, path) in [
            ("open", link_absolute.as_ptr()),
            ("open-dangling", dangling_link_absolute.as_ptr()),
            ("openat", link_absolute.as_ptr()),
            ("openat-dangling", dangling_link_absolute.as_ptr()),
        ] {
            for (suffix, extra) in [("", 0), ("-nofollow", libc::O_NOFOLLOW)] {
                let label = format!("{surface}-exclusive-symlink{suffix}");
                set_errno(0);
                let flags = libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | extra;
                let fd = if surface.starts_with("openat") {
                    libc::openat(libc::AT_FDCWD, path, flags, 0o600)
                } else {
                    libc::open(path, flags, 0o600)
                };
                report_fd(&label, fd);
            }
        }

        if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
            fail_extra(format!("reset file before dup: {}", errno()));
        }
        let duplicate = libc::dup(filefd);
        if duplicate < 0 {
            fail_extra(format!("dup virtual file: {}", errno()));
        }
        let mut byte = 0u8;
        if libc::read(filefd, (&mut byte as *mut u8).cast(), 1) != 1
            || libc::read(duplicate, (&mut byte as *mut u8).cast(), 1) != 1
            || libc::lseek(filefd, 0, libc::SEEK_CUR) != 2
        {
            fail_extra(format!("dup did not share file offset: {}", errno()));
        }
        println!("dup-shared-offset=ok");
        libc::close(duplicate);

        if libc::lseek(filefd, libc::off_t::MAX, libc::SEEK_SET) != libc::off_t::MAX {
            fail_extra(format!(
                "set maximum representable file offset: {}",
                errno()
            ));
        }
        set_errno(0);
        if libc::lseek(filefd, 1, libc::SEEK_CUR) != -1
            || errno() != libc::EOVERFLOW
            || libc::lseek(filefd, 0, libc::SEEK_CUR) != libc::off_t::MAX
        {
            fail_extra(format!(
                "SEEK_CUR overflow changed or clamped the offset: {}",
                errno()
            ));
        }
        println!("lseek-cur-overflow-preserves-offset=ok");

        if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
            fail_extra(format!("reset before SEEK_END overflow: {}", errno()));
        }
        set_errno(0);
        if libc::lseek(filefd, libc::off_t::MAX, libc::SEEK_END) != -1
            || errno() != libc::EOVERFLOW
            || libc::lseek(filefd, 0, libc::SEEK_CUR) != 0
        {
            fail_extra(format!(
                "SEEK_END overflow changed or clamped the offset: {}",
                errno()
            ));
        }
        println!("lseek-end-overflow-preserves-offset=ok");

        let mut pipe_fds = [0; 2];
        if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
            fail_extra(format!("create dup2 target pipe: {}", errno()));
        }
        libc::close(pipe_fds[1]);
        if libc::lseek(filefd, 0, libc::SEEK_SET) != 0
            || libc::dup2(filefd, pipe_fds[0]) != pipe_fds[0]
            || libc::read(pipe_fds[0], (&mut byte as *mut u8).cast(), 1) != 1
            || byte != expected_first
            || libc::lseek(filefd, 0, libc::SEEK_CUR) != 1
        {
            fail_extra(format!("dup2 ordinary target semantics: {}", errno()));
        }
        println!("dup2-native-target=ok");
        let low_getfl = libc::fcntl(pipe_fds[0], libc::F_GETFL);
        if low_getfl < 0
            || low_getfl & libc::O_ACCMODE != libc::O_RDONLY
            || low_getfl & (libc::O_APPEND | libc::O_NONBLOCK)
                != initial_file_status & (libc::O_APPEND | libc::O_NONBLOCK)
        {
            fail_extra(format!("fcntl F_GETFL on low bridge: {}", errno()));
        }
        println!("fcntl-low-getfl=ok");
        let low_duplicate = libc::fcntl(pipe_fds[0], libc::F_DUPFD, 3);
        if low_duplicate < 0
            || libc::read(low_duplicate, (&mut byte as *mut u8).cast(), 1) != 1
            || byte != expected_second
            || libc::lseek(filefd, 0, libc::SEEK_CUR) != 2
        {
            fail_extra(format!("fcntl F_DUPFD on low bridge: {}", errno()));
        }
        println!("fcntl-low-dupfd-graph-bytes=ok");
        libc::close(low_duplicate);
        libc::close(pipe_fds[0]);

        #[cfg(target_os = "linux")]
        {
            let mut pipe_fds = [0; 2];
            if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
                fail_extra(format!("create dup3 target pipe: {}", errno()));
            }
            libc::close(pipe_fds[1]);
            if libc::lseek(filefd, 0, libc::SEEK_SET) != 0
                || libc::dup3(filefd, pipe_fds[0], libc::O_CLOEXEC) != pipe_fds[0]
                || libc::fcntl(pipe_fds[0], libc::F_GETFD) & libc::FD_CLOEXEC == 0
                || libc::read(pipe_fds[0], (&mut byte as *mut u8).cast(), 1) != 1
                || libc::lseek(filefd, 0, libc::SEEK_CUR) != 1
            {
                fail_extra(format!("dup3 ordinary target semantics: {}", errno()));
            }
            println!("dup3-native-target=ok");
            libc::close(pipe_fds[0]);
        }

        let getfl = libc::fcntl(filefd, libc::F_GETFL);
        if getfl < 0
            || getfl & libc::O_ACCMODE != libc::O_RDONLY
            || getfl & (libc::O_APPEND | libc::O_NONBLOCK)
                != initial_file_status & (libc::O_APPEND | libc::O_NONBLOCK)
        {
            fail_extra(format!("fcntl F_GETFL on graph descriptor: {}", errno()));
        }
        println!("fcntl-getfl=ok");

        if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
            fail_extra(format!("reset file before F_DUPFD: {}", errno()));
        }
        let fcntl_duplicate = libc::fcntl(filefd, libc::F_DUPFD, 3);
        if fcntl_duplicate < 0
            || libc::fcntl(fcntl_duplicate, libc::F_GETFL) & (libc::O_APPEND | libc::O_NONBLOCK)
                != initial_file_status & (libc::O_APPEND | libc::O_NONBLOCK)
            || libc::read(filefd, (&mut byte as *mut u8).cast(), 1) != 1
            || libc::read(fcntl_duplicate, (&mut byte as *mut u8).cast(), 1) != 1
            || libc::lseek(filefd, 0, libc::SEEK_CUR) != 2
        {
            fail_extra(format!("fcntl F_DUPFD shared offset: {}", errno()));
        }
        println!("fcntl-dupfd-shared-offset=ok");
        libc::close(fcntl_duplicate);

        let fcntl_cloexec_duplicate = libc::fcntl(filefd, libc::F_DUPFD_CLOEXEC, 3);
        if fcntl_cloexec_duplicate < 0
            || libc::fcntl(fcntl_cloexec_duplicate, libc::F_GETFD) & libc::FD_CLOEXEC == 0
        {
            fail_extra(format!("fcntl F_DUPFD_CLOEXEC flags: {}", errno()));
        }
        println!("fcntl-dupfd-cloexec=ok");
        libc::close(fcntl_cloexec_duplicate);

        if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
            fail_extra(format!("reset file before fork: {}", errno()));
        }
        let mut fork_target = [0; 2];
        if libc::pipe(fork_target.as_mut_ptr()) != 0 {
            fail_extra(format!("create fork target pipe: {}", errno()));
        }
        libc::close(fork_target[1]);
        if libc::dup2(filefd, fork_target[0]) != fork_target[0] {
            fail_extra(format!("bridge fork target: {}", errno()));
        }
        let child = libc::fork();
        if child < 0 {
            fail_extra(format!("fork descriptor child: {}", errno()));
        }
        if child == 0 {
            let mut first = 0u8;
            let result = libc::read(
                fork_target[0],
                (&mut first as *mut u8).cast::<libc::c_void>(),
                1,
            );
            libc::_exit(if result == 1 && first == expected_first {
                0
            } else {
                6
            });
        }
        let mut status = 0;
        if libc::waitpid(child, &mut status, 0) != child || status != 0 {
            fail_extra(format!(
                "fork child did not read graph bytes: status={status}"
            ));
        }
        let mut second = 0u8;
        if libc::read(filefd, (&mut second as *mut u8).cast(), 1) != 1
            || second != expected_second
            || libc::lseek(filefd, 0, libc::SEEK_CUR) != 2
        {
            fail_extra(format!("fork did not share native file state: {}", errno()));
        }
        println!("fork-low-fd-shared-offset=ok");
        libc::close(fork_target[0]);

        if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
            fail_extra(format!("reset file before exec: {}", errno()));
        }
        let mut exec_target = [0; 2];
        if libc::pipe(exec_target.as_mut_ptr()) != 0 {
            fail_extra(format!("create exec target pipe: {}", errno()));
        }
        libc::close(exec_target[1]);
        let executable = c_path(&std::env::current_exe().unwrap_or_else(|error| {
            fail_extra(format!("resolve current probe for exec: {error}"))
        }));
        let helper = CString::new("--exec-read-fd").expect("static exec helper argument");
        let target_argument =
            CString::new(exec_target[0].to_string()).expect("numeric descriptor argument");
        let expected_argument =
            CString::new(vec![expected_first]).expect("single expected descriptor byte");
        let child = libc::fork();
        if child < 0 {
            fail_extra(format!("fork exec descriptor child: {}", errno()));
        }
        if child == 0 {
            if libc::dup2(filefd, exec_target[0]) != exec_target[0] {
                libc::_exit(7);
            }
            libc::execl(
                executable.as_ptr(),
                executable.as_ptr(),
                helper.as_ptr(),
                target_argument.as_ptr(),
                expected_argument.as_ptr(),
                ptr::null::<libc::c_char>(),
            );
            libc::_exit(8);
        }
        if libc::waitpid(child, &mut status, 0) != child || status != 0 {
            fail_extra(format!(
                "exec child did not inherit graph-backed low fd: status={status}"
            ));
        }
        println!("exec-low-fd-graph-bytes=ok");
        libc::close(exec_target[0]);

        if libc::lseek(filefd, 0, libc::SEEK_SET) != 0 {
            fail_extra(format!("reset file after dup checks: {}", errno()));
        }

        let concurrent_fd = libc::openat(rootfd, concurrent_relative.as_ptr(), libc::O_RDONLY);
        if concurrent_fd < 0 {
            fail_extra(format!("open concurrent-read fixture: {}", errno()));
        }
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut readers = Vec::new();
        for _ in 0..2 {
            let barrier = std::sync::Arc::clone(&barrier);
            readers.push(std::thread::spawn(move || {
                let mut bytes = vec![0u8; 32 * 1024 + 1];
                barrier.wait();
                let read = libc::read(
                    concurrent_fd,
                    bytes.as_mut_ptr().cast::<libc::c_void>(),
                    bytes.len(),
                );
                (read, bytes)
            }));
        }
        barrier.wait();
        let mut observed = readers
            .into_iter()
            .map(|reader| reader.join().expect("concurrent reader did not panic"))
            .collect::<Vec<_>>();
        if observed.iter().any(|(read, _)| *read != 32 * 1024 + 1) {
            fail_extra("concurrent same-fd reads returned short data");
        }
        observed.sort_by_key(|(_, bytes)| bytes[0]);
        if !observed[0].1.iter().all(|byte| *byte == b'A')
            || !observed[1].1.iter().all(|byte| *byte == b'B')
        {
            fail_extra("concurrent same-fd reads returned an overlapping range");
        }
        println!("concurrent-uncached-shared-offset=ok");
        libc::close(concurrent_fd);

        set_errno(0);
        report_status(
            "read-valid-null-buffer",
            libc::read(filefd, ptr::null_mut(), 1) as libc::c_int,
        );
        set_errno(0);
        report_status(
            "pread-valid-null-buffer",
            libc::pread(filefd, ptr::null_mut(), 1, 0) as libc::c_int,
        );
        set_errno(0);
        report_status(
            "stat-valid-null-buffer",
            libc::stat(file_absolute.as_ptr(), ptr::null_mut()),
        );
        set_errno(0);
        report_status(
            "lstat-valid-null-buffer",
            libc::lstat(file_absolute.as_ptr(), ptr::null_mut()),
        );
        set_errno(0);
        report_status(
            "fstat-valid-null-buffer",
            libc::fstat(filefd, ptr::null_mut()),
        );
        set_errno(0);
        report_status(
            "readlink-valid-null-buffer",
            libc::readlink(link_absolute.as_ptr(), ptr::null_mut(), 1) as libc::c_int,
        );
        set_errno(0);
        report_status(
            "readlinkat-valid-null-buffer",
            libc::readlinkat(rootfd, link_relative.as_ptr(), ptr::null_mut(), 1) as libc::c_int,
        );
        set_errno(0);
        let readlinkat_file_empty = libc::readlinkat(
            filefd,
            empty.as_ptr(),
            link_buf.as_mut_ptr().cast(),
            link_buf.len(),
        );
        if readlinkat_file_empty < 0 {
            println!("readlinkat-file-empty=err:{}", errno());
        } else {
            println!("readlinkat-file-empty=ok");
        }

        #[cfg(target_os = "linux")]
        {
            set_errno(0);
            report_status(
                "readlink-valid-zero-size",
                libc::readlink(link_absolute.as_ptr(), link_buf.as_mut_ptr().cast(), 0)
                    as libc::c_int,
            );
            set_errno(0);
            report_status(
                "readlinkat-valid-zero-size",
                libc::readlinkat(
                    rootfd,
                    link_relative.as_ptr(),
                    link_buf.as_mut_ptr().cast(),
                    0,
                ) as libc::c_int,
            );
            set_errno(0);
            report_status(
                "getdents64-valid-null-buffer",
                direct_getdents64(rootfd, ptr::null_mut(), 4096) as libc::c_int,
            );

            macro_rules! report_null_stat {
                ($label:literal, $call:expr) => {{
                    set_errno(0);
                    let result = $call;
                    report_status($label, result);
                }};
            }
            report_null_stat!(
                "__xstat-valid-null-buffer",
                versioned_xstat(NATIVE_STAT_VERSION, file_absolute.as_ptr(), ptr::null_mut(),)
            );
            report_null_stat!(
                "__lxstat-valid-null-buffer",
                versioned_lxstat(NATIVE_STAT_VERSION, file_absolute.as_ptr(), ptr::null_mut(),)
            );
            report_null_stat!(
                "__fxstat-valid-null-buffer",
                versioned_fxstat(NATIVE_STAT_VERSION, filefd, ptr::null_mut())
            );
            report_null_stat!(
                "stat64-valid-null-buffer",
                direct_stat64(file_absolute.as_ptr(), ptr::null_mut())
            );
            report_null_stat!(
                "lstat64-valid-null-buffer",
                direct_lstat64(file_absolute.as_ptr(), ptr::null_mut())
            );
            report_null_stat!(
                "fstat64-valid-null-buffer",
                direct_fstat64(filefd, ptr::null_mut())
            );
            report_null_stat!(
                "__xstat64-valid-null-buffer",
                versioned_xstat64(NATIVE_STAT_VERSION, file_absolute.as_ptr(), ptr::null_mut(),)
            );
            report_null_stat!(
                "__lxstat64-valid-null-buffer",
                versioned_lxstat64(NATIVE_STAT_VERSION, file_absolute.as_ptr(), ptr::null_mut(),)
            );
            report_null_stat!(
                "__fxstat64-valid-null-buffer",
                versioned_fxstat64(NATIVE_STAT_VERSION, filefd, ptr::null_mut())
            );
        }

        #[cfg(target_os = "macos")]
        {
            let mut basep = 0;
            set_errno(0);
            report_status(
                "getdirentries-valid-null-buffer",
                getdirentries64_probe(rootfd, ptr::null_mut(), 4096, &mut basep) as libc::c_int,
            );
        }

        set_errno(0);
        report_fd("open-empty", libc::open(empty.as_ptr(), libc::O_RDONLY));
        let mut plain_stat = std::mem::zeroed::<libc::stat>();
        set_errno(0);
        report_stat(
            "stat-empty",
            libc::stat(empty.as_ptr(), &mut plain_stat),
            plain_stat,
        );
        plain_stat = std::mem::zeroed();
        set_errno(0);
        report_stat(
            "lstat-empty",
            libc::lstat(empty.as_ptr(), &mut plain_stat),
            plain_stat,
        );
        set_errno(0);
        report_status("access-empty", libc::access(empty.as_ptr(), libc::F_OK));
        set_errno(0);
        let readlink_empty = libc::readlink(
            empty.as_ptr(),
            link_buf.as_mut_ptr().cast::<libc::c_char>(),
            link_buf.len(),
        );
        if readlink_empty < 0 {
            println!("readlink-empty=err:{}", errno());
        } else {
            println!("readlink-empty=ok");
        }

        set_errno(0);
        report_fd(
            "open-nofollow-intermediate",
            libc::open(nested_absolute.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW),
        );
        set_errno(0);
        report_fd(
            "openat-relative",
            libc::openat(rootfd, file_relative.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-nofollow-intermediate",
            libc::openat(
                rootfd,
                nested_relative.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW,
            ),
        );
        set_errno(0);
        report_fd(
            "openat-absolute-ignores-dirfd",
            libc::openat(INVALID_DIRFD, file_absolute.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-invalid-dirfd",
            libc::openat(INVALID_DIRFD, file_relative.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-file-dirfd",
            libc::openat(filefd, child_relative.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-empty",
            libc::openat(rootfd, empty.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-null",
            libc::openat(rootfd, ptr::null(), libc::O_RDONLY),
        );

        #[cfg(target_os = "macos")]
        {
            set_errno(0);
            report_fd(
                "openat-invalid-access-mode",
                libc::openat(rootfd, file_relative.as_ptr(), libc::O_ACCMODE),
            );
        }

        #[cfg(target_os = "linux")]
        {
            for (label, path) in [
                ("mode3-readonly", readonly_relative.as_ptr()),
                ("mode3-writeonly", writeonly_relative.as_ptr()),
                ("mode3-noaccess", noaccess_relative.as_ptr()),
                ("mode3-directory", dir_relative.as_ptr()),
            ] {
                set_errno(0);
                report_fd(label, libc::openat(rootfd, path, libc::O_ACCMODE));
            }

            set_errno(0);
            let path_fd = libc::openat(rootfd, file_relative.as_ptr(), libc::O_PATH);
            if path_fd < 0 {
                println!("opath-file=err:{}", errno());
            } else {
                println!("opath-file=ok");
                let path_flags = libc::fcntl(path_fd, libc::F_GETFL);
                if path_flags < 0 || path_flags & libc::O_PATH == 0 {
                    fail_extra(format!("F_GETFL lost O_PATH: {}", errno()));
                }
                println!("opath-getfl=ok");
                let mut path_stat = std::mem::zeroed::<libc::stat>();
                set_errno(0);
                report_stat(
                    "opath-fstat",
                    libc::fstat(path_fd, &mut path_stat),
                    path_stat,
                );
                let mut byte = 0u8;
                set_errno(0);
                report_status(
                    "opath-read",
                    libc::read(path_fd, (&mut byte as *mut u8).cast(), 1) as libc::c_int,
                );
                set_errno(0);
                report_status(
                    "opath-pread",
                    libc::pread(path_fd, (&mut byte as *mut u8).cast(), 1, 0) as libc::c_int,
                );
                set_errno(0);
                report_status(
                    "opath-lseek",
                    libc::lseek(path_fd, 0, libc::SEEK_SET) as libc::c_int,
                );
                set_errno(0);
                report_status("opath-flock", libc::flock(path_fd, libc::LOCK_SH));
                set_errno(0);
                let mapped = libc::mmap(
                    ptr::null_mut(),
                    4096,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    path_fd,
                    0,
                );
                if mapped == libc::MAP_FAILED {
                    println!("opath-mmap=err:{}", errno());
                } else {
                    println!("opath-mmap=ok");
                    libc::munmap(mapped, 4096);
                }
                libc::close(path_fd);
            }

            set_errno(0);
            report_opath_ignored_fd(
                "opath-trunc-ignored",
                libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_PATH | libc::O_TRUNC | libc::O_WRONLY,
                ),
            );
            set_errno(0);
            report_opath_ignored_fd(
                "opath-mode3-ignored",
                libc::openat(
                    rootfd,
                    readonly_relative.as_ptr(),
                    libc::O_PATH | libc::O_ACCMODE,
                ),
            );
            set_errno(0);
            report_fd(
                "opath-create-ignored",
                libc::openat(
                    rootfd,
                    missing_relative.as_ptr(),
                    libc::O_PATH | libc::O_CREAT,
                    0o600 as libc::mode_t,
                ),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-open-directory",
                libc::open(root_c.as_ptr(), libc::O_PATH | libc::O_TMPFILE),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-open-file",
                libc::open(file_absolute.as_ptr(), libc::O_PATH | libc::O_TMPFILE),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-open64-directory",
                libc::open64(root_c.as_ptr(), libc::O_PATH | libc::O_TMPFILE),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-open64-file",
                libc::open64(file_absolute.as_ptr(), libc::O_PATH | libc::O_TMPFILE),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-openat-directory",
                libc::openat(
                    rootfd,
                    dot_relative.as_ptr(),
                    libc::O_PATH | libc::O_TMPFILE,
                ),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-openat-file",
                libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_PATH | libc::O_TMPFILE,
                ),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-openat64-directory",
                libc::openat64(
                    rootfd,
                    dot_relative.as_ptr(),
                    libc::O_PATH | libc::O_TMPFILE,
                ),
            );
            set_errno(0);
            report_fd(
                "opath-tmpfile-openat64-file",
                libc::openat64(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_PATH | libc::O_TMPFILE,
                ),
            );

            for (label, path) in [
                ("mode3-directory-readable", file_relative.as_ptr()),
                ("mode3-directory-writeonly", writeonly_relative.as_ptr()),
                ("mode3-directory-noaccess", noaccess_relative.as_ptr()),
                ("mode3-directory-directory", dir_relative.as_ptr()),
            ] {
                set_errno(0);
                report_fd(
                    label,
                    libc::openat(rootfd, path, libc::O_ACCMODE | libc::O_DIRECTORY),
                );
            }

            set_errno(0);
            let path_dirfd = libc::openat(rootfd, dir_relative.as_ptr(), libc::O_PATH);
            if path_dirfd < 0 {
                println!("opath-directory=err:{}", errno());
            } else {
                println!("opath-directory=ok");
                set_errno(0);
                report_status(
                    "opath-getdents64",
                    direct_getdents64(
                        path_dirfd,
                        link_buf.as_mut_ptr().cast::<libc::c_void>(),
                        link_buf.len(),
                    ) as libc::c_int,
                );
                libc::close(path_dirfd);
            }

            set_errno(0);
            let path_linkfd = libc::openat(
                rootfd,
                link_relative.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW,
            );
            if path_linkfd < 0 {
                println!("opath-symlink=err:{}", errno());
            } else {
                println!("opath-symlink=ok");
                set_errno(0);
                let read = libc::readlinkat(
                    path_linkfd,
                    empty.as_ptr(),
                    link_buf.as_mut_ptr().cast(),
                    link_buf.len(),
                );
                if read < 0 {
                    println!("opath-readlinkat-empty=err:{}", errno());
                } else {
                    println!("opath-readlinkat-empty=ok:{read}");
                }
                libc::close(path_linkfd);
            }
        }

        run_fstatat("fstatat-relative", rootfd, file_relative.as_ptr(), 0);
        run_fstatat(
            "fstatat-absolute-ignores-dirfd",
            INVALID_DIRFD,
            file_absolute.as_ptr(),
            0,
        );
        run_fstatat(
            "fstatat-invalid-dirfd",
            INVALID_DIRFD,
            file_relative.as_ptr(),
            0,
        );
        run_fstatat("fstatat-file-dirfd", filefd, child_relative.as_ptr(), 0);
        run_fstatat("fstatat-empty", rootfd, empty.as_ptr(), 0);
        run_fstatat("fstatat-null", rootfd, ptr::null(), 0);
        run_fstatat(
            "fstatat-invalid-flag",
            rootfd,
            file_relative.as_ptr(),
            INVALID_AT_FLAG,
        );
        run_fstatat(
            "fstatat-symlink-nofollow",
            rootfd,
            link_relative.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        );
        run_fstatat(
            "fstatat-nofollow-intermediate",
            rootfd,
            nested_relative.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        );
        set_errno(0);
        report_status(
            "fstatat-invalid-dirfd-null-buffer",
            libc::fstatat(INVALID_DIRFD, file_relative.as_ptr(), ptr::null_mut(), 0),
        );
        set_errno(0);
        report_status(
            "fstatat-empty-null-buffer",
            libc::fstatat(rootfd, empty.as_ptr(), ptr::null_mut(), 0),
        );
        set_errno(0);
        report_status(
            "fstatat-valid-null-buffer",
            libc::fstatat(rootfd, file_relative.as_ptr(), ptr::null_mut(), 0),
        );
        run_fstatat(
            "fstatat-at-empty-path",
            filefd,
            empty.as_ptr(),
            AT_EMPTY_PATH_VALUE,
        );
        run_fstatat(
            "fstatat-eaccess-is-invalid",
            rootfd,
            file_relative.as_ptr(),
            libc::AT_EACCESS,
        );
        #[cfg(target_os = "macos")]
        {
            run_fstatat(
                "fstatat-realdev",
                rootfd,
                file_relative.as_ptr(),
                AT_REALDEV_VALUE,
            );
            run_fstatat(
                "fstatat-fdonly",
                filefd,
                child_relative.as_ptr(),
                AT_FDONLY_VALUE,
            );
        }

        run_faccessat(
            "faccessat-f-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::F_OK,
            0,
        );
        run_faccessat(
            "faccessat-r-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::R_OK,
            0,
        );
        run_faccessat(
            "faccessat-w-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::W_OK,
            0,
        );
        run_faccessat(
            "faccessat-x-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::X_OK,
            0,
        );
        run_faccessat(
            "faccessat-extra-mode-bit",
            rootfd,
            file_relative.as_ptr(),
            EXTRA_ACCESS_MODE_BIT,
            0,
        );
        run_faccessat(
            "faccessat-all-mode-bits",
            rootfd,
            file_relative.as_ptr(),
            ALL_ACCESS_MODE_BITS,
            0,
        );
        run_faccessat(
            "faccessat-invalid-dirfd",
            INVALID_DIRFD,
            file_relative.as_ptr(),
            libc::F_OK,
            0,
        );
        run_faccessat(
            "faccessat-file-dirfd",
            filefd,
            child_relative.as_ptr(),
            libc::F_OK,
            0,
        );
        run_faccessat("faccessat-empty", rootfd, empty.as_ptr(), libc::F_OK, 0);
        run_faccessat("faccessat-null", rootfd, ptr::null(), libc::F_OK, 0);
        run_faccessat(
            "faccessat-invalid-flag",
            rootfd,
            file_relative.as_ptr(),
            libc::F_OK,
            INVALID_AT_FLAG,
        );
        run_faccessat(
            "faccessat-eaccess",
            rootfd,
            file_relative.as_ptr(),
            libc::R_OK | libc::W_OK,
            libc::AT_EACCESS,
        );
        run_faccessat(
            "faccessat-symlink-nofollow",
            rootfd,
            link_relative.as_ptr(),
            libc::F_OK,
            libc::AT_SYMLINK_NOFOLLOW,
        );
        run_faccessat(
            "faccessat-nofollow-intermediate",
            rootfd,
            nested_relative.as_ptr(),
            libc::F_OK,
            libc::AT_SYMLINK_NOFOLLOW,
        );
        run_faccessat(
            "faccessat-at-empty-path",
            filefd,
            empty.as_ptr(),
            libc::R_OK,
            AT_EMPTY_PATH_VALUE,
        );

        #[cfg(target_os = "macos")]
        {
            let ordered_dirfd = libc::openat(
                rootfd,
                dir_relative.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            );
            if ordered_dirfd < 0 {
                fail_extra(format!("open ordered traversal directory: {}", errno()));
            }
            set_errno(0);
            report_fd(
                "beneath-symlink-parent-order-open",
                libc::openat(
                    ordered_dirfd,
                    beneath_order_relative.as_ptr(),
                    libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                ),
            );
            run_fstatat(
                "beneath-symlink-parent-order-stat",
                ordered_dirfd,
                beneath_order_relative.as_ptr(),
                AT_RESOLVE_BENEATH_VALUE,
            );
            run_faccessat(
                "beneath-symlink-parent-order-access",
                ordered_dirfd,
                beneath_order_relative.as_ptr(),
                libc::F_OK,
                AT_RESOLVE_BENEATH_VALUE,
            );
            if libc::chdir(dir_absolute.as_ptr()) != 0 {
                fail_extra(format!(
                    "chdir ordered traversal directory for plain open: {}",
                    errno()
                ));
            }
            set_errno(0);
            report_fd(
                "beneath-symlink-parent-order-plain-open",
                libc::open(
                    beneath_order_relative.as_ptr(),
                    libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                ),
            );
            if libc::chdir(root_c.as_ptr()) != 0 {
                fail_extra(format!("restore parity workspace cwd: {}", errno()));
            }
            libc::close(ordered_dirfd);
        }

        #[cfg(target_os = "linux")]
        {
            let mut statx = std::mem::zeroed::<libc::statx>();
            set_errno(0);
            let result = libc::statx(
                rootfd,
                nested_relative.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BASIC_STATS,
                &mut statx,
            );
            if result == 0 {
                println!(
                    "statx-nofollow-intermediate=ok:{:o}",
                    statx.stx_mode as u32 & libc::S_IFMT as u32
                );
            } else {
                println!("statx-nofollow-intermediate=err:{}", errno());
            }

            set_errno(0);
            report_status(
                "statx-invalid-dirfd-null-buffer",
                libc::statx(
                    INVALID_DIRFD,
                    file_relative.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    ptr::null_mut(),
                ),
            );
            set_errno(0);
            report_status(
                "statx-empty-null-buffer",
                libc::statx(
                    rootfd,
                    empty.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    ptr::null_mut(),
                ),
            );
            set_errno(0);
            report_status(
                "statx-valid-null-buffer",
                libc::statx(
                    rootfd,
                    file_relative.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    ptr::null_mut(),
                ),
            );
        }

        if std::env::var_os("KIN_EXPECT_GRAPH_OWNED").is_some() {
            let vfd_base = expected_vfd_base();
            if rootfd < vfd_base || filefd < vfd_base {
                fail_extra(format!(
                    "root/file descriptors must be virtual (base {vfd_base}), got {rootfd}/{filefd}"
                ));
            }

            let root_dirent_inode = directory_entry_inode(rootfd, b"file.txt");
            let deep_path = root.join("dir/deep");
            let deep_relative = CString::new("dir/deep").expect("static deep path");
            let deep_dirfd = libc::openat(
                rootfd,
                deep_relative.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            );
            if deep_dirfd < vfd_base {
                fail_extra(format!(
                    "open deep directory for inode parity: fd={deep_dirfd}, errno={}",
                    errno()
                ));
            }
            let deep_dirent_inode = directory_entry_inode(deep_dirfd, b"file.txt");
            libc::close(deep_dirfd);
            let mut root_file_stat = std::mem::zeroed::<libc::stat>();
            if libc::stat(file_absolute.as_ptr(), &mut root_file_stat) != 0 {
                fail_extra(format!("stat root file for inode parity: {}", errno()));
            }
            let deep_file_absolute = c_path(&deep_path.join("file.txt"));
            let mut deep_file_stat = std::mem::zeroed::<libc::stat>();
            if libc::stat(deep_file_absolute.as_ptr(), &mut deep_file_stat) != 0 {
                fail_extra(format!("stat deep file for inode parity: {}", errno()));
            }
            if root_dirent_inode == 0
                || root_dirent_inode != root_file_stat.st_ino
                || deep_dirent_inode == 0
                || deep_dirent_inode != deep_file_stat.st_ino
            {
                fail_extra(format!(
                    "readdir/stat inode disagreement: root={root_dirent_inode}/{} deep={deep_dirent_inode}/{}",
                    root_file_stat.st_ino, deep_file_stat.st_ino
                ));
            }
            if root_dirent_inode == deep_dirent_inode {
                fail_extra("equal basenames in different directories collided in graph inode");
            }

            let mut graph_bytes = [0u8; 32];
            set_errno(0);
            let read = libc::read(
                filefd,
                graph_bytes.as_mut_ptr().cast::<libc::c_void>(),
                graph_bytes.len(),
            );
            if read != b"graph-parity\n".len() as isize
                || &graph_bytes[..read.max(0) as usize] != b"graph-parity\n"
            {
                fail_extra(format!(
                    "disk-divergent file did not return graph bytes: read={read}, errno={}",
                    errno()
                ));
            }

            set_errno(0);
            let graph_only = libc::openat(rootfd, graph_only_relative.as_ptr(), libc::O_RDONLY);
            if graph_only < vfd_base {
                fail_extra(format!(
                    "graph-only path did not allocate a virtual fd: fd={graph_only}, errno={}",
                    errno()
                ));
            }
            let mut only_bytes = [0u8; 32];
            let only_read = libc::read(
                graph_only,
                only_bytes.as_mut_ptr().cast::<libc::c_void>(),
                only_bytes.len(),
            );
            if only_read != b"graph-only\n".len() as isize
                || &only_bytes[..only_read.max(0) as usize] != b"graph-only\n"
            {
                fail_extra("graph-only entry was not served by the provider");
            }
            if libc::close(graph_only) != 0 {
                fail_extra(format!("close graph-only fd: {}", errno()));
            }

            if libc::chdir(root_c.as_ptr()) != 0 {
                fail_extra(format!(
                    "chdir graph workspace for parent traversal: {}",
                    errno()
                ));
            }
            for (label, fd) in [
                (
                    "absolute parent traversal",
                    libc::open(graph_only_parent_absolute.as_ptr(), libc::O_RDONLY),
                ),
                (
                    "cwd parent traversal",
                    libc::open(graph_only_parent_relative.as_ptr(), libc::O_RDONLY),
                ),
                (
                    "dirfd parent traversal",
                    libc::openat(rootfd, graph_only_parent_relative.as_ptr(), libc::O_RDONLY),
                ),
            ] {
                if fd < vfd_base {
                    fail_extra(format!(
                        "{label} escaped graph authority: fd={fd}, errno={}",
                        errno()
                    ));
                }
                let mut bytes = [0u8; 32];
                let read = libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len());
                if read != b"graph-only\n".len() as isize
                    || &bytes[..read.max(0) as usize] != b"graph-only\n"
                {
                    fail_extra(format!("{label} did not resolve graph-only bytes"));
                }
                libc::close(fd);
            }
            let mut parent_stat = std::mem::zeroed::<libc::stat>();
            if libc::stat(graph_only_parent_absolute.as_ptr(), &mut parent_stat) != 0 {
                fail_extra(format!(
                    "parent-traversal stat escaped graph authority: {}",
                    errno()
                ));
            }

            let mut opened = Vec::new();
            for (label, path) in [
                ("repoint", stateful_relative.as_ptr()),
                ("unlink", unlinked_relative.as_ptr()),
                ("rename", renamed_relative.as_ptr()),
            ] {
                let fd = libc::openat(rootfd, path, libc::O_RDONLY);
                if fd < vfd_base {
                    fail_extra(format!("open {label} identity descriptor: {}", errno()));
                }
                let mut stat = std::mem::zeroed::<libc::stat>();
                if libc::fstat(fd, &mut stat) != 0 {
                    fail_extra(format!("initial fstat {label}: {}", errno()));
                }
                opened.push((label, fd, stat));
            }
            let renamed_dirfd = libc::openat(
                rootfd,
                renamed_dir_relative.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            );
            if renamed_dirfd < vfd_base {
                fail_extra(format!(
                    "open renamed directory identity descriptor: fd={renamed_dirfd}, errno={}",
                    errno()
                ));
            }
            let mut renamed_dir_before = std::mem::zeroed::<libc::stat>();
            if libc::fstat(renamed_dirfd, &mut renamed_dir_before) != 0 {
                fail_extra(format!("initial fstat renamed directory: {}", errno()));
            }

            let trigger = libc::openat(rootfd, trigger_relative.as_ptr(), libc::O_RDONLY);
            if trigger < vfd_base {
                fail_extra(format!("open state trigger: {}", errno()));
            }
            libc::close(trigger);

            for (label, fd, before) in &opened {
                let mut after = std::mem::zeroed::<libc::stat>();
                if libc::fstat(*fd, &mut after) != 0 {
                    fail_extra(format!("post-mutation fstat {label}: {}", errno()));
                }
                if (after.st_ino, after.st_size, after.st_mtime)
                    != (before.st_ino, before.st_size, before.st_mtime)
                {
                    fail_extra(format!(
                        "{label} descriptor identity changed across graph mutation"
                    ));
                }

                let mut byte = 0u8;
                if libc::read(*fd, (&mut byte as *mut u8).cast(), 1) != 1 || byte != b'O' {
                    fail_extra(format!(
                        "{label} sequential descriptor read followed the current path binding"
                    ));
                }
                byte = 0;
                if libc::pread(*fd, (&mut byte as *mut u8).cast(), 1, 0) != 1 || byte != b'O' {
                    fail_extra(format!(
                        "{label} descriptor read followed the current path binding"
                    ));
                }
                let mapping = libc::mmap(
                    ptr::null_mut(),
                    4096,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    *fd,
                    0,
                );
                if mapping == libc::MAP_FAILED || *(mapping.cast::<u8>()) != b'O' {
                    fail_extra(format!(
                        "{label} descriptor mmap followed the current path binding: {}",
                        errno()
                    ));
                }
                if libc::munmap(mapping, 4096) != 0 {
                    fail_extra(format!("munmap pinned {label} descriptor: {}", errno()));
                }

                #[cfg(target_os = "linux")]
                {
                    let mut empty_stat = std::mem::zeroed::<libc::stat>();
                    if libc::fstatat(*fd, empty.as_ptr(), &mut empty_stat, AT_EMPTY_PATH_VALUE) != 0
                        || (empty_stat.st_ino, empty_stat.st_size, empty_stat.st_mtime)
                            != (before.st_ino, before.st_size, before.st_mtime)
                    {
                        fail_extra(format!(
                            "{label} AT_EMPTY_PATH did not preserve descriptor identity: {}",
                            errno()
                        ));
                    }
                    if libc::faccessat(*fd, empty.as_ptr(), libc::F_OK, AT_EMPTY_PATH_VALUE) != 0 {
                        fail_extra(format!(
                            "{label} faccessat AT_EMPTY_PATH lost descriptor identity: {}",
                            errno()
                        ));
                    }

                    let mut versioned = std::mem::zeroed::<libc::stat>();
                    if versioned_fxstat(NATIVE_STAT_VERSION, *fd, &mut versioned) != 0
                        || (versioned.st_ino, versioned.st_size, versioned.st_mtime)
                            != (before.st_ino, before.st_size, before.st_mtime)
                    {
                        fail_extra(format!(
                            "{label} __fxstat did not preserve descriptor identity: {}",
                            errno()
                        ));
                    }

                    let mut lfs = std::mem::zeroed::<libc::stat64>();
                    if direct_fstat64(*fd, &mut lfs) != 0
                        || (lfs.st_ino, lfs.st_size, lfs.st_mtime)
                            != (before.st_ino, before.st_size, before.st_mtime)
                    {
                        fail_extra(format!(
                            "{label} fstat64 did not preserve descriptor identity: {}",
                            errno()
                        ));
                    }
                    let mut versioned_lfs = std::mem::zeroed::<libc::stat64>();
                    if versioned_fxstat64(NATIVE_STAT_VERSION, *fd, &mut versioned_lfs) != 0
                        || (
                            versioned_lfs.st_ino,
                            versioned_lfs.st_size,
                            versioned_lfs.st_mtime,
                        ) != (before.st_ino, before.st_size, before.st_mtime)
                    {
                        fail_extra(format!(
                            "{label} __fxstat64 did not preserve descriptor identity: {}",
                            errno()
                        ));
                    }

                    let mut statx = std::mem::zeroed::<libc::statx>();
                    if libc::statx(
                        *fd,
                        empty.as_ptr(),
                        AT_EMPTY_PATH_VALUE,
                        libc::STATX_BASIC_STATS,
                        &mut statx,
                    ) != 0
                        || (
                            statx.stx_ino,
                            statx.stx_size,
                            i64::from(statx.stx_mtime.tv_sec),
                        ) != (before.st_ino, before.st_size as u64, before.st_mtime)
                    {
                        fail_extra(format!(
                            "{label} statx AT_EMPTY_PATH did not preserve descriptor identity: {}",
                            errno()
                        ));
                    }
                }

                #[cfg(target_os = "macos")]
                {
                    let mut fdonly_stat = std::mem::zeroed::<libc::stat>();
                    if libc::fstatat(
                        *fd,
                        child_relative.as_ptr(),
                        &mut fdonly_stat,
                        AT_FDONLY_VALUE,
                    ) != 0
                        || (
                            fdonly_stat.st_ino,
                            fdonly_stat.st_size,
                            fdonly_stat.st_mtime,
                        ) != (before.st_ino, before.st_size, before.st_mtime)
                    {
                        fail_extra(format!(
                            "{label} AT_FDONLY did not preserve descriptor identity: {}",
                            errno()
                        ));
                    }
                }
            }

            let mut replaced = std::mem::zeroed::<libc::stat>();
            if libc::fstatat(rootfd, stateful_relative.as_ptr(), &mut replaced, 0) != 0
                || replaced.st_mtime != 2
            {
                fail_extra(format!(
                    "repointed path did not expose replacement: {}",
                    errno()
                ));
            }
            let repoint_before = opened
                .iter()
                .find(|(label, _, _)| *label == "repoint")
                .map(|(_, _, stat)| stat.st_ino)
                .unwrap_or_else(|| fail_extra("missing repoint identity descriptor"));
            if repoint_before == replaced.st_ino {
                fail_extra("same-path replacement reused the opened object's graph-backed inode");
            }
            for (label, path) in [
                ("unlinked", unlinked_relative.as_ptr()),
                ("renamed-source", renamed_relative.as_ptr()),
            ] {
                set_errno(0);
                let mut stat = std::mem::zeroed::<libc::stat>();
                expect_errno(
                    label,
                    libc::fstatat(rootfd, path, &mut stat, 0),
                    libc::ENOENT,
                );
            }
            let mut moved = std::mem::zeroed::<libc::stat>();
            if libc::fstatat(rootfd, moved_relative.as_ptr(), &mut moved, 0) != 0 {
                fail_extra(format!("renamed destination missing: {}", errno()));
            }
            let rename_before = opened
                .iter()
                .find(|(label, _, _)| *label == "rename")
                .map(|(_, _, stat)| stat.st_ino)
                .unwrap_or_else(|| fail_extra("missing rename identity descriptor"));
            if rename_before != moved.st_ino {
                fail_extra(
                    "renamed destination did not preserve the opened object's graph-backed inode",
                );
            }

            set_errno(0);
            let mut removed_dir = std::mem::zeroed::<libc::stat>();
            expect_errno(
                "renamed-directory-source",
                libc::fstatat(rootfd, renamed_dir_relative.as_ptr(), &mut removed_dir, 0),
                libc::ENOENT,
            );
            let mut moved_dir = std::mem::zeroed::<libc::stat>();
            if libc::fstatat(rootfd, moved_dir_relative.as_ptr(), &mut moved_dir, 0) != 0 {
                fail_extra(format!(
                    "renamed directory destination missing: {}",
                    errno()
                ));
            }
            if moved_dir.st_ino != renamed_dir_before.st_ino {
                fail_extra(
                    "renamed directory destination did not preserve its graph capability inode",
                );
            }
            let moved_child = libc::openat(
                renamed_dirfd,
                renamed_dir_child_relative.as_ptr(),
                libc::O_RDONLY,
            );
            if moved_child < vfd_base {
                fail_extra(format!(
                    "openat through renamed virtual dirfd lost its pinned lookup capability: \
                     fd={moved_child}, errno={}",
                    errno()
                ));
            }
            let mut child_bytes = [0u8; 16];
            let child_read = libc::read(
                moved_child,
                child_bytes.as_mut_ptr().cast::<libc::c_void>(),
                child_bytes.len(),
            );
            if child_read != b"dir-child\n".len() as isize
                || &child_bytes[..child_read.max(0) as usize] != b"dir-child\n"
            {
                fail_extra("renamed virtual dirfd resolved a child outside graph authority");
            }
            libc::close(moved_child);
            libc::close(renamed_dirfd);
            for (_, fd, _) in opened {
                libc::close(fd);
            }

            #[cfg(target_os = "linux")]
            {
                set_errno(0);
                let check_fd = libc::openat(rootfd, file_relative.as_ptr(), libc::O_ACCMODE);
                if check_fd < vfd_base {
                    fail_extra(format!(
                        "Linux mode-3 check descriptor was not virtual: fd={check_fd}, errno={}",
                        errno()
                    ));
                }
                let mut check_stat = std::mem::zeroed::<libc::stat>();
                if libc::fstat(check_fd, &mut check_stat) != 0 {
                    fail_extra(format!("mode-3 fstat failed: {}", errno()));
                }
                let mut byte = 0u8;
                set_errno(0);
                expect_errno(
                    "mode-3 read",
                    libc::read(check_fd, (&mut byte as *mut u8).cast(), 1) as libc::c_int,
                    libc::EBADF,
                );
                set_errno(0);
                expect_errno(
                    "mode-3 write",
                    libc::write(check_fd, (&byte as *const u8).cast(), 1) as libc::c_int,
                    libc::EBADF,
                );
                set_errno(0);
                expect_errno(
                    "mode-3 lseek",
                    libc::lseek(check_fd, 0, libc::SEEK_SET) as libc::c_int,
                    libc::EBADF,
                );
                if libc::close(check_fd) != 0 {
                    fail_extra(format!("close mode-3 fd: {}", errno()));
                }
                set_errno(0);
                expect_errno(
                    "mode-3 truncate",
                    libc::openat(
                        rootfd,
                        file_relative.as_ptr(),
                        libc::O_ACCMODE | libc::O_TRUNC,
                    ),
                    libc::EOPNOTSUPP,
                );
                set_errno(0);
                expect_errno(
                    "mode-3 create",
                    libc::openat(
                        rootfd,
                        graph_only_relative.as_ptr(),
                        libc::O_ACCMODE | libc::O_CREAT,
                        0o600 as libc::mode_t,
                    ),
                    libc::EOPNOTSUPP,
                );

                set_errno(0);
                expect_errno(
                    "open O_TMPFILE",
                    libc::open(
                        root_c.as_ptr(),
                        libc::O_TMPFILE | libc::O_RDWR,
                        0o600 as libc::mode_t,
                    ),
                    libc::EOPNOTSUPP,
                );
                set_errno(0);
                expect_errno(
                    "openat O_TMPFILE",
                    libc::openat(
                        rootfd,
                        dot_relative.as_ptr(),
                        libc::O_TMPFILE | libc::O_RDWR,
                        0o600 as libc::mode_t,
                    ),
                    libc::EOPNOTSUPP,
                );
            }

            #[cfg(target_os = "macos")]
            {
                for (label, path, flags) in [
                    (
                        "O_SYMLINK",
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_SYMLINK,
                    ),
                    (
                        "O_EXEC",
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_EXEC,
                    ),
                    (
                        "O_EVTONLY",
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_EVTONLY,
                    ),
                    ("O_SEARCH", root_c.as_ptr(), libc::O_RDONLY | libc::O_SEARCH),
                ] {
                    set_errno(0);
                    expect_errno(label, libc::open(path, flags), libc::EOPNOTSUPP);
                }

                set_errno(0);
                let guarded = libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW_ANY,
                );
                if guarded < vfd_base {
                    fail_extra(format!("O_NOFOLLOW_ANY regular open: {}", errno()));
                }
                libc::close(guarded);
                set_errno(0);
                expect_errno(
                    "O_NOFOLLOW_ANY intermediate",
                    libc::open(
                        nested_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW_ANY,
                    ),
                    libc::ELOOP,
                );

                set_errno(0);
                let beneath = libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                );
                if beneath < vfd_base {
                    fail_extra(format!("O_RESOLVE_BENEATH relative open: {}", errno()));
                }
                libc::close(beneath);
                set_errno(0);
                expect_errno(
                    "O_RESOLVE_BENEATH absolute",
                    libc::openat(
                        rootfd,
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );

                if libc::chdir(root_c.as_ptr()) != 0 {
                    fail_extra(format!(
                        "chdir graph workspace for plain-open guards: {}",
                        errno()
                    ));
                }
                set_errno(0);
                let plain_beneath = libc::open(
                    file_relative.as_ptr(),
                    libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                );
                if plain_beneath < vfd_base {
                    fail_extra(format!(
                        "plain O_RESOLVE_BENEATH relative open: {}",
                        errno()
                    ));
                }
                libc::close(plain_beneath);
                set_errno(0);
                expect_errno(
                    "plain O_RESOLVE_BENEATH escape",
                    libc::open(
                        parent_relative.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );

                set_errno(0);
                let dirfd = libc::openat(
                    rootfd,
                    dir_relative.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                );
                if dirfd < vfd_base {
                    fail_extra(format!(
                        "open graph directory for beneath checks: {}",
                        errno()
                    ));
                }
                set_errno(0);
                expect_errno(
                    "O_RESOLVE_BENEATH direct escape and re-entry",
                    libc::openat(
                        dirfd,
                        beneath_escape_relative.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                set_errno(0);
                expect_errno(
                    "O_RESOLVE_BENEATH symlink escape and re-entry",
                    libc::openat(
                        dirfd,
                        beneath_bounce_relative.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                if libc::close(dirfd) != 0 {
                    fail_extra(format!("close graph directory fd: {}", errno()));
                }

                set_errno(0);
                let unique = libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_RDONLY | O_UNIQUE_VALUE,
                );
                if unique < vfd_base {
                    fail_extra(format!("O_UNIQUE single-link open: {}", errno()));
                }
                libc::close(unique);
                set_errno(0);
                expect_errno(
                    "O_UNIQUE multi-link",
                    libc::openat(
                        rootfd,
                        multi_relative.as_ptr(),
                        libc::O_RDONLY | O_UNIQUE_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                set_errno(0);
                expect_errno(
                    "plain O_UNIQUE multi-link",
                    libc::open(multi_relative.as_ptr(), libc::O_RDONLY | O_UNIQUE_VALUE),
                    libc::ENOTCAPABLE,
                );

                let mut guarded_stat = std::mem::zeroed::<libc::stat>();
                if libc::fstatat(
                    rootfd,
                    link_relative.as_ptr(),
                    &mut guarded_stat,
                    AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                ) != 0
                    || guarded_stat.st_mode & libc::S_IFMT != libc::S_IFLNK
                {
                    fail_extra(format!(
                        "AT_SYMLINK_NOFOLLOW_ANY final symlink: {}",
                        errno()
                    ));
                }
                set_errno(0);
                expect_errno(
                    "AT_SYMLINK_NOFOLLOW_ANY intermediate",
                    libc::fstatat(
                        rootfd,
                        nested_relative.as_ptr(),
                        &mut guarded_stat,
                        AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                    ),
                    libc::ELOOP,
                );
                if libc::fstatat(
                    rootfd,
                    file_relative.as_ptr(),
                    &mut guarded_stat,
                    AT_RESOLVE_BENEATH_VALUE,
                ) != 0
                {
                    fail_extra(format!("AT_RESOLVE_BENEATH relative stat: {}", errno()));
                }
                set_errno(0);
                expect_errno(
                    "AT_RESOLVE_BENEATH absolute",
                    libc::fstatat(
                        rootfd,
                        file_absolute.as_ptr(),
                        &mut guarded_stat,
                        AT_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                if libc::fstatat(
                    rootfd,
                    file_relative.as_ptr(),
                    &mut guarded_stat,
                    AT_UNIQUE_VALUE,
                ) != 0
                {
                    fail_extra(format!("AT_UNIQUE single-link stat: {}", errno()));
                }
                set_errno(0);
                expect_errno(
                    "AT_UNIQUE multi-link",
                    libc::fstatat(
                        rootfd,
                        multi_relative.as_ptr(),
                        &mut guarded_stat,
                        AT_UNIQUE_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );

                if libc::faccessat(
                    rootfd,
                    link_relative.as_ptr(),
                    libc::F_OK,
                    AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                ) != 0
                {
                    fail_extra(format!(
                        "faccessat AT_SYMLINK_NOFOLLOW_ANY final: {}",
                        errno()
                    ));
                }
                set_errno(0);
                expect_errno(
                    "faccessat AT_SYMLINK_NOFOLLOW_ANY intermediate",
                    libc::faccessat(
                        rootfd,
                        nested_relative.as_ptr(),
                        libc::F_OK,
                        AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                    ),
                    libc::ELOOP,
                );
                if libc::faccessat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::F_OK,
                    AT_RESOLVE_BENEATH_VALUE | AT_UNIQUE_VALUE,
                ) != 0
                {
                    fail_extra(format!(
                        "faccessat AT_RESOLVE_BENEATH|AT_UNIQUE: {}",
                        errno()
                    ));
                }
            }
        }

        run_descriptor_state_matrix();

        if libc::close(filefd) != 0 || libc::close(rootfd) != 0 {
            eprintln!("closing fixture descriptors failed: {}", errno());
            std::process::exit(3);
        }
    }
}
