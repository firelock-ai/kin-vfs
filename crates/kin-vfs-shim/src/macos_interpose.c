// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// macOS DYLD interpose table for kin-vfs-shim.
//
// This translation unit exists so the `replacee` entries below resolve to the
// REAL libSystem symbols via load-time bind relocations. The libc names here
// (`open`, `read`, `stat`, ...) are declared by the system headers and are NOT
// defined in this object, so the static linker emits each as an undefined
// external -> `bind libSystem/_<name>`. dyld then redirects every external call
// to `<name>` into the matching local `kin_interpose_<name>` replacement.
//
// Keeping the table in C makes that undefined replacee binding explicit and
// independent of the Rust hook symbols. See the module comment in intercept.rs.
//
// Each replacement is a local C wrapper that calls a distinctly named
// `__kin_rust_*` Rust implementation, so its table slot is an image rebase
// rather than another libSystem bind.

#if defined(__APPLE__)

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// Keep the actual interpose replacement in this C translation unit. Mach-O's
// interpose section links correctly when the replacement slot is a local
// rebase and the replacee slot is a libSystem bind. Pointing both slots at
// undefined cross-object symbols lets the linker displace the bind fixups
// across tuple boundaries. Each local wrapper delegates immediately to the
// distinctly named Rust implementation.
#define KIN_FORWARD(return_type, name, signature, arguments)                   \
  extern return_type __kin_rust_##name signature;                              \
  static return_type kin_interpose_##name signature {                          \
    return __kin_rust_##name arguments;                                        \
  }

KIN_FORWARD(int, open, (const char *path, int flags, mode_t mode),
            (path, flags, mode))
KIN_FORWARD(int, openat,
            (int dirfd, const char *path, int flags, mode_t mode),
            (dirfd, path, flags, mode))
KIN_FORWARD(int, close, (int fd), (fd))
KIN_FORWARD(int, dup, (int fd), (fd))
KIN_FORWARD(int, dup2, (int oldfd, int newfd), (oldfd, newfd))
KIN_FORWARD(int, flock, (int fd, int operation), (fd, operation))
KIN_FORWARD(ssize_t, read, (int fd, void *buf, size_t count), (fd, buf, count))
KIN_FORWARD(ssize_t, pread,
            (int fd, void *buf, size_t count, off_t offset),
            (fd, buf, count, offset))
KIN_FORWARD(off_t, lseek, (int fd, off_t offset, int whence),
            (fd, offset, whence))
KIN_FORWARD(int, stat, (const char *path, struct stat *buf), (path, buf))
KIN_FORWARD(int, lstat, (const char *path, struct stat *buf), (path, buf))
KIN_FORWARD(int, fstat, (int fd, struct stat *buf), (fd, buf))
KIN_FORWARD(int, fstatat,
            (int dirfd, const char *path, struct stat *buf, int flags),
            (dirfd, path, buf, flags))
KIN_FORWARD(int, access, (const char *path, int mode), (path, mode))
KIN_FORWARD(int, faccessat,
            (int dirfd, const char *path, int mode, int flags),
            (dirfd, path, mode, flags))
KIN_FORWARD(void *, mmap,
            (void *addr, size_t len, int prot, int flags, int fd, off_t offset),
            (addr, len, prot, flags, fd, offset))
KIN_FORWARD(int, munmap, (void *addr, size_t len), (addr, len))
KIN_FORWARD(ssize_t, readlink, (const char *path, char *buf, size_t bufsiz),
            (path, buf, bufsiz))
KIN_FORWARD(ssize_t, readlinkat,
            (int dirfd, const char *path, char *buf, size_t bufsiz),
            (dirfd, path, buf, bufsiz))

// The `*64` and `__getdirentries64` symbols are not in the public headers as
// these exact names on modern macOS; declare them so we can take their address
// as the replacee. They exist in libSystem (verified with `nm`).
//
// On x86_64-apple-darwin (Xcode 16+) sys/stat.h already declares stat64,
// lstat64, and fstat64 with `struct stat64 *`; redeclaring with `struct stat *`
// yields a conflicting-types error. On arm64 these symbols are absent from the
// SDK public headers so the forward-declaration is needed there.
#ifndef __x86_64__
extern int stat64(const char *, struct stat *);
extern int lstat64(const char *, struct stat *);
extern int fstat64(int, struct stat *);
#endif
extern ssize_t __getdirentries64(int, char *, size_t, long *);

KIN_FORWARD(int, stat64, (const char *path, struct stat *buf), (path, buf))
KIN_FORWARD(int, lstat64, (const char *path, struct stat *buf), (path, buf))
KIN_FORWARD(int, fstat64, (int fd, struct stat *buf), (fd, buf))
KIN_FORWARD(ssize_t, getdirentries64,
            (int fd, char *buf, size_t nbytes, long *basep),
            (fd, buf, nbytes, basep))

// Resolving the genuine functions with dlsym(RTLD_NEXT, ...) is unsafe during
// early process startup: dlsym itself reaches interposed libc operations before
// Rust thread-local state is ready. Returning `&open` directly is also unsafe
// at link time: its GOT relocation shares an undefined symbol with the magic
// interpose tuple, and ld64 can assign the tuple's bind to the next GOT symbol.
//
// Instead, each accessor returns a local forwarder. A direct call from the
// interposing image to the replacee is deliberately not re-interposed by dyld,
// and its branch relocation does not perturb the pointer relocation in the
// `__interpose` tuple.
#define KIN_REAL_FORWARD(return_type, accessor, replacee, signature, arguments) \
  static return_type kin_real_call_##accessor signature {                       \
    return replacee arguments;                                                  \
  }                                                                             \
  __attribute__((used)) void *kin_real_##accessor(void) {                        \
    return (void *)&kin_real_call_##accessor;                                    \
  }

KIN_REAL_FORWARD(int, open, open,
                 (const char *path, int flags, mode_t mode),
                 (path, flags, mode))
KIN_REAL_FORWARD(int, openat, openat,
                 (int dirfd, const char *path, int flags, mode_t mode),
                 (dirfd, path, flags, mode))
KIN_REAL_FORWARD(int, close, close, (int fd), (fd))
KIN_REAL_FORWARD(int, dup, dup, (int fd), (fd))
KIN_REAL_FORWARD(int, dup2, dup2, (int oldfd, int newfd), (oldfd, newfd))
KIN_REAL_FORWARD(int, flock, flock,
                 (int fd, int operation),
                 (fd, operation))
KIN_REAL_FORWARD(ssize_t, read, read,
                 (int fd, void *buf, size_t count),
                 (fd, buf, count))
KIN_REAL_FORWARD(ssize_t, pread, pread,
                 (int fd, void *buf, size_t count, off_t offset),
                 (fd, buf, count, offset))
KIN_REAL_FORWARD(off_t, lseek, lseek,
                 (int fd, off_t offset, int whence),
                 (fd, offset, whence))
KIN_REAL_FORWARD(int, stat, stat,
                 (const char *path, struct stat *buf),
                 (path, buf))
KIN_REAL_FORWARD(int, lstat, lstat,
                 (const char *path, struct stat *buf),
                 (path, buf))
KIN_REAL_FORWARD(int, fstat, fstat,
                 (int fd, struct stat *buf),
                 (fd, buf))
KIN_REAL_FORWARD(int, fstatat, fstatat,
                 (int dirfd, const char *path, struct stat *buf, int flags),
                 (dirfd, path, buf, flags))
KIN_REAL_FORWARD(int, access, access,
                 (const char *path, int mode),
                 (path, mode))
KIN_REAL_FORWARD(int, faccessat, faccessat,
                 (int dirfd, const char *path, int mode, int flags),
                 (dirfd, path, mode, flags))
KIN_REAL_FORWARD(void *, mmap, mmap,
                 (void *addr, size_t len, int prot, int flags, int fd,
                  off_t offset),
                 (addr, len, prot, flags, fd, offset))
KIN_REAL_FORWARD(int, munmap, munmap,
                 (void *addr, size_t len),
                 (addr, len))
KIN_REAL_FORWARD(ssize_t, readlink, readlink,
                 (const char *path, char *buf, size_t bufsiz),
                 (path, buf, bufsiz))
KIN_REAL_FORWARD(ssize_t, readlinkat, readlinkat,
                 (int dirfd, const char *path, char *buf, size_t bufsiz),
                 (dirfd, path, buf, bufsiz))
KIN_REAL_FORWARD(int, stat64, stat64,
                 (const char *path, struct stat *buf),
                 (path, buf))
KIN_REAL_FORWARD(int, lstat64, lstat64,
                 (const char *path, struct stat *buf),
                 (path, buf))
KIN_REAL_FORWARD(int, fstat64, fstat64,
                 (int fd, struct stat *buf),
                 (fd, buf))
KIN_REAL_FORWARD(ssize_t, __getdirentries64, __getdirentries64,
                 (int fd, char *buf, size_t nbytes, long *basep),
                 (fd, buf, nbytes, basep))

// dyld interpose entry: { replacement, replacee }. Each tuple is a separate
// named section atom, matching Apple's DYLD_INTERPOSE macro. A single C array
// is not equivalent: the Mach-O linker atomizes/reorders its pointer fixups in
// `__DATA,__interpose`, which can pair one replacement with the next replacee
// (`open` with `openat`, and so on). Keeping each pair in its own 16-byte atom
// makes that destructive cross-pair reordering impossible.
#define KIN_INTERPOSE(replacement, replacee)                                   \
  __attribute__((used)) static struct {                                        \
    const void *replacement;                                                   \
    const void *replacee;                                                      \
  } kin_interpose_tuple_##replacee                                             \
      __attribute__((section("__DATA,__interpose"))) = {                       \
      (const void *)(uintptr_t)&(replacement),                                 \
      (const void *)(uintptr_t)&(replacee),                                    \
  }

KIN_INTERPOSE(kin_interpose_open, open);
KIN_INTERPOSE(kin_interpose_openat, openat);
KIN_INTERPOSE(kin_interpose_close, close);
KIN_INTERPOSE(kin_interpose_dup, dup);
KIN_INTERPOSE(kin_interpose_dup2, dup2);
KIN_INTERPOSE(kin_interpose_flock, flock);
KIN_INTERPOSE(kin_interpose_read, read);
KIN_INTERPOSE(kin_interpose_pread, pread);
KIN_INTERPOSE(kin_interpose_lseek, lseek);
KIN_INTERPOSE(kin_interpose_stat, stat);
KIN_INTERPOSE(kin_interpose_lstat, lstat);
KIN_INTERPOSE(kin_interpose_fstat, fstat);
KIN_INTERPOSE(kin_interpose_fstatat, fstatat);
KIN_INTERPOSE(kin_interpose_access, access);
KIN_INTERPOSE(kin_interpose_faccessat, faccessat);
KIN_INTERPOSE(kin_interpose_mmap, mmap);
KIN_INTERPOSE(kin_interpose_munmap, munmap);
KIN_INTERPOSE(kin_interpose_readlink, readlink);
KIN_INTERPOSE(kin_interpose_readlinkat, readlinkat);
KIN_INTERPOSE(kin_interpose_stat64, stat64);
KIN_INTERPOSE(kin_interpose_lstat64, lstat64);
KIN_INTERPOSE(kin_interpose_fstat64, fstat64);
KIN_INTERPOSE(kin_interpose_getdirentries64, __getdirentries64);

enum { KIN_INTERPOSE_ENTRY_COUNT = 23 };

// Keep the table length in lockstep with `macos_interpose::INTERPOSE_ENTRY_COUNT`
// (passed in by build.rs). A mismatch fails the build instead of silently
// shipping a short table.
#ifdef KIN_INTERPOSE_EXPECTED
_Static_assert(KIN_INTERPOSE_ENTRY_COUNT == KIN_INTERPOSE_EXPECTED,
               "interpose table length must match INTERPOSE_ENTRY_COUNT");
#endif

// Anchor symbol referenced from Rust so the linker pulls THIS object — and
// therefore the `__interpose` section above — into the final cdylib.
// `__attribute__((used))` keeps the compiler from dropping it; the Rust-side
// `#[used]` reference keeps the linker from dropping the object. Returns the
// table length so the value is observable (the test cross-checks it).
__attribute__((used)) unsigned long kin_macos_interpose_entry_count(void) {
  return KIN_INTERPOSE_ENTRY_COUNT;
}

#endif // __APPLE__
