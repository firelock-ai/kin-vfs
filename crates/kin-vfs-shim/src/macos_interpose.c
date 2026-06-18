// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// macOS DYLD interpose table for kin-vfs-shim (FIR-909).
//
// This translation unit exists so the `replacee` entries below resolve to the
// REAL libSystem symbols via load-time bind relocations. The libc names here
// (`open`, `read`, `stat`, ...) are declared by the system headers and are NOT
// defined in this object, so the static linker emits each as an undefined
// external -> `bind libSystem/_<name>`. dyld then redirects every external call
// to `<name>` into the matching `__kin_interpose_<name>` replacement.
//
// A pure-Rust table cannot do this: because the Rust shim *defines* `open` etc.
// (`#[no_mangle]` hooks, required on Linux), a Rust reference to `libc::open`
// coalesces with that local definition, so both interpose slots end up pointing
// at our own hook (verified no-op). See the module comment in intercept.rs.
//
// The `__kin_interpose_*` replacements are thin forwarders defined in Rust
// (see `mod macos_interpose`), so they rebase into our image rather than
// coalescing with the libc names.

#if defined(__APPLE__)

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// Replacement forwarders, defined in Rust with the C ABI.
extern int __kin_interpose_open(const char *, int, mode_t);
extern int __kin_interpose_openat(int, const char *, int, mode_t);
extern int __kin_interpose_close(int);
extern int __kin_interpose_dup(int);
extern int __kin_interpose_dup2(int, int);
extern int __kin_interpose_flock(int, int);
extern ssize_t __kin_interpose_read(int, void *, size_t);
extern ssize_t __kin_interpose_pread(int, void *, size_t, off_t);
extern off_t __kin_interpose_lseek(int, off_t, int);
extern int __kin_interpose_stat(const char *, struct stat *);
extern int __kin_interpose_lstat(const char *, struct stat *);
extern int __kin_interpose_fstat(int, struct stat *);
extern int __kin_interpose_fstatat(int, const char *, struct stat *, int);
extern int __kin_interpose_access(const char *, int);
extern int __kin_interpose_faccessat(int, const char *, int, int);
extern void *__kin_interpose_mmap(void *, size_t, int, int, int, off_t);
extern int __kin_interpose_munmap(void *, size_t);
extern ssize_t __kin_interpose_readlink(const char *, char *, size_t);
extern ssize_t __kin_interpose_readlinkat(int, const char *, char *, size_t);

// The `*64` and `__getdirentries64` symbols are not in the public headers as
// these exact names on modern macOS; declare them so we can take their address
// as the replacee. They exist in libSystem (verified with `nm`).
extern int stat64(const char *, struct stat *);
extern int lstat64(const char *, struct stat *);
extern int fstat64(int, struct stat *);
extern ssize_t __getdirentries64(int, char *, size_t, long *);

extern int __kin_interpose_stat64(const char *, struct stat *);
extern int __kin_interpose_lstat64(const char *, struct stat *);
extern int __kin_interpose_fstat64(int, struct stat *);
extern ssize_t __kin_interpose_getdirentries64(int, char *, size_t, long *);

// dyld interpose entry: { replacement, replacee }. Placed in
// `__DATA,__interpose`, which dyld scans at load time. (Apple's own
// `DYLD_INTERPOSE` macro emits this exact shape; we spell it out so the file is
// self-contained and needs no private SDK header.)
typedef struct {
  const void *replacement;
  const void *replacee;
} kin_interpose_t;

#define KIN_INTERPOSE(replacement, replacee)                                   \
  { (const void *)(replacement), (const void *)(replacee) }

__attribute__((used)) static const kin_interpose_t
    kin_interpose_table[] __attribute__((section("__DATA,__interpose"))) = {
        KIN_INTERPOSE(__kin_interpose_open, open),
        KIN_INTERPOSE(__kin_interpose_openat, openat),
        KIN_INTERPOSE(__kin_interpose_close, close),
        KIN_INTERPOSE(__kin_interpose_dup, dup),
        KIN_INTERPOSE(__kin_interpose_dup2, dup2),
        KIN_INTERPOSE(__kin_interpose_flock, flock),
        KIN_INTERPOSE(__kin_interpose_read, read),
        KIN_INTERPOSE(__kin_interpose_pread, pread),
        KIN_INTERPOSE(__kin_interpose_lseek, lseek),
        KIN_INTERPOSE(__kin_interpose_stat, stat),
        KIN_INTERPOSE(__kin_interpose_lstat, lstat),
        KIN_INTERPOSE(__kin_interpose_fstat, fstat),
        KIN_INTERPOSE(__kin_interpose_fstatat, fstatat),
        KIN_INTERPOSE(__kin_interpose_access, access),
        KIN_INTERPOSE(__kin_interpose_faccessat, faccessat),
        KIN_INTERPOSE(__kin_interpose_mmap, mmap),
        KIN_INTERPOSE(__kin_interpose_munmap, munmap),
        KIN_INTERPOSE(__kin_interpose_readlink, readlink),
        KIN_INTERPOSE(__kin_interpose_readlinkat, readlinkat),
        KIN_INTERPOSE(__kin_interpose_stat64, stat64),
        KIN_INTERPOSE(__kin_interpose_lstat64, lstat64),
        KIN_INTERPOSE(__kin_interpose_fstat64, fstat64),
        KIN_INTERPOSE(__kin_interpose_getdirentries64, __getdirentries64),
};

// Keep the table length in lockstep with `macos_interpose::INTERPOSE_ENTRY_COUNT`
// (passed in by build.rs). A mismatch fails the build instead of silently
// shipping a short table — the FIR-909 failure mode.
#ifdef KIN_INTERPOSE_EXPECTED
_Static_assert(sizeof(kin_interpose_table) / sizeof(kin_interpose_table[0]) ==
                   KIN_INTERPOSE_EXPECTED,
               "interpose table length must match INTERPOSE_ENTRY_COUNT");
#endif

// ── Real libSystem function pointers (recursion-free resolution) ──────────
//
// The shim's hooks need the genuine libSystem function to forward to. Resolving
// that with `dlsym(RTLD_NEXT, ...)` is UNSAFE once our interpose table is live:
// during early process startup the first `dlsym` runs libc internals that are
// themselves interposed, recursing into our hooks before init completes →
// stack overflow (verified: SIGSEGV/EXC_BAD_ACCESS with an unwindable stack).
//
// These accessors return `&<symbol>`, which — because this C TU does not define
// those names — binds to libSystem at load time (a plain GOT bind, NOT routed
// through `__interpose`). So Rust gets the real function with zero dlsym and
// zero recursion. Each is `used` so it survives dead-stripping.
#define KIN_REAL_PTR(name)                                                     \
  __attribute__((used)) void *kin_real_##name(void) {                          \
    return (void *)&name;                                                      \
  }

KIN_REAL_PTR(open)
KIN_REAL_PTR(openat)
KIN_REAL_PTR(close)
KIN_REAL_PTR(dup)
KIN_REAL_PTR(dup2)
KIN_REAL_PTR(flock)
KIN_REAL_PTR(read)
KIN_REAL_PTR(pread)
KIN_REAL_PTR(lseek)
KIN_REAL_PTR(stat)
KIN_REAL_PTR(lstat)
KIN_REAL_PTR(fstat)
KIN_REAL_PTR(fstatat)
KIN_REAL_PTR(access)
KIN_REAL_PTR(faccessat)
KIN_REAL_PTR(mmap)
KIN_REAL_PTR(munmap)
KIN_REAL_PTR(readlink)
KIN_REAL_PTR(readlinkat)
KIN_REAL_PTR(stat64)
KIN_REAL_PTR(lstat64)
KIN_REAL_PTR(fstat64)
KIN_REAL_PTR(__getdirentries64)

// Anchor symbol referenced from Rust so the linker pulls THIS object — and
// therefore the `__interpose` section above — into the final cdylib.
// `__attribute__((used))` keeps the compiler from dropping it; the Rust-side
// `#[used]` reference keeps the linker from dropping the object. Returns the
// table length so the value is observable (the test cross-checks it).
__attribute__((used)) unsigned long kin_macos_interpose_entry_count(void) {
  return sizeof(kin_interpose_table) / sizeof(kin_interpose_table[0]);
}

#endif // __APPLE__
