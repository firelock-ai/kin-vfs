// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Variadic fcntl boundary for the Unix shim. Stable Rust can call a C
// variadic function but cannot define one, so C decodes the optional argument
// before entering the fixed Rust hook.

#if !defined(_WIN32)

#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>

extern int __kin_interpose_fcntl_decoded(int, int, uintptr_t, int);

enum {
  KIN_FCNTL_NO_ARG = 0,
  KIN_FCNTL_INT_ARG = 1,
  KIN_FCNTL_POINTER_ARG = 2,
  KIN_FCNTL_OFF_T_ARG = 3,
};

static int kin_fcntl_argument_kind(int command) {
#ifdef F_GETFD
  if (command == F_GETFD)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETFL
  if (command == F_GETFL)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETOWN
  if (command == F_GETOWN)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETSIG
  if (command == F_GETSIG)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETLEASE
  if (command == F_GETLEASE)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETPIPE_SZ
  if (command == F_GETPIPE_SZ)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GET_SEALS
  if (command == F_GET_SEALS)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETNOSIGPIPE
  if (command == F_GETNOSIGPIPE)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETPROTECTIONCLASS
  if (command == F_GETPROTECTIONCLASS)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_GETPROTECTIONLEVEL
  if (command == F_GETPROTECTIONLEVEL)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_FLUSH_DATA
  if (command == F_FLUSH_DATA)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_CHKCLEAN
  if (command == F_CHKCLEAN)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_FULLFSYNC
  if (command == F_FULLFSYNC)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_FREEZE_FS
  if (command == F_FREEZE_FS)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_THAW_FS
  if (command == F_THAW_FS)
    return KIN_FCNTL_NO_ARG;
#endif
#ifdef F_BARRIERFSYNC
  if (command == F_BARRIERFSYNC)
    return KIN_FCNTL_NO_ARG;
#endif

#ifdef F_DUPFD
  if (command == F_DUPFD)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_DUPFD_CLOEXEC
  if (command == F_DUPFD_CLOEXEC)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETFD
  if (command == F_SETFD)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETFL
  if (command == F_SETFL)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETOWN
  if (command == F_SETOWN)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETSIG
  if (command == F_SETSIG)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETLEASE
  if (command == F_SETLEASE)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_NOTIFY
  if (command == F_NOTIFY)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETPIPE_SZ
  if (command == F_SETPIPE_SZ)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_ADD_SEALS
  if (command == F_ADD_SEALS)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_NOCACHE
  if (command == F_NOCACHE)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_RDAHEAD
  if (command == F_RDAHEAD)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_NODIRECT
  if (command == F_NODIRECT)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SINGLE_WRITER
  if (command == F_SINGLE_WRITER)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_GLOBAL_NOCACHE
  if (command == F_GLOBAL_NOCACHE)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETPROTECTIONCLASS
  if (command == F_SETPROTECTIONCLASS)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETBACKINGSTORE
  if (command == F_SETBACKINGSTORE)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_SETNOSIGPIPE
  if (command == F_SETNOSIGPIPE)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_NOCACHE_EXT
  if (command == F_NOCACHE_EXT)
    return KIN_FCNTL_INT_ARG;
#endif
#ifdef F_TRANSFEREXTENTS
  if (command == F_TRANSFEREXTENTS)
    return KIN_FCNTL_INT_ARG;
#endif

#ifdef F_SETSIZE
  if (command == F_SETSIZE)
    return KIN_FCNTL_OFF_T_ARG;
#endif

  // Lock, path, and platform-extension commands conventionally carry a
  // pointer. Unknown commands are forwarded in that representation rather
  // than reading an optional argument for known no-argument commands.
  return KIN_FCNTL_POINTER_ARG;
}

static int kin_fcntl_dispatch(int fd, int command, va_list arguments) {
  int kind = kin_fcntl_argument_kind(command);
  uintptr_t argument = 0;
  if (kind == KIN_FCNTL_INT_ARG) {
    argument = (uintptr_t)(intptr_t)va_arg(arguments, int);
  } else if (kind == KIN_FCNTL_OFF_T_ARG) {
    argument = (uintptr_t)(intptr_t)va_arg(arguments, off_t);
  } else if (kind == KIN_FCNTL_POINTER_ARG) {
    argument = (uintptr_t)va_arg(arguments, void *);
  }
  return __kin_interpose_fcntl_decoded(fd, command, argument, kind);
}

#if defined(__APPLE__)
int __kin_interpose_fcntl(int fd, int command, ...) {
#else
int fcntl(int fd, int command, ...) {
#endif
  va_list arguments;
  va_start(arguments, command);
  int result = kin_fcntl_dispatch(fd, command, arguments);
  va_end(arguments);
  return result;
}

// Rust retains a function-pointer reference to this symbol so the linker
// cannot discard the object containing the Linux exported wrapper.
uintptr_t kin_fcntl_interpose_anchor(void) {
  return (uintptr_t)&__kin_interpose_fcntl_decoded;
}

#endif
