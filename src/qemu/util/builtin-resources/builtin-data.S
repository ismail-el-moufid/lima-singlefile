/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "builtin-path.h"

#ifdef __APPLE__
.section __TEXT,__const
.globl _qemu_builtin_blob
.p2align 4
_qemu_builtin_blob:
#else
.section .rodata
.globl qemu_builtin_blob
.type qemu_builtin_blob, %object
.p2align 4
qemu_builtin_blob:
#endif
.incbin QEMU_BUILTIN_DATA_FILE
#ifndef __APPLE__
.size qemu_builtin_blob, . - qemu_builtin_blob
.section .note.GNU-stack,"",%progbits
#endif
