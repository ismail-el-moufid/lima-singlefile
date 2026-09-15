/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef QEMU_BUILTIN_H
#define QEMU_BUILTIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QEMU_BUILTIN_PREFIX "builtin:"

typedef struct QemuBuiltinResource {
    const char *name;
    const uint8_t *data;
    size_t size;
} QemuBuiltinResource;

/* Process-lifetime immutable storage; callers must not free or modify it. */
bool qemu_builtin_is_uri(const char *name);
/* Exact resource name (including keymaps/<layout>) or builtin:<name>.
 * Never strips directory components or normalizes paths.
 */
const QemuBuiltinResource *qemu_builtin_lookup(const char *name);
size_t qemu_builtin_count(void);
const QemuBuiltinResource *qemu_builtin_at(size_t index);

#endif
