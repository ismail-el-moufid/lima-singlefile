/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Deliberately libc-only: this registry is also testable without a QEMU build. */
#include "qemu/builtin.h"
#include <string.h>

extern const uint8_t qemu_builtin_blob[];
#include "builtin-table.inc"

bool qemu_builtin_is_uri(const char *name)
{
    return name && strncmp(name, QEMU_BUILTIN_PREFIX,
                           sizeof(QEMU_BUILTIN_PREFIX) - 1) == 0;
}

const QemuBuiltinResource *qemu_builtin_lookup(const char *name)
{
    size_t i;

    if (!name) {
        return NULL;
    }
    if (qemu_builtin_is_uri(name)) {
        name += sizeof(QEMU_BUILTIN_PREFIX) - 1;
    }
    for (i = 0; i < qemu_builtin_count(); i++) {
        if (strcmp(name, builtin_resources[i].name) == 0) {
            return &builtin_resources[i];
        }
    }
    return NULL;
}

size_t qemu_builtin_count(void)
{
    return sizeof(builtin_resources) / sizeof(builtin_resources[0]);
}

const QemuBuiltinResource *qemu_builtin_at(size_t index)
{
    return index < qemu_builtin_count() ? &builtin_resources[index] : NULL;
}
