/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/builtin.h"
#include "qemu/resource.h"

gboolean qemu_resource_get_contents(const char *filename, gchar **contents,
                                    gsize *length, GError **error)
{
    const QemuBuiltinResource *resource;

    if (!qemu_builtin_is_uri(filename)) {
        return g_file_get_contents(filename, contents, length, error);
    }

    *contents = NULL;
    if (length) {
        *length = 0;
    }
    resource = qemu_builtin_lookup(filename);
    if (!resource) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT,
                    "Unknown built-in resource '%s'", filename);
        return FALSE;
    }

    /* ROM consumers own this copy and may patch it or retain it for reset. */
    *contents = g_malloc(resource->size + 1);
    memcpy(*contents, resource->data, resource->size);
    (*contents)[resource->size] = '\0';
    if (length) {
        *length = resource->size;
    }
    return TRUE;
}
