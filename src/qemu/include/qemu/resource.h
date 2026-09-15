/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef QEMU_RESOURCE_H
#define QEMU_RESOURCE_H

#include <glib.h>

/* Like g_file_get_contents(), including ownership and trailing NUL semantics.
 * Explicit builtin: URIs read memory only; all other names retain file semantics.
 */
gboolean qemu_resource_get_contents(const char *filename, gchar **contents,
                                    gsize *length, GError **error);

#endif
