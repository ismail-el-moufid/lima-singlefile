/*
 * Immutable embedded firmware block protocol.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qobject/qdict.h"
#include "qemu/builtin.h"
#include "qemu/module.h"
#include "block/block-io.h"
#include "block/block_int.h"

typedef struct BDRVBuiltinState {
    const QemuBuiltinResource *resource;
} BDRVBuiltinState;

static void builtin_parse_filename(const char *filename, QDict *options,
                                   Error **errp)
{
    if (!qemu_builtin_is_uri(filename)) {
        error_setg(errp, "Expected builtin:<filename>, got '%s'", filename);
        return;
    }
    qdict_put_str(options, "filename", filename);
}

static int builtin_open(BlockDriverState *bs, QDict *options, int flags,
                        Error **errp)
{
    BDRVBuiltinState *s = bs->opaque;
    const char *filename = qdict_get_try_str(options, "filename");
    int ret;

    if (!qemu_builtin_is_uri(filename)) {
        error_setg(errp, "builtin requires filename=builtin:<filename>");
        return -EINVAL;
    }
    s->resource = qemu_builtin_lookup(filename);
    if (!s->resource) {
        error_setg(errp, "Unknown built-in resource '%s'", filename);
        return -ENOENT;
    }
    qdict_del(options, "filename");

    bdrv_graph_rdlock_main_loop();
    ret = bdrv_apply_auto_read_only(bs, "Built-in firmware is read-only", errp);
    bdrv_graph_rdunlock_main_loop();
    return ret;
}

static int64_t coroutine_fn builtin_co_getlength(BlockDriverState *bs)
{
    BDRVBuiltinState *s = bs->opaque;

    return s->resource->size;
}

static int coroutine_fn builtin_co_preadv(BlockDriverState *bs, int64_t offset,
                                         int64_t bytes, QEMUIOVector *qiov,
                                         BdrvRequestFlags flags)
{
    BDRVBuiltinState *s = bs->opaque;
    const QemuBuiltinResource *r = s->resource;

    if (offset < 0 || bytes < 0 || (uint64_t)offset > r->size ||
        (uint64_t)bytes > r->size - offset) {
        return -EIO;
    }
    return qemu_iovec_from_buf(qiov, 0, r->data + offset, bytes) == bytes
           ? 0 : -EIO;
}

static int coroutine_fn builtin_co_pwritev(BlockDriverState *bs, int64_t offset,
                                          int64_t bytes, QEMUIOVector *qiov,
                                          BdrvRequestFlags flags)
{
    return -EROFS;
}

static int builtin_reopen_prepare(BDRVReopenState *state,
                                  BlockReopenQueue *queue, Error **errp)
{
    if (state->flags & BDRV_O_RDWR) {
        error_setg(errp, "Built-in firmware cannot be reopened writable");
        return -EROFS;
    }
    return 0;
}

static void builtin_refresh_limits(BlockDriverState *bs, Error **errp)
{
    bs->bl.request_alignment = 1;
}

static void builtin_refresh_filename(BlockDriverState *bs)
{
    BDRVBuiltinState *s = bs->opaque;

    snprintf(bs->exact_filename, sizeof(bs->exact_filename),
             QEMU_BUILTIN_PREFIX "%s", s->resource->name);
}

static const char *const builtin_strong_runtime_opts[] = {
    "filename", NULL
};

static BlockDriver bdrv_builtin = {
    .format_name = "builtin",
    .protocol_name = "builtin",
    .instance_size = sizeof(BDRVBuiltinState),
    .bdrv_needs_filename = true,
    .bdrv_parse_filename = builtin_parse_filename,
    .bdrv_open = builtin_open,
    .bdrv_co_getlength = builtin_co_getlength,
    .bdrv_co_get_allocated_file_size = builtin_co_getlength,
    .bdrv_co_preadv = builtin_co_preadv,
    .bdrv_co_pwritev = builtin_co_pwritev,
    .bdrv_reopen_prepare = builtin_reopen_prepare,
    .bdrv_refresh_limits = builtin_refresh_limits,
    .bdrv_refresh_filename = builtin_refresh_filename,
    .strong_runtime_opts = builtin_strong_runtime_opts,
};

static void bdrv_builtin_init(void)
{
    bdrv_register(&bdrv_builtin);
}

/* Kept in block_ss, not a loadable module, including in qemu-img. */
block_init(bdrv_builtin_init);
