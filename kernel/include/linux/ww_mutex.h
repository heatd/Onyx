#ifndef _LINUX_WW_MUTEX_H
#define _LINUX_WW_MUTEX_H

#include <stdbool.h>

#include <onyx/bug.h>

#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/atomic.h>

struct ww_class {
    atomic_t txid;
    bool wait_die;
};

struct ww_acquire_ctx
{
    unsigned int txid;
    unsigned int acquired;
    bool wait_die;
    bool wounded;
#ifdef CONFIG_DEBUG_WW_MUTEX
    struct ww_class *class_;
#endif
};

struct ww_mutex
{
    struct mutex base;
    struct ww_acquire_ctx *ctx;
#ifdef CONFIG_DEBUG_WW_MUTEX
    struct ww_class *class_;
#endif
};

static inline bool ww_mutex_is_locked(struct ww_mutex *ww)
{
    return mutex_is_locked(&ww->base);
}

#define WW_CLASS_INITIALIZER(name) .txid = ATOMIC_INIT(0)

#define DEFINE_WW_CLASS(name) struct ww_class name = {WW_CLASS_INITIALIZER}
#define DEFINE_WD_CLASS(name) struct ww_class name = {WW_CLASS_INITIALIZER, .wait_die = true,}

static inline void ww_mutex_init(struct ww_mutex *mtx, struct ww_class *class_)
{
    mutex_init(&mtx->base);
    mtx->ctx = NULL;
#ifdef CONFIG_DEBUG_WW_MUTEX
    mtx->class_ = class_;
#endif
}

__BEGIN_CDECLS

int __must_check ww_mutex_lock(struct ww_mutex *ww, struct ww_acquire_ctx *ctx);
int __must_check ww_mutex_lock_interruptible(struct ww_mutex *ww, struct ww_acquire_ctx *ctx);

static void ww_mutex_lock_slow(struct ww_mutex *ww, struct ww_acquire_ctx *ctx)
{
    int err = ww_mutex_lock(ww, ctx);
    (void) err;
}

static inline int __must_check ww_mutex_lock_slow_interruptible(struct ww_mutex *ww, struct ww_acquire_ctx *ctx)
{
    return ww_mutex_lock_interruptible(ww, ctx);
}

int __must_check ww_mutex_trylock(struct ww_mutex *ww, struct ww_acquire_ctx *ctx);
void ww_mutex_unlock(struct ww_mutex *ww);

static inline void ww_acquire_init(struct ww_acquire_ctx *ctx, struct ww_class *ww_class)
{
    ctx->txid = atomic_fetch_inc(&ww_class->txid);
    ctx->wait_die = ww_class->wait_die;
    ctx->acquired = 0;
    ctx->wounded = false;
#ifdef CONFIG_DEBUG_WW_MUTEX
    ctx->class_ = ww_class;
#endif
}

static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
{
}

static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
{
}

__END_CDECLS

#endif
