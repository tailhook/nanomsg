/*
    Copyright (c) 2012-2013 250bpm s.r.o.  All rights reserved.
    Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom
    the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
*/

#include "tcp.h"
#include "btcp.h"
#include "ctcp.h"

#include "../../tcp.h"

#include "../utils/port.h"
#include "../utils/iface.h"

#include "../../utils/err.h"
#include "../../utils/alloc.h"
#include "../../utils/fast.h"
#include "../../utils/list.h"
#include "../../utils/cont.h"
#include "../../aio/usock.h"

#include <string.h>

#if defined NN_HAVE_WINDOWS
#include "../../utils/win.h"
#else
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

/*  TCP-specific socket options. */

struct nn_tcp_optset {
    struct nn_optset base;
    int nodelay;
    int keepidle;
    int keepintvl;
    int keepcnt;
};

static void nn_tcp_optset_destroy (struct nn_optset *self);
static int nn_tcp_optset_setopt (struct nn_optset *self, int option,
    const void *optval, size_t optvallen);
static int nn_tcp_optset_getopt (struct nn_optset *self, int option,
    void *optval, size_t *optvallen);
static const struct nn_optset_vfptr nn_tcp_optset_vfptr = {
    nn_tcp_optset_destroy,
    nn_tcp_optset_setopt,
    nn_tcp_optset_getopt
};

/*  nn_transport interface. */
static int nn_tcp_bind (void *hint, struct nn_epbase **epbase);
static int nn_tcp_connect (void *hint, struct nn_epbase **epbase);
static struct nn_optset *nn_tcp_optset (void);

static struct nn_transport nn_tcp_vfptr = {
    "tcp",
    NN_TCP,
    NULL,
    NULL,
    nn_tcp_bind,
    nn_tcp_connect,
    nn_tcp_optset,
    NN_LIST_ITEM_INITIALIZER
};

struct nn_transport *nn_tcp = &nn_tcp_vfptr;

static int nn_tcp_bind (void *hint, struct nn_epbase **epbase)
{
    return nn_btcp_create (hint, epbase);
}

static int nn_tcp_connect (void *hint, struct nn_epbase **epbase)
{
    return nn_ctcp_create (hint, epbase);
}

static struct nn_optset *nn_tcp_optset ()
{
    struct nn_tcp_optset *optset;

    optset = nn_alloc (sizeof (struct nn_tcp_optset), "optset (tcp)");
    alloc_assert (optset);
    optset->base.vfptr = &nn_tcp_optset_vfptr;

    /*  Default values for TCP socket options. */
    optset->nodelay = 0;
    optset->keepidle = -1;  /*  Use os defaults  */
    optset->keepintvl = -1;  /*  Use os defaults  */
    optset->keepcnt = -1;  /*  Use os defaults  */

    return &optset->base;
}

static void nn_tcp_optset_destroy (struct nn_optset *self)
{
    struct nn_tcp_optset *optset;

    optset = nn_cont (self, struct nn_tcp_optset, base);
    nn_free (optset);
}

static int nn_tcp_optset_setopt (struct nn_optset *self, int option,
    const void *optval, size_t optvallen)
{
    struct nn_tcp_optset *optset;
    int val;

    optset = nn_cont (self, struct nn_tcp_optset, base);

    /*  At this point we assume that all options are of type int. */
    if (optvallen != sizeof (int))
        return -EINVAL;
    val = *(int*) optval;

    switch (option) {
    case NN_TCP_NODELAY:
        if (nn_slow (val != 0 && val != 1))
            return -EINVAL;
        optset->nodelay = val;
        return 0;
    case NN_TCP_KEEPIDLE:
        if (nn_slow (val <= 0))
            return -EINVAL;
        optset->keepidle = val;
        return 0;
    case NN_TCP_KEEPINTVL:
        if (nn_slow (val <= 0))
            return -EINVAL;
        optset->keepintvl = val;
        return 0;
    case NN_TCP_KEEPCNT:
        if (nn_slow (val <= 0))
            return -EINVAL;
        optset->keepcnt = val;
        return 0;
    default:
        return -ENOPROTOOPT;
    }
}

static int nn_tcp_optset_getopt (struct nn_optset *self, int option,
    void *optval, size_t *optvallen)
{
    struct nn_tcp_optset *optset;
    int intval;

    optset = nn_cont (self, struct nn_tcp_optset, base);

    switch (option) {
    case NN_TCP_NODELAY:
        intval = optset->nodelay;
        break;
    case NN_TCP_KEEPIDLE:
        intval = optset->keepidle;
        break;
    case NN_TCP_KEEPINTVL:
        intval = optset->keepintvl;
        break;
    case NN_TCP_KEEPCNT:
        intval = optset->keepcnt;
        break;
    default:
        return -ENOPROTOOPT;
    }
    memcpy (optval, &intval,
        *optvallen < sizeof (int) ? *optvallen : sizeof (int));
    *optvallen = sizeof (int);
    return 0;
}

void nn_tcp_set_options(struct nn_epbase *source, struct nn_usock *sock)
{
    int val;
    size_t sz;

    sz = sizeof (val);
    nn_epbase_getopt (source, NN_SOL_SOCKET, NN_SNDBUF, &val, &sz);
    nn_assert (sz == sizeof (val));
    nn_usock_setsockopt (sock, SOL_SOCKET, SO_SNDBUF,
        &val, sizeof (val));

    sz = sizeof (val);
    nn_epbase_getopt (source, NN_SOL_SOCKET, NN_RCVBUF, &val, &sz);
    nn_assert (sz == sizeof (val));
    nn_usock_setsockopt (sock, SOL_SOCKET, SO_RCVBUF,
        &val, sizeof (val));

#if defined SO_KEEPALIVE
    sz = sizeof (val);
    nn_epbase_getopt (source, NN_SOL_SOCKET, NN_KEEPALIVE, &val, &sz);
    nn_assert (sz == sizeof (val));
    nn_usock_setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE,
        &val, sizeof (val));
#endif

#if defined TCP_NODELAY
    sz = sizeof (val);
    nn_epbase_getopt (source, NN_TCP, NN_TCP_NODELAY, &val, &sz);
    nn_assert (sz == sizeof (val));
    nn_usock_setsockopt (sock, IPPROTO_TCP, TCP_NODELAY,
        &val, sizeof (val));
#endif

#if defined TCP_KEEPIDLE
    sz = sizeof (val);
    nn_epbase_getopt (source, NN_TCP, NN_TCP_KEEPIDLE, &val, &sz);
    nn_assert (sz == sizeof (val));
    if(val >= 0) {
        nn_usock_setsockopt (sock, IPPROTO_TCP, TCP_KEEPIDLE,
            &val, sizeof (val));
    }
#endif

#if defined TCP_KEEPINTVL
    sz = sizeof (val);
    nn_epbase_getopt (source, NN_TCP, NN_TCP_KEEPINTVL, &val, &sz);
    nn_assert (sz == sizeof (val));
    if(val >= 0) {
        nn_usock_setsockopt (sock, IPPROTO_TCP, TCP_KEEPINTVL,
            &val, sizeof (val));
    }
#endif

#if defined TCP_KEEPCNT
    sz = sizeof (val);
    nn_epbase_getopt (source, NN_TCP, NN_TCP_KEEPCNT, &val, &sz);
    nn_assert (sz == sizeof (val));
    if(val >= 0) {
        nn_usock_setsockopt (sock, IPPROTO_TCP, TCP_KEEPCNT,
            &val, sizeof (val));
    }
#endif

}

