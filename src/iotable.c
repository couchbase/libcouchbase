#define LCB_IOPS_V12_NO_DEPRECATE
#include "lcbio.h"

struct _1to3_st {
    lcb_ioC_write2_callback callback;
    void *udata;
    unsigned int refcount;
    unsigned int last_error;
};

static void
_1to3_callback(lcb_sockdata_t *sd, lcb_io_writebuf_t *wb, int status)
{
    struct _1to3_st *ott = (struct _1to3_st*)wb->buffer.root;
    wb->buffer.root = NULL;
    wb->buffer.ringbuffer = NULL;
    sd->parent->v.v1.release_writebuf(sd->parent, sd, wb);

    if (status != 0 && ott->last_error == 0) {
        ott->last_error = sd->parent->v.v0.error;
    }

    if (--ott->refcount == 0) {
        ott->callback(sd, ott->last_error, ott->udata);
        free(ott);
    }
}

static int
_1to3_write(lcb_io_opt_t iops,
            lcb_sockdata_t *sd,
            struct lcb_iovec_st *iov,
            lcb_size_t niov,
            void *uarg,
            lcb_ioC_write2_callback cb)
{
    unsigned int ii = 0;

    struct _1to3_st *ott;

    /** Schedule IOV writes, two at a time... */
    ott = malloc(sizeof(*ott));

    ott->callback = cb;
    ott->udata = uarg;
    ott->refcount = 0;
    ott->last_error = 0;

    while (ii < niov) {
        int jj = 0;
        lcb_io_writebuf_t *wb;

        wb = iops->v.v1.create_writebuf(iops, sd);
        wb->buffer.root = (char*)ott;
        wb->buffer.ringbuffer = NULL;

        for (jj = 0; jj < 2 && ii < niov; ii++, jj++) {
            wb->buffer.iov[jj] = iov[ii];
        }
        ott->refcount++;
        iops->v.v1.start_write(iops, sd, wb, _1to3_callback);
    }
    return 0;
}

static int
init_v2_table(lcb_iotable *table, lcb_io_opt_t io)
{
    io->v.v2.get_procs(LCB_IOPROCS_VERSION,
                       &table->loop,
                       &table->timer,
                       &table->u_io.v0.io,
                       &table->u_io.v0.ev,
                       &table->u_io.completion,
                       &table->model);

    table->p = io;
    if (table->model == LCB_IOMODEL_COMPLETION) {
        if (!table->u_io.completion.write2) {
            table->u_io.completion.write2 = _1to3_write;
        }
    }

    return 0;
}

LIBCOUCHBASE_API
int
lcb_init_io_table(lcb_iotable *table, lcb_io_opt_t io)
{

    table->p = 0;

    if (io->version >= 2) {
        return init_v2_table(table, io);
    }

    table->p = io;
    table->timer.create = io->v.v0.create_timer;
    table->timer.destroy = io->v.v0.destroy_timer;
    table->timer.cancel = io->v.v0.delete_timer;
    table->timer.schedule = io->v.v0.update_timer;
    table->loop.start = io->v.v0.run_event_loop;
    table->loop.stop = io->v.v0.stop_event_loop;

    if (io->version % 2 == 0) {
        lcb_ev_procs *ev = &table->u_io.v0.ev;
        lcb_bsd_procs *bsd = &table->u_io.v0.io;

        table->model = LCB_IOMODEL_EVENT;
        ev->create = io->v.v0.create_event;
        ev->destroy = io->v.v0.destroy_event;
        ev->cancel = io->v.v0.delete_event;
        ev->watch = io->v.v0.update_event;
        bsd->socket0 = io->v.v0.socket;
        bsd->connect0 = io->v.v0.connect;
        bsd->close = io->v.v0.close;
        bsd->recv = io->v.v0.recv;
        bsd->recvv = io->v.v0.recvv;
        bsd->send = io->v.v0.send;
        bsd->sendv = io->v.v0.sendv;

    } else {
        lcb_completion_procs *cp = &table->u_io.completion;

        table->model = LCB_IOMODEL_COMPLETION;

        cp->socket = io->v.v1.create_socket;
        cp->close = io->v.v1.close_socket;
        cp->connect = io->v.v1.start_connect;
        cp->read = io->v.v1.start_read;

        /** Emulate it! */
        cp->write2 = _1to3_write;
        cp->write = io->v.v1.start_write;
        cp->wballoc = io->v.v1.create_writebuf;
        cp->nameinfo = io->v.v1.get_nameinfo;
    }

    return 0;
}
