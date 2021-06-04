/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014-2020 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "mcreq.h"
#include "compress.h"

#include <snappy.h>
#include <snappy-sinksource.h>

class FragBufSource : public snappy::Source
{
  public:
    explicit FragBufSource(const lcb_FRAGBUF *buf_) : buf(buf_)
    {
        if (buf->total_length) {
            left = buf->total_length;
        } else {
            left = 0;
            for (unsigned int ii = 0; ii < buf->niov; ii++) {
                left += buf->iov[ii].iov_len;
            }
        }
        idx = 0;
        ptr = static_cast<const char *>(buf->iov[idx].iov_base);
    }

    ~FragBufSource() override = default;

    size_t Available() const override
    {
        return left;
    }

    const char *Peek(size_t *len) override
    {
        *len = buf->iov[idx].iov_len - static_cast<size_t>((ptr - static_cast<const char *>(buf->iov[idx].iov_base)));
        return ptr;
    }

    void Skip(size_t n) override
    {
        do {
            size_t spanleft = buf->iov[idx].iov_len - (ptr - static_cast<const char *>(buf->iov[idx].iov_base));
            if (n < spanleft) {
                ptr += n;
                left -= n;
                break;
            }
            if (idx + 1 >= buf->niov) {
                left = 0;
                ptr = nullptr;
                break;
            }
            left -= spanleft;
            n -= spanleft;
            ptr = static_cast<const char *>(buf->iov[++idx].iov_base);
        } while (n > 0);
        if (left == 0 || idx >= buf->niov) {
            ptr = nullptr;
            left = 0;
        }
    }

  private:
    const lcb_FRAGBUF *buf;
    const char *ptr;
    size_t left;
    unsigned int idx;
};

int mcreq_compress_value(mc_PIPELINE *pl, mc_PACKET *pkt, const lcb_VALBUF *vbuf, lcb_settings *settings,
                         int *should_compress)
{
    std::size_t origsize = 0;
    snappy::Source *source;
    switch (vbuf->vtype) {
        case LCB_KV_COPY:
        case LCB_KV_CONTIG:
            origsize = vbuf->u_buf.contig.nbytes;
            if (origsize < settings->compress_min_size) {
                *should_compress = 0;
                mcreq_reserve_value(pl, pkt, vbuf);
                return 0;
            }
            source = new snappy::ByteArraySource(static_cast<const char *>(vbuf->u_buf.contig.bytes),
                                                 vbuf->u_buf.contig.nbytes);
            break;

        case LCB_KV_IOV:
        case LCB_KV_IOVCOPY:
            if (vbuf->u_buf.multi.total_length == 0) {
                for (unsigned int ii = 0; ii < vbuf->u_buf.multi.niov; ii++) {
                    origsize += vbuf->u_buf.multi.iov[ii].iov_len;
                }
            }
            if (origsize == 0 || origsize < settings->compress_min_size) {
                *should_compress = 0;
                mcreq_reserve_value(pl, pkt, vbuf);
                return 0;
            }
            source = new FragBufSource(&vbuf->u_buf.multi);
            break;

        default:
            return -1;
    }

    std::size_t maxsize = snappy::MaxCompressedLength(source->Available());
    if (mcreq_reserve_value2(pl, pkt, maxsize) != LCB_SUCCESS) {
        delete source;
        return -1;
    }
    nb_SPAN *outspan = &pkt->u_value.single;
    snappy::UncheckedByteArraySink sink(SPAN_BUFFER(outspan));

    Compress(source, &sink);
    std::size_t compsize = sink.CurrentDestination() - SPAN_BUFFER(outspan);
    delete source;

    if (compsize == 0 || (((float)compsize / origsize) > settings->compress_min_ratio)) {
        netbuf_mblock_release(&pl->nbmgr, outspan);
        *should_compress = 0;
        mcreq_reserve_value(pl, pkt, vbuf);
        return 0;
    }

    if (compsize < maxsize) {
        /* chop off some bytes? */
        nb_SPAN trailspan = *outspan;
        trailspan.offset += compsize;
        trailspan.size = maxsize - compsize;
        netbuf_mblock_release(&pl->nbmgr, &trailspan);
        outspan->size = compsize;
    }
    return 0;
}

int mcreq_inflate_value(const void *compressed, size_t ncompressed, const void **bytes, size_t *nbytes, void **freeptr)
{
    size_t compsize = 0;

    if (!snappy::GetUncompressedLength(static_cast<const char *>(compressed), ncompressed, &compsize)) {
        return -1;
    }
    *freeptr = malloc(compsize);
    if (!snappy::RawUncompress(static_cast<const char *>(compressed), ncompressed, static_cast<char *>(*freeptr))) {
        free(*freeptr);
        *freeptr = nullptr;
        return -1;
    }

    *bytes = *freeptr;
    *nbytes = compsize;
    return 0;
}
