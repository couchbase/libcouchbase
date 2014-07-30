#include "internal.h"
#include "bucketconfig/clconfig.h"
#include "list.h"
#include "mc/mcreq.h"
#include "retryq.h"

LIBCOUCHBASE_API
void
lcb_dump(lcb_t instance, FILE *fp, lcb_U32 flags)
{
    unsigned ii;

    if (!fp) {
        fp = stderr;
    }
    fprintf(fp, "Dumping state for lcb_t=%p\n", (void*)instance);
    fprintf(fp, "Settings=%p\n", instance->settings);

    if (instance->cur_configinfo) {
        clconfig_info *cfg = instance->cur_configinfo;
        fprintf(fp, "Current VBC=%p\n", cfg->vbc);
        fprintf(fp, "Config RevID=%d\n", cfg->vbc->revid);
        if (flags & LCB_DUMP_VBCONFIG) {
            char *cfgdump = lcbvb_save_json(cfg->vbc);
            fprintf(fp, "=== CLUSTER CONFIG BEGIN ===\n");
            fprintf(fp, "%s", cfgdump);
            free(cfgdump);
            fprintf(fp, "\n");
            fprintf(fp, "=== CLUSTER CONFIG END ===\n");
        } else {
            fprintf(fp, "=== NOT DUMPING CLUSTER CONFIG. LCB_DUMP_VBCONFIG not passed\n");
        }
    } else {
        fprintf(fp, "NO CLUSTER CONFIG\n");
    }
    fprintf(fp,"Retry queue has items: %s\n", lcb_retryq_empty(instance->retryq) ? "No" : "Yes");
    if (flags & LCB_DUMP_PKTINFO) {
        fprintf(fp, "=== BEGIN RETRY QUEUE DUMP ===\n");
        lcb_retryq_dump(instance->retryq, fp, NULL);
        fprintf(fp, "=== END RETRY QUEUE DUMP ===\n");
    } else {
        fprintf(fp, "=== NOT DUMPING PACKET INFO. LCB_DUMP_PKTINFO not passed\n");
    }

    fprintf(fp, "=== BEGIN PIPELINE DUMP ===\n");
    for (ii = 0; ii < instance->cmdq.npipelines; ii++) {
        mc_SERVER *server;
        mc_PIPELINE *pl = instance->cmdq.pipelines[ii];

        server = (mc_SERVER *)pl;
        fprintf(fp, "** [%u] SERVER %s\n", ii, server->datahost);
        if (server->connctx) {
            fprintf(fp, "** == BEGIN SOCKET INFO\n");
            lcbio_ctx_dump(server->connctx, fp);
            fprintf(fp, "** == END SOCKET INFO\n");
        } else if (server->connreq.u.p_generic) {
            fprintf(fp, "** == STILL CONNECTING\n");
        } else {
            fprintf(fp, "** == NOT CONNECTED\n");
        }
        if (flags & LCB_DUMP_BUFINFO) {
            fprintf(fp, "** == DUMPING NETBUF INFO (For packet network data)\n");
            netbuf_dump_status(&pl->nbmgr, fp);
            fprintf(fp, "** == DUMPING NETBUF INFO (For packet structures)\n");
            netbuf_dump_status(&pl->reqpool, fp);
        } else {
            fprintf(fp, "** == NOT DUMPING NETBUF INFO. LCB_DUMP_BUFINFO not passed\n");
        }
        if (flags & LCB_DUMP_PKTINFO) {
            mcreq_dump_chain(pl, fp, NULL);
        } else {
            fprintf(fp, "** == NOT DUMPING PACKETS. LCB_DUMP_PKTINFO not passed\n");
        }
        fprintf(fp, "\n\n");
    }
    fprintf(fp, "=== END PIPELINE DUMP ===\n");

    fprintf(fp, "=== BEGIN CONFMON DUMP ===\n");
    lcb_confmon_dump(instance->confmon, fp);
    fprintf(fp, "=== END CONFMON DUMP ===\n");
}
