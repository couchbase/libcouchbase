#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>

#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>

#include <libcouchbase/couchbase.h>

static void check(lcb_STATUS err, const char *msg)
{
    if (err != LCB_SUCCESS) {
        //fprintf(stderr, "[\x1b[31mERROR\x1b[0m] %s: %s\n", msg, lcb_strerror_short(err));
        exit(EXIT_FAILURE);
    } else {
        // fprintf(stderr, "[\x1b[31mSUCCESS\x1b[0m] %s: \n", msg);
    }
}

static int err2color(lcb_STATUS err)
{
    switch (err) {
        case LCB_SUCCESS:
            return 32;
        case LCB_ERR_DOCUMENT_EXISTS:
            return 33;
        default:
            return 31;
    }
}

static void store_callback(lcb_INSTANCE *instance, int type, const lcb_RESPSTORE *resp)
{
    lcb_STATUS rc = lcb_respstore_status(resp);
    const char *key;
    size_t nkey;
    lcb_respstore_key(resp, &key, &nkey);
    // fprintf(stderr, "[\x1b[%dm%-5s\x1b[0m] %s, key=%.*s\n", err2color(rc), lcb_strcbtype(type), lcb_strerror_short(rc),
    //         (int)nkey, key);

}

static void get_callback(lcb_INSTANCE *instance, int type, const lcb_RESPGET *resp)
{
    lcb_STATUS rc;
    const char *key;
    size_t nkey;

    rc = lcb_respget_status(resp);
    lcb_respget_key(resp, &key, &nkey);
    // fprintf(stderr, "[\x1b[%dm%-5s\x1b[0m] %s, key=%.*s\n", err2color(rc), lcb_strcbtype(type), lcb_strerror_short(rc),
    //         (int)nkey, key);
}

static int running = 1;
static int value = 0;
static void sigint_handler(int unused)
{
    fprintf(stderr,"interrupted %d\n", unused);
    running = 0;
}

static void log(const char *s)
{
    fprintf(stderr,"log: %s\n", s);
    running = 0;
}

int main()
{
    //signal(SIGINT, sigint_handler);
    lcb_INSTANCE *instance;
    lcb_CREATEOPTS *options = NULL;
    char *bucket = NULL;
    int msec = 5;

    // allocate with
    //    cbdinocluster allocate --def-file examples/mixed-version.yaml

    // make sure that first node is 6.6
    //
    //   curl -sS -u Administrator:password http://172.17.0.4:8091/pools/default | \
    //       jq '.nodes[] | {version: .version, hostname: .configuredHostname}'
    //
    const char* connstr = "couchbase://192.168.106.130,192.168.106.129,192.168.106.128/my_bucket";
    const char* user = "Administrator";
    const char* pwd = "password";

    lcb_createopts_create(&options, LCB_TYPE_BUCKET);
    lcb_createopts_connstr(options, connstr, strlen(connstr));
    lcb_createopts_credentials(options, user, strlen(user), pwd, strlen(pwd));

    check(lcb_create(&instance, options), "create couchbase handle");
    uint32_t aKVTimeout = 5000000;
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_CONFIGURATION_TIMEOUT, &aKVTimeout);

    lcb_createopts_destroy(options);
    check(lcb_connect(instance), "schedule connection");
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    check(lcb_get_bootstrap_status(instance), "bootstrap from cluster");
    check(lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_BUCKETNAME, &bucket), "get bucket name");

    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback);

    int iter=0;
    while (running) {
        running = 1 + (running + 1) % 10;

            std::stringstream ss_key, ss_value;
            ss_key << "DummyKey" << running;
            ss_value << "{\"v\":\"DummyKey" << running << "\"}";
            std::string key = ss_key.str();
            std::string value = ss_value.str();


        {
            lcb_CMDSTORE *cmd;
            lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
            lcb_cmdstore_key(cmd, key.c_str(), strlen(key.c_str()));
            lcb_cmdstore_value(cmd, value.c_str(), strlen(value.c_str()));
            check(lcb_store(instance, NULL, cmd), "schedule STORE operation");
            lcb_cmdstore_destroy(cmd);
            lcb_wait(instance, LCB_WAIT_DEFAULT);
        }

        {
            lcb_CMDGET *cmd;
            lcb_cmdget_create(&cmd);
            lcb_cmdget_key(cmd, key.c_str(), strlen(key.c_str()));
            check(lcb_get(instance, NULL, cmd), "schedule GET operation");
            lcb_cmdget_destroy(cmd);
            lcb_wait(instance, LCB_WAIT_DEFAULT);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(msec));
        if(++iter % 100 == 0) {
            fprintf(stderr, "%d\n", iter);
        }
        lcb_tick_nowait(instance); // give LCB time to operate
    }


    //lcb_destroy(instance);
    return 0;
}
