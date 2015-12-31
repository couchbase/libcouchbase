/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2012 Couchbase, Inc.
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
#include "config.h"
#include <sys/types.h>
#include <libcouchbase/couchbase.h>
#include <errno.h>
#include <iostream>
#include <map>
#include <sstream>
#include <queue>
#include <list>
#include <cstring>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <signal.h>
#ifndef WIN32
#include <pthread.h>
#else
#define usleep(n) Sleep(n/1000)
#endif
#include <cstdarg>
#include "common/options.h"
#include "common/histogram.h"

using namespace std;
using namespace cbc;
using namespace cliopts;
using std::vector;
using std::string;

struct DeprecatedOptions {
    UIntOption iterations;
    UIntOption instances;
    BoolOption loop;

    DeprecatedOptions() :
        iterations("iterations"), instances("num-instances"), loop("loop")
    {
        iterations.abbrev('i').hide().setDefault(1000);
        instances.abbrev('Q').hide().setDefault(1);
        loop.abbrev('l').hide().setDefault(false);
    }

    void addOptions(Parser &p) {
        p.addOption(instances);
        p.addOption(loop);
        p.addOption(iterations);
    }
};

#define JSON_VALUE_SIZE 16

// Writes a single json field "line". This returns something like:
// "Field_$counter": "*********....",
static size_t writeJsonLine(std::stringstream& ss, int docsize, int counter)
{
    size_t begin_size = ss.tellp();
    ss << '"'; // Opening quote for key
    ss << "Field_" << counter;
    ss << '"'; // Closing quote for key
    ss << ':'; // For dictionary value

    // Handle the value:
    // Determine how much of the value we can actually write..
    size_t nw = static_cast<size_t>(ss.tellp()) - begin_size;
    docsize -= nw;
    docsize = std::max(docsize, 1);
    docsize = std::min(docsize, JSON_VALUE_SIZE);

    // Now write to the document again..
    ss << '"'; // Opening quote for value
    ss << string(docsize, '*'); // Fill '*' to remaining size
    ss << '"'; // Closing quote
    ss << ','; // For next value
    ss << '\n'; // Easy to read

    return static_cast<size_t>(ss.tellp()) - begin_size;
}

// Generates a "JSON" document of a given size. In order to remain
// more or less in-tune with common document sizes, field names will be
// "Field_$incr" and values will be evenly distributed as fixed 16 byte
// strings. (See JSON_VALUE_SIZE)
static string genJsonDocument(int docsize)
{
    std::stringstream ss;
    int counter = 0;
    ss << '{';
    while (docsize > 0) {
        docsize -= writeJsonLine(ss, docsize, counter++);
    }
    ss << "\"__E\":1\n";
    ss << "}";
    return ss.str();
}

class DocGenerator {
public:
    DocGenerator() : minSize(0), maxSize(0), mode(RAW) {
    }

    enum Mode {
        RAW, // Just use a static buffer
        JSON, // Generate something that looks like JSON
        USER // Use user-defined values
    };

    void init(uint32_t minsz, uint32_t maxsz, Mode mode_) {
        // Normalize the size
        mode = mode_;
        minSize = std::min(minsz, maxsz);
        maxSize = maxsz;

        int grades = 10;
        size_t diff = maxSize - minSize;
        size_t factor = diff / grades;
        if (factor == 0) {
            grades = 1;
            factor = maxSize;
        }

        // Use raw buffer mode
        if (mode == RAW) {
            rawbuf.insert(0, maxSize, '#');
            if (minSize == maxSize) {
                // Use exact:
                raw_sizes.push_back(1);
                return;
            }
        }


        printf("Grades=%d, Factor=%d, Diff=%d\n", grades, factor, diff);

        for (int ii = 0; ii < grades+1; ii++) {
            size_t size = minSize + (factor * ii);
            printf("Using value size %lu\n", size);
            string jdoc = genJsonDocument(size);
            if (mode == RAW) {
                raw_sizes.push_back(size);
            } else {
                doc_values.push_back(genJsonDocument(size));
            }
        }
    }

    void initUser(const vector<string>& userdocs) {
        doc_values.assign(userdocs.begin(), userdocs.end());
    }

    /**
     * Get a document buffer and size for a given iteration sequence
     * @param seq The sequence number
     * @param[out] docsize The size of the document
     * @return the document buffer
     */
    const void *getDocValue(size_t seq, size_t *docsize) {
        if (mode == RAW) {
            *docsize = raw_sizes[seq % raw_sizes.size()];
            return rawbuf.c_str();
        } else {
            const string& s = doc_values[seq % doc_values.size()];
            *docsize = s.size();
            return s.c_str();
        }
    }

private:
    uint32_t minSize;
    uint32_t maxSize;
    Mode mode;
    vector<string> doc_values;
    vector<size_t> raw_sizes;
    string rawbuf;
};

class Configuration
{
public:
    Configuration() :
        o_multiSize("batch-size"),
        o_numItems("num-items"),
        o_keyPrefix("key-prefix"),
        o_numThreads("num-threads"),
        o_randSeed("random-seed"),
        o_setPercent("set-pct"),
        o_minSize("min-size"),
        o_maxSize("max-size"),
        o_noPopulate("no-population"),
        o_pauseAtEnd("pause-at-end"),
        o_numCycles("num-cycles"),
        o_sequential("sequential"),
        o_startAt("start-at"),
        o_rateLimit("rate-limit"),
        o_userdocs("docs"),
        o_writeJson("json"),
        o_sdpath("sd-path"),
        o_sdvalsize("sd-size")
    {
        o_multiSize.setDefault(100).abbrev('B').description("Number of operations to batch");
        o_numItems.setDefault(1000).abbrev('I').description("Number of items to operate on");
        o_keyPrefix.abbrev('p').description("key prefix to use");
        o_numThreads.setDefault(1).abbrev('t').description("The number of threads to use");
        o_randSeed.setDefault(0).abbrev('s').description("Specify random seed").hide();
        o_setPercent.setDefault(33).abbrev('r').description("The percentage of operations which should be mutations");
        o_minSize.setDefault(50).abbrev('m').description("Set minimum payload size");
        o_maxSize.setDefault(5120).abbrev('M').description("Set maximum payload size");
        o_noPopulate.setDefault(false).abbrev('n').description("Skip population");
        o_pauseAtEnd.setDefault(false).abbrev('E').description("Pause at end of run (holding connections open) until user input");
        o_numCycles.setDefault(-1).abbrev('c').description("Number of cycles to be run until exiting. Set to -1 to loop infinitely");
        o_sequential.setDefault(false).description("Use sequential access (instead of random)");
        o_startAt.setDefault(0).description("For sequential access, set the first item");
        o_rateLimit.setDefault(0).description("Set operations per second limit (per thread)");
        o_sdpath.description("Sub-document path");
        o_userdocs.description("User documents to load (overrides --min-size and --max-size");
        o_writeJson.description("Enable writing JSON values (rather than bytes)");
        o_sdvalsize.description("Sub-document value size").setDefault(16);
    }

    void processOptions() {
        opsPerCycle = o_multiSize.result();
        prefix = o_keyPrefix.result();
        setprc = o_setPercent.result();
        shouldPopulate = !o_noPopulate.result();

        if (depr.loop.passed()) {
            fprintf(stderr, "The --loop/-l option is deprecated. Use --num-cycles\n");
            maxCycles = -1;
        } else {
            maxCycles = o_numCycles.result();
        }

        if (depr.iterations.passed()) {
            fprintf(stderr, "The --num-iterations/-I option is deprecated. Use --batch-size\n");
            opsPerCycle = depr.iterations.result();
        }

        if (o_sdpath.passed()) {
            // Set the path to use..
            sd_path = o_sdpath.result();
            isSubdoc = true;
        } else {
            isSubdoc = false;
        }

        // Set the document sizes..
        if (o_userdocs.passed()) {
            vector<string> inputs = o_userdocs.result();
            vector<string> docs;
            for (size_t ii = 0; ii < inputs.size(); ii++) {
                std::stringstream ss;
                std::ifstream ifs(inputs[ii].c_str());
                if (!ifs.is_open()) {
                    perror(inputs[ii].c_str());
                    exit(EXIT_FAILURE);
                }
                ss << ifs.rdbuf();
                docs.push_back(ss.str());
            }
            docgen.initUser(docs);

        } else {
            DocGenerator::Mode genmode;
            if (o_writeJson.result() || !sd_path.empty()) {
                genmode = DocGenerator::JSON;
            } else {
                genmode = DocGenerator::RAW;
            }
            docgen.init(o_minSize.result(), o_maxSize.result(), genmode);
        }

        sd_value += '"';
        sd_value.insert(1, o_sdvalsize.result(), '@');
        sd_value += '"';
    }

    void addOptions(Parser& parser) {
        parser.addOption(o_multiSize);
        parser.addOption(o_numItems);
        parser.addOption(o_keyPrefix);
        parser.addOption(o_numThreads);
        parser.addOption(o_randSeed);
        parser.addOption(o_setPercent);
        parser.addOption(o_noPopulate);
        parser.addOption(o_minSize);
        parser.addOption(o_maxSize);
        parser.addOption(o_pauseAtEnd);
        parser.addOption(o_numCycles);
        parser.addOption(o_sequential);
        parser.addOption(o_startAt);
        parser.addOption(o_rateLimit);
        parser.addOption(o_userdocs);
        parser.addOption(o_sdpath);
        parser.addOption(o_userdocs);
        parser.addOption(o_writeJson);
        parser.addOption(o_sdvalsize);
        params.addToParser(parser);
        depr.addOptions(parser);
    }

    uint32_t getNumInstances(void) {
        if (depr.instances.passed()) {
            return depr.instances.result();
        }
        return o_numThreads.result();
    }

    bool isTimings(void) { return params.useTimings(); }

    bool isLoopDone(size_t niter) {
        if (maxCycles == -1) {
            return false;
        }
        return niter >= (size_t)maxCycles;
    }

    void setDGM(bool val) {
        dgm = val;
    }

    void setWaitTime(uint32_t val) {
        waitTime = val;
    }

    uint32_t getRandomSeed() { return o_randSeed; }
    uint32_t getNumThreads() { return o_numThreads; }
    string& getKeyPrefix() { return prefix; }
    bool shouldPauseAtEnd() { return o_pauseAtEnd; }
    bool sequentialAccess() { return o_sequential; }
    unsigned firstKeyOffset() { return o_startAt; }
    uint32_t getNumItems() { return o_numItems; }
    uint32_t getRateLimit() { return o_rateLimit; }


    std::string sd_path;
    std::string sd_value;

    uint32_t opsPerCycle;
    unsigned setprc;
    string prefix;
    volatile int maxCycles;
    bool dgm;
    bool shouldPopulate;
    bool isSubdoc;
    uint32_t waitTime;
    ConnParams params;
    DocGenerator docgen;

private:
    UIntOption o_multiSize;
    UIntOption o_numItems;
    StringOption o_keyPrefix;
    UIntOption o_numThreads;
    UIntOption o_randSeed;
    UIntOption o_setPercent;
    UIntOption o_minSize;
    UIntOption o_maxSize;
    BoolOption o_noPopulate;
    BoolOption o_pauseAtEnd; // Should pillowfight pause execution (with
                             // connections open) before exiting?
    IntOption o_numCycles;
    BoolOption o_sequential;
    UIntOption o_startAt;
    UIntOption o_rateLimit;

    // List of paths to user documents to load.. They should all be valid JSON
    ListOption o_userdocs;

    // Whether generated values should be JSON
    BoolOption o_writeJson;

    // Sub-document path to access
    StringOption o_sdpath;

    // Size of subdoc value
    UIntOption o_sdvalsize;

    DeprecatedOptions depr;
} config;

void log(const char *format, ...)
{
    char buffer[512];
    va_list args;

    va_start(args, format);
    vsprintf(buffer, format, args);
    if (config.isTimings()) {
        std::cerr << "[" << std::fixed << lcb_nstime() / 1000000000.0 << "] ";
    }
    std::cerr << buffer << std::endl;
    va_end(args);
}



extern "C" {
static void operationCallback(lcb_t, int, const lcb_RESPBASE*);
}

class InstanceCookie {
public:
    InstanceCookie(lcb_t instance) {
        lcb_set_cookie(instance, this);
        lastPrint = 0;
        if (config.isTimings()) {
            hg.install(instance, stdout);
        }
    }

    static InstanceCookie* get(lcb_t instance) {
        return (InstanceCookie *)lcb_get_cookie(instance);
    }


    static void dumpTimings(lcb_t instance, const char *header, bool force=false) {
        time_t now = time(NULL);
        InstanceCookie *ic = get(instance);

        if (now - ic->lastPrint > 0) {
            ic->lastPrint = now;
        } else if (!force) {
            return;
        }

        Histogram &h = ic->hg;
        printf("[%f %s]\n", lcb_nstime() / 1000000000.0, header);
        printf("              +---------+---------+---------+---------+\n");
        h.write();
        printf("              +----------------------------------------\n");
    }

private:
    time_t lastPrint;
    Histogram hg;
};

struct NextOp {
    NextOp() : seqno(0), valsize(0), data(NULL), mode(GET) {}

    string key;
    uint32_t seqno;
    size_t valsize;
    const void *data;
    enum Mode { STORE, GET, SD_STORE, SD_GET };
    Mode mode;
};

class KeyGenerator {
public:
    KeyGenerator(int ix) :
        currSeqno(0), rnum(0), ngenerated(0), isSequential(false),
        isPopulate(config.shouldPopulate)
{
        srand(config.getRandomSeed());
        for (int ii = 0; ii < 8192; ++ii) {
            seqPool[ii] = rand();
        }
        if (isPopulate) {
            isSequential = true;
        } else {
            isSequential = config.sequentialAccess();
        }

        // Maximum number of keys for this thread
        maxKey = config.getNumItems() /  config.getNumThreads();

        offset = config.firstKeyOffset();
        offset += maxKey * ix;
        id = ix;

        if (config.isSubdoc) {
            modeGet = NextOp::SD_GET;
            modeStore = NextOp::SD_STORE;
        } else {
            modeGet = NextOp::GET;
            modeStore = NextOp::STORE;
        }
    }

    void setNextOp(NextOp& op) {
        bool store_override = false;

        if (isPopulate) {
            if (ngenerated++ < maxKey) {
                store_override = true;
            } else {
                printf("Thread %d has finished populating.\n", id);
                isPopulate = false;
                isSequential = config.sequentialAccess();
            }
        }

        op.seqno = rnum;

        if (isSequential) {
            rnum++;
            rnum %= maxKey;
        } else {
            rnum += seqPool[currSeqno];
            currSeqno++;
            if (currSeqno > 8191) {
                currSeqno = 0;
            }
        }

        if (store_override) {
            // Populate
            op.mode = NextOp::STORE;
            setOpDocValue(op);

        } else if (shouldStore(op.seqno)) {
            op.mode = modeStore;
            if (op.mode == NextOp::STORE) {
                // KV Store
                setOpDocValue(op);
            } else {
                op.data = config.sd_value.c_str();
                op.valsize = config.sd_value.size();
            }
        } else {
            op.mode = modeGet;
        }

        generateKey(op);
    }

    void setOpDocValue(NextOp& op) {
        op.data = config.docgen.getDocValue(op.seqno, &op.valsize);
    }

    bool shouldStore(uint32_t seqno) {
        if (config.setprc == 0) {
            return false;
        }

        float seqno_f = seqno % 100;
        float pct_f = seqno_f / config.setprc;
        return pct_f < 1;
    }

    void generateKey(NextOp& op) {
        uint32_t seqno = op.seqno;
        seqno %= maxKey;
        seqno += offset;

        char buffer[21];
        snprintf(buffer, sizeof(buffer), "%020d", seqno);
        op.key.assign(config.getKeyPrefix() + buffer);
    }
    const char *getStageString() const {
        if (isPopulate) {
            return "Populate";
        } else {
            return "Run";
        }
    }

private:
    uint32_t seqPool[8192];
    uint32_t currSeqno;
    uint32_t rnum;
    uint32_t offset;
    uint32_t maxKey;
    size_t ngenerated;
    int id;

    bool isSequential;
    bool isPopulate;
    NextOp::Mode modeGet;
    NextOp::Mode modeStore;
};

class ThreadContext
{
public:
    ThreadContext(lcb_t handle, int ix) : kgen(ix), niter(0), instance(handle) {

    }

    void singleLoop() {
        bool hasItems = false;
        lcb_sched_enter(instance);
        NextOp opinfo;

        for (size_t ii = 0; ii < config.opsPerCycle; ++ii) {
            kgen.setNextOp(opinfo);

            if (opinfo.mode == NextOp::STORE) {
                lcb_CMDSTORE scmd = { 0 };
                scmd.operation = LCB_SET;
                LCB_CMD_SET_KEY(&scmd, opinfo.key.c_str(), opinfo.key.size());
                LCB_CMD_SET_VALUE(&scmd, opinfo.data, opinfo.valsize);
                error = lcb_store3(instance, this, &scmd);

            } else if (opinfo.mode == NextOp::GET) {
                lcb_CMDGET gcmd = { 0 };
                LCB_CMD_SET_KEY(&gcmd, opinfo.key.c_str(), opinfo.key.size());
                error = lcb_get3(instance, this, &gcmd);

            } else if (opinfo.mode == NextOp::SD_GET) {
                lcb_CMDSDGET sd_gcmd = { 0 };
                LCB_CMD_SET_KEY(&sd_gcmd, opinfo.key.c_str(), opinfo.key.size());
                LCB_SDCMD_SET_PATH(&sd_gcmd, config.sd_path.c_str(), config.sd_path.size());
                error = lcb_sdget3(instance, this, &sd_gcmd);

            } else if (opinfo.mode == NextOp::SD_STORE) {
                lcb_CMDSDSTORE sd_scmd = { 0 };
                LCB_CMD_SET_KEY(&sd_scmd, opinfo.key.c_str(), opinfo.key.size());
                LCB_CMD_SET_VALUE(&sd_scmd, opinfo.data, opinfo.valsize);
                LCB_SDCMD_SET_PATH(&sd_scmd, config.sd_path.c_str(), config.sd_path.size());
                sd_scmd.cmdflags = LCB_CMDSUBDOC_F_MKINTERMEDIATES;
                sd_scmd.mode = LCB_SUBDOC_DICT_UPSERT;
                error = lcb_sdstore3(instance, this, &sd_scmd);
            }
            if (error != LCB_SUCCESS) {
                hasItems = false;
                log("Failed to schedule operation: [0x%x] %s", error, lcb_strerror(instance, error));
            } else {
                hasItems = true;
            }
        }
        if (hasItems) {
            lcb_sched_leave(instance);
            lcb_wait(instance);
            if (error != LCB_SUCCESS) {
                log("Operation(s) failed: [0x%x] %s", error, lcb_strerror(instance, error));
            }
        } else {
            lcb_sched_fail(instance);
        }
    }

    bool run() {
        do {
            singleLoop();

            if (config.isTimings()) {
                InstanceCookie::dumpTimings(instance, kgen.getStageString());
            }
            if (config.params.shouldDump()) {
                lcb_dump(instance, stderr, LCB_DUMP_ALL);
            }
            if (config.getRateLimit() > 0) {
                rateLimitThrottle();
            }

        } while (!config.isLoopDone(++niter));

        if (config.isTimings()) {
            InstanceCookie::dumpTimings(instance, kgen.getStageString(), true);
        }
        return true;
    }

#ifndef WIN32
    pthread_t thr;
#endif

protected:
    // the callback methods needs to be able to set the error handler..
    friend void operationCallback(lcb_t, int, const lcb_RESPBASE*);
    Histogram histogram;

    void setError(lcb_error_t e) { error = e; }

private:

    void rateLimitThrottle() {
        lcb_U64 now = lcb_nstime();
        static lcb_U64 previous_time = now;

        const lcb_U64 elapsed_ns = now - previous_time;
        const lcb_U64 wanted_duration_ns =
                config.opsPerCycle * 1e9 / config.getRateLimit();
        // On first invocation no previous_time, so skip attempting to sleep.
        if (elapsed_ns > 0 && elapsed_ns < wanted_duration_ns) {
            // Dampen the sleep time by averaging with the previous
            // sleep time.
            static lcb_U64 last_sleep_ns = 0;
            const lcb_U64 sleep_ns =
                    (last_sleep_ns + wanted_duration_ns - elapsed_ns) / 2;
            usleep(sleep_ns / 1000);
            now += sleep_ns;
            last_sleep_ns = sleep_ns;
        }
        previous_time = now;
    }

    KeyGenerator kgen;
    size_t niter;
    lcb_error_t error;
    lcb_t instance;
};

static void operationCallback(lcb_t, int, const lcb_RESPBASE *resp)
{
    ThreadContext *tc;

    tc = const_cast<ThreadContext *>(reinterpret_cast<const ThreadContext *>(resp->cookie));
    tc->setError(resp->rc);

#ifndef WIN32
    static volatile unsigned long nops = 1;
    static time_t start_time = time(NULL);
    static int is_tty = isatty(STDOUT_FILENO);
    if (is_tty) {
        if (++nops % 1000 == 0) {
            time_t now = time(NULL);
            time_t nsecs = now - start_time;
            if (!nsecs) { nsecs = 1; }
            unsigned long ops_sec = nops / nsecs;
            printf("OPS/SEC: %10lu\r", ops_sec);
            fflush(stdout);
        }
    }
#endif
}


std::list<ThreadContext *> contexts;

extern "C" {
    typedef void (*handler_t)(int);
}

#ifndef WIN32
static void sigint_handler(int)
{
    static int ncalled = 0;
    ncalled++;

    if (ncalled < 2) {
        log("Termination requested. Waiting threads to finish. Ctrl-C to force termination.");
        signal(SIGINT, sigint_handler); // Reinstall
        config.maxCycles = 0;
        return;
    }

    std::list<ThreadContext *>::iterator it;
    for (it = contexts.begin(); it != contexts.end(); ++it) {
        delete *it;
    }
    contexts.clear();
    exit(EXIT_FAILURE);
}

static void setup_sigint_handler()
{
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_handler = sigint_handler;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
}

extern "C" {
static void* thread_worker(void*);
}

static void start_worker(ThreadContext *ctx)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    int rc = pthread_create(&ctx->thr, &attr, thread_worker, ctx);
    if (rc != 0) {
        log("Couldn't create thread: (%d)", errno);
        exit(EXIT_FAILURE);
    }
}
static void join_worker(ThreadContext *ctx)
{
    void *arg = NULL;
    int rc = pthread_join(ctx->thr, &arg);
    if (rc != 0) {
        log("Couldn't join thread (%d)", errno);
        exit(EXIT_FAILURE);
    }
}

#else
static void setup_sigint_handler() {}
static void start_worker(ThreadContext *ctx) { ctx->run(); }
static void join_worker(ThreadContext *ctx) { (void)ctx; }
#endif

extern "C" {
static void *thread_worker(void *arg)
{
    ThreadContext *ctx = static_cast<ThreadContext *>(arg);
    ctx->run();
    return NULL;
}
}

int main(int argc, char **argv)
{
    int exit_code = EXIT_SUCCESS;
    setup_sigint_handler();

    Parser parser("cbc-pillowfight");
    config.addOptions(parser);
    parser.parse(argc, argv, false);
    config.processOptions();
    size_t nthreads = config.getNumThreads();
    log("Running. Press Ctrl-C to terminate...");

#ifdef WIN32
    if (nthreads > 1) {
        log("WARNING: More than a single thread on Windows not supported. Forcing 1");
        nthreads = 1;
    }
#endif

    struct lcb_create_st options;
    ConnParams& cp = config.params;
    lcb_error_t error;

    for (uint32_t ii = 0; ii < nthreads; ++ii) {
        cp.fillCropts(options);
        lcb_t instance = NULL;
        error = lcb_create(&instance, &options);
        if (error != LCB_SUCCESS) {
            log("Failed to create instance: %s", lcb_strerror(NULL, error));
            exit(EXIT_FAILURE);
        }
        lcb_install_callback3(instance, LCB_CALLBACK_STORE, operationCallback);
        lcb_install_callback3(instance, LCB_CALLBACK_GET, operationCallback);
        lcb_install_callback3(instance, LCB_CALLBACK_SDGET, operationCallback);
        lcb_install_callback3(instance, LCB_CALLBACK_SDSTORE, operationCallback);
        cp.doCtls(instance);

        new InstanceCookie(instance);

        lcb_connect(instance);
        lcb_wait(instance);
        error = lcb_get_bootstrap_status(instance);

        if (error != LCB_SUCCESS) {
            std::cout << std::endl;
            log("Failed to connect: %s", lcb_strerror(instance, error));
            exit(EXIT_FAILURE);
        }

        ThreadContext *ctx = new ThreadContext(instance, ii);
        contexts.push_back(ctx);
        start_worker(ctx);
    }

    for (std::list<ThreadContext *>::iterator it = contexts.begin();
            it != contexts.end(); ++it) {
        join_worker(*it);
    }
    return exit_code;
}
