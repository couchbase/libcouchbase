/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

#include "internal.h"
#include "clconfig.h"
#include <lcbio/lcbio.h>
#include <lcbio/timer-ng.h>
#include <fstream>
#include <iostream>
#include <istream>

#define CONFIG_CACHE_MAGIC "{{{fb85b563d0a8f65fa8d3d58f1b3a0708}}}"

#define LOGARGS(pb, lvl) static_cast<clconfig_provider*>(pb)->parent->settings, "bc_file", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOGFMT "(cache=%s) "
#define LOGID(fb) fb->filename.c_str()

struct FileProvider : clconfig_provider, clconfig_listener {
    FileProvider(lcb_confmon* confmon);
    ~FileProvider();

    enum Status { CACHE_ERROR, NO_CHANGES, UPDATED };
    Status load_cache();
    void maybe_remove_file() {
        if (!is_readonly && !filename.empty()) {
            remove(filename.c_str());
        }
    }
    void write_cache(lcbvb_CONFIG *vbc);

    std::string filename;
    clconfig_info *config;
    time_t last_mtime;
    int last_errno;
    bool is_readonly; /* Whether the config cache should _not_ overwrite the file */
    lcbio_pTIMER timer;


};

FileProvider::Status FileProvider::load_cache()
{
    if (filename.empty()) {
        return CACHE_ERROR;
    }

    std::ifstream ifs(filename.c_str(),
                      std::ios::in | std::ios::binary | std::ios::ate);

    if (!ifs.is_open() || !ifs.good()) {
        int save_errno = last_errno = errno;
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Couldn't open for reading: %s", LOGID(this), strerror(save_errno));
        return CACHE_ERROR;
    }

    struct stat st;
    if (stat(filename.c_str(), &st)) {
        last_errno = errno;
        return CACHE_ERROR;
    }

    if (last_mtime == st.st_mtime) {
        lcb_log(LOGARGS(this, WARN), LOGFMT "Modification time too old", LOGID(this));
        return NO_CHANGES;
    }

    size_t fsize = ifs.tellg();
    if (!fsize) {
        lcb_log(LOGARGS(this, WARN), LOGFMT "File '%s' is empty", LOGID(this), filename.c_str());
        return CACHE_ERROR;
    }
    ifs.seekg(0, std::ios::beg);
    std::vector<char> buf(fsize);
    ifs.read(&buf[0], fsize);
    buf.push_back(0); // NUL termination

    char *end = std::strstr(&buf[0], CONFIG_CACHE_MAGIC);
    if (end == NULL) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Couldn't find magic", LOGID(this));
        maybe_remove_file();
        return CACHE_ERROR;
    }
    *end = '\0'; // Stop parsing at MAGIC

    lcbvb_CONFIG *vbc = lcbvb_create();
    if (vbc == NULL) {
        return CACHE_ERROR;
    }

    Status status = CACHE_ERROR;

    if (lcbvb_load_json(vbc, &buf[0]) != 0) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Couldn't parse configuration", LOGID(this));
        lcb_log_badconfig(LOGARGS(this, ERROR), vbc, &buf[0]);
        maybe_remove_file();
        goto GT_DONE;
    }

    if (lcbvb_get_distmode(vbc) != LCBVB_DIST_VBUCKET) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Not applying cached memcached config", LOGID(this));
        goto GT_DONE;
    }

    if (strcmp(vbc->bname, clconfig_provider::parent->settings->bucket) != 0) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Bucket name in file is different from the one requested", LOGID(this));
        goto GT_DONE;
    }

    if (config) {
        lcb_clconfig_decref(config);
    }

    config = lcb_clconfig_create(vbc, LCB_CLCONFIG_FILE);
    config->cmpclock = gethrtime();
    last_mtime = st.st_mtime;

    status = UPDATED;
    vbc = NULL;

    GT_DONE:
    if (vbc != NULL) {
        lcbvb_destroy(vbc);
    }
    return status;
}

void FileProvider::write_cache(lcbvb_CONFIG *cfg)
{
    if (filename.empty() || is_readonly) {
        return;
    }

    std::ofstream ofs(filename.c_str(), std::ios::trunc);
    if (ofs.good()) {
        lcb_log(LOGARGS(this, INFO), LOGFMT "Writing configuration to file", LOGID(this));
        char *json = lcbvb_save_json(cfg);
        ofs << json;
        ofs << CONFIG_CACHE_MAGIC;
        free(json);
    } else {
        int save_errno = errno;
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Couldn't open file for writing: %s", LOGID(this), strerror(save_errno));
    }
}

static clconfig_info * get_cached(clconfig_provider *pb)
{
    FileProvider *provider = static_cast<FileProvider*>(pb);
    if (provider->filename.empty()) {
        return NULL;
    }

    return provider->config;
}

static void async_callback(void *cookie)
{
    FileProvider *provider = reinterpret_cast<FileProvider*>(cookie);
    if (provider->load_cache() == FileProvider::UPDATED) {
        lcb_confmon_provider_success(provider, provider->config);
    } else {
        lcb_confmon_provider_failed(provider, LCB_ERROR);
    }
}

static lcb_error_t refresh_file(clconfig_provider *pb)
{
    FileProvider *provider = static_cast<FileProvider*>(pb);
    if (lcbio_timer_armed(provider->timer)) {
        return LCB_SUCCESS;
    }

    lcbio_async_signal(provider->timer);
    return LCB_SUCCESS;
}

static lcb_error_t pause_file(clconfig_provider *pb)
{
    (void)pb;
    return LCB_SUCCESS;
}

FileProvider::~FileProvider() {
    if (timer) {
        lcbio_timer_destroy(timer);
    }
    if (config) {
        lcb_clconfig_decref(config);
    }
}

static void shutdown_file(clconfig_provider *pb)
{
    delete static_cast<FileProvider*>(pb);
}

static void config_listener(clconfig_listener *lsn, clconfig_event_t event,
                            clconfig_info *info)
{
    if (event != CLCONFIG_EVENT_GOT_NEW_CONFIG) {
        return;
    }

    FileProvider *provider = static_cast<FileProvider*>(lsn);
    if (!provider->enabled) {
        return;
    }

    if (info->origin == LCB_CLCONFIG_PHONY || info->origin == LCB_CLCONFIG_FILE) {
        lcb_log(LOGARGS(provider, TRACE), "Not writing configuration originating from PHONY or FILE to cache");
        return;
    }

    provider->write_cache(info->vbc);
}

static void
do_file_dump(clconfig_provider *pb, FILE *fp)
{
    FileProvider *pr = static_cast<FileProvider*>(pb);

    fprintf(fp, "## BEGIN FILE PROVIEDER DUMP ##\n");
    if (!pr->filename.empty()) {
        fprintf(fp, "FILENAME: %s\n", pr->filename.c_str());
    }
    fprintf(fp, "LAST SYSTEM ERRNO: %d\n", pr->last_errno);
    fprintf(fp, "LAST MTIME: %lu\n", (unsigned long)pr->last_mtime);
    fprintf(fp, "## END FILE PROVIDER DUMP ##\n");

}

FileProvider::FileProvider(lcb_confmon *parent_)
    : config(NULL), last_mtime(0), last_errno(0), is_readonly(false),
      timer(lcbio_timer_new(parent_->iot, this, async_callback)) {

    memset(static_cast<clconfig_provider*>(this), 0, sizeof(clconfig_provider));
    memset(static_cast<clconfig_listener*>(this), 0, sizeof(clconfig_listener));

    clconfig_provider::get_cached = ::get_cached;
    clconfig_provider::refresh = ::refresh_file;
    clconfig_provider::pause = ::pause_file;
    clconfig_provider::shutdown = ::shutdown_file;
    clconfig_provider::dump = ::do_file_dump;
    clconfig_provider::type = LCB_CLCONFIG_FILE;
    clconfig_listener::callback = ::config_listener;

    lcb_confmon_add_listener(parent_, this);
}

clconfig_provider * lcb_clconfig_create_file(lcb_confmon *parent)
{
    return new FileProvider(parent);
}

static std::string mkcachefile(const char *name, const char *bucket)
{
    if (name != NULL) {
        return std::string(name);
    } else {
        std::string buffer(lcb_get_tmpdir());
        if (buffer.empty()) {
            buffer += ".";
        }
        buffer += "/";
        buffer += bucket;
        return buffer;
    }
}

int lcb_clconfig_file_set_filename(clconfig_provider *p, const char *f, int ro)
{
    FileProvider *provider = static_cast<FileProvider*>(p);
    provider->enabled = 1;
    provider->filename = mkcachefile(f, p->parent->settings->bucket);
    provider->is_readonly = bool(ro);

    if (ro) {
        FILE *fp_tmp = fopen(provider->filename.c_str(), "r");
        if (!fp_tmp) {
            lcb_log(LOGARGS(provider, ERROR), LOGFMT "Couldn't open for reading: %s", LOGID(provider), strerror(errno));
            return -1;
        } else {
            fclose(fp_tmp);
        }
    }
    return 0;
}

const char *
lcb_clconfig_file_get_filename(clconfig_provider *p)
{
    FileProvider *fp = static_cast<FileProvider*>(p);
    if (fp->filename.empty()) {
        return NULL;
    } else {
        return fp->filename.c_str();
    }
}

void
lcb_clconfig_file_set_readonly(clconfig_provider *p, int val)
{
    static_cast<FileProvider*>(p)->is_readonly = bool(val);
}
