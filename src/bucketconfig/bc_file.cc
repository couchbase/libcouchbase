/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013-2020 Couchbase, Inc.
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
#include <lcbio/timer-cxx.h>
#include <fstream>
#include <istream>
#include <cstring>

#define CONFIG_CACHE_MAGIC "{{{fb85b563d0a8f65fa8d3d58f1b3a0708}}}"

#define LOGARGS(pb, lvl) static_cast<Provider *>(pb)->parent->settings, "bc_file", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOGFMT "(cache=%s) "
#define LOGID(fb) fb->filename.c_str()

using namespace lcb::clconfig;

struct FileProvider : Provider, Listener {
    explicit FileProvider(Confmon *parent_);
    ~FileProvider() override;

    enum Status { CACHE_ERROR, NO_CHANGES, UPDATED };
    Status load_cache();
    void reload_cache();
    void maybe_remove_file() const
    {
        if (!is_readonly && !filename.empty()) {
            remove(filename.c_str());
        }
    }
    void write_cache(lcbvb_CONFIG *cfg);
    void mkcachefile(const char *name, const char *bucket);

    /* Overrides */
    ConfigInfo *get_cached() override;
    lcb_STATUS refresh() override;
    void dump(FILE *) const override;
    void clconfig_lsn(EventType, ConfigInfo *) override;

    std::string filename;
    ConfigInfo *config;
    time_t last_mtime;
    int last_errno;
    bool is_readonly; /* Whether the config cache should _not_ overwrite the file */
    lcb::io::Timer<FileProvider, &FileProvider::reload_cache> timer;
    bool do_not_cache_cluster{true};
};

FileProvider::Status FileProvider::load_cache()
{
    if (filename.empty()) {
        return CACHE_ERROR;
    }

    std::ifstream ifs(filename.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

    if (!ifs.is_open() || !ifs.good()) {
        int save_errno = last_errno = errno;
        lcb_log(LOGARGS(this, WARN),
                LOGFMT "Couldn't open config cache for reading (%s). Proceed to next configuration provider.",
                LOGID(this), strerror(save_errno));
        return CACHE_ERROR;
    }

    struct stat st {
    };
    if (stat(filename.c_str(), &st)) {
        last_errno = errno;
        return CACHE_ERROR;
    }

    if (last_mtime == st.st_mtime) {
        lcb_log(LOGARGS(this, DEBUG), LOGFMT "Modification time too old", LOGID(this));
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
    if (end == nullptr) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Couldn't find magic", LOGID(this));
        maybe_remove_file();
        return CACHE_ERROR;
    }
    *end = '\0'; // Stop parsing at MAGIC

    lcbvb_CONFIG *vbc = lcbvb_create();
    if (vbc == nullptr) {
        return CACHE_ERROR;
    }

    Status status = CACHE_ERROR;

    if (lcbvb_load_json(vbc, &buf[0]) != 0) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Couldn't parse configuration", LOGID(this));
        lcb_log_badconfig(LOGARGS(this, ERROR), vbc, &buf[0]);
        maybe_remove_file();
        goto GT_DONE;
    }

    if (lcbvb_get_distmode(vbc) == LCBVB_DIST_KETAMA) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Not applying cached memcached config", LOGID(this));
        goto GT_DONE;
    }

    if (settings().bucket == nullptr && vbc->bname != nullptr) {
        lcb_log(
            LOGARGS(this, DEBUG),
            LOGFMT
            "The cached configuration has bucket associated, but the connection does not have it. Ignore the cache.",
            LOGID(this));
        goto GT_DONE;
    } else if (settings().bucket != nullptr && vbc->bname == nullptr) {
        lcb_log(
            LOGARGS(this, DEBUG),
            LOGFMT
            "The connection has bucket associated, but the cached configuration does not have it. Ignore the cache.",
            LOGID(this));
        goto GT_DONE;
    } else if (settings().bucket != nullptr && vbc->bname != nullptr && strcmp(vbc->bname, settings().bucket) != 0) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Bucket name in file is different from the one requested", LOGID(this));
        goto GT_DONE;
    }

    if (config) {
        config->decref();
    }

    config = ConfigInfo::create(vbc, CLCONFIG_FILE, filename);
    last_mtime = st.st_mtime;

    status = UPDATED;
    vbc = nullptr;

GT_DONE:
    if (vbc != nullptr) {
        lcbvb_destroy(vbc);
    }
    return status;
}

void FileProvider::write_cache(lcbvb_CONFIG *cfg)
{
    if (filename.empty() || is_readonly || (do_not_cache_cluster && parent->settings->conntype == LCB_TYPE_CLUSTER)) {
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

ConfigInfo *FileProvider::get_cached()
{
    return filename.empty() ? nullptr : config;
}

void FileProvider::reload_cache()
{
    if (load_cache() == UPDATED) {
        parent->provider_got_config(this, config);
    } else {
        parent->provider_failed(this, LCB_ERR_GENERIC);
    }
}

lcb_STATUS FileProvider::refresh()
{
    if (!timer.is_armed()) {
        timer.signal();
    }
    return LCB_SUCCESS;
}

FileProvider::~FileProvider()
{
    timer.release();
    if (config) {
        config->decref();
    }
}

void FileProvider::clconfig_lsn(EventType event, ConfigInfo *info)
{
    if (event != CLCONFIG_EVENT_GOT_NEW_CONFIG) {
        return;
    }
    if (!enabled) {
        return;
    }

    if (info->get_origin() == CLCONFIG_PHONY || info->get_origin() == CLCONFIG_FILE) {
        lcb_log(LOGARGS(this, TRACE), "Not writing configuration originating from PHONY or FILE to cache");
        return;
    }

    write_cache(info->vbc);
}

void FileProvider::dump(FILE *fp) const
{
    fprintf(fp, "## BEGIN FILE PROVIEDER DUMP ##\n");
    if (!filename.empty()) {
        fprintf(fp, "FILENAME: %s\n", filename.c_str());
    }
    fprintf(fp, "LAST SYSTEM ERRNO: %d\n", last_errno);
    fprintf(fp, "LAST MTIME: %lu\n", (unsigned long)last_mtime);
    fprintf(fp, "## END FILE PROVIDER DUMP ##\n");
}

FileProvider::FileProvider(Confmon *parent_)
    : Provider(parent_, CLCONFIG_FILE), config(nullptr), last_mtime(0), last_errno(0), is_readonly(false),
      timer(parent_->iot, this)
{
    parent->add_listener(this);
}

void FileProvider::mkcachefile(const char *name, const char *bucket)
{
    std::string buffer;
    bool is_dir = false;
    if (name != nullptr) {
        buffer = std::string(name);
        if (!buffer.empty() && buffer[buffer.size() - 1] == '/') {
            is_dir = true;
        }
    } else {
        buffer = lcb_get_tmpdir();
        if (buffer.empty()) {
            buffer += ".";
        }
        buffer += "/";
        is_dir = true;
    }
    if (is_dir) {
        // append bucket name only if we know that cachefile is directory
        if (bucket == nullptr) {
            buffer += ".cluster";
            do_not_cache_cluster = false;
        } else {
            buffer += bucket;
        }
    }

    filename = buffer;
}

bool lcb::clconfig::file_set_filename(Provider *p, const char *f, bool ro)
{
    auto *provider = static_cast<FileProvider *>(p);
    provider->enabled = true;
    provider->mkcachefile(f, p->parent->settings->bucket);
    if (provider->filename.empty()) {
        return false;
    }
    provider->is_readonly = bool(ro);

    if (ro) {
        FILE *fp_tmp = fopen(provider->filename.c_str(), "r");
        if (!fp_tmp) {
            lcb_log(LOGARGS(provider, ERROR), LOGFMT "Couldn't open for reading: %s", LOGID(provider), strerror(errno));
            return false;
        } else {
            fclose(fp_tmp);
        }
    }
    return true;
}

const char *lcb::clconfig::file_get_filename(Provider *p)
{
    auto *fp = static_cast<FileProvider *>(p);
    if (fp->filename.empty()) {
        return nullptr;
    } else {
        return fp->filename.c_str();
    }
}

void lcb::clconfig::file_set_readonly(Provider *p, bool val)
{
    static_cast<FileProvider *>(p)->is_readonly = val;
}

Provider *lcb::clconfig::new_file_provider(Confmon *mon)
{
    return new FileProvider(mon);
}
