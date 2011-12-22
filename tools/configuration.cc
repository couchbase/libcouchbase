/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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

#include <cstdlib>
#include "tools/configuration.h"

Configuration::Configuration() {
    using namespace std;
    setHost(getenv("COUCHBASE_CLUSTER_URI"));
    setUser(getenv("COUCHBASE_CLUSTER_USER"));
    setPassword(getenv("COUCHBASE_CLUSTER_PASSWORD"));
    setBucket(getenv("COUCHBASE_CLUSTER_BUCKET"));
}

Configuration::~Configuration() {
}

void Configuration::setHost(const char *h) {
    if (h != NULL) {
        host.assign(h);
    }
}

const char *Configuration::getHost() const {
    if (host.length() > 0) {
        return host.c_str();
    }
    return NULL;
}

void Configuration::setUser(const char *u) {
    if (u) {
        user.assign(u);
    }
}

const char *Configuration::getUser() const {
    if (user.length() > 0) {
        return user.c_str();
    }
    return NULL;
}

void Configuration::setPassword(const char *p) {
    if (p) {
        passwd.assign(p);
    }
}

const char *Configuration::getPassword() const {
    if (passwd.length() > 0) {
        return passwd.c_str();
    }
    return NULL;
}

void Configuration::setBucket(const char *b) {
    if (b)  {
        bucket.assign(b);
    }
}

const char *Configuration::getBucket() const {
    if (bucket.length() > 0) {
        return bucket.c_str();
    }
    return NULL;
}
