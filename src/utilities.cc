/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2020 Couchbase, Inc.
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

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <limits>

#include "internal.h"

/**
 * This file contains utility functions which don't have another place
 * to call home
 */

extern std::uint64_t lcb_byteswap64(std::uint64_t val)
{
    lcb_size_t ii;
    std::uint64_t ret = 0;
    for (ii = 0; ii < sizeof(std::uint64_t); ii++) {
        ret <<= 8;
        ret |= val & 0xff;
        val >>= 8;
    }
    return ret;
}

extern std::uint16_t lcb_byteswap16(std::uint16_t val)
{
    return ((val & 0xff) << 8) | ((val >> 8) & 0xff);
}

/**
 * While the C standard library uses 'putenv' for environment variable
 * manipulation, POSIX defines setenv (which works sanely) but Windows
 * only has putenv (via the CRT interface).
 * However Windows also has the 'GetEnvironmentVariable' etc. API - which
 * actually uses a different interface.
 *
 * We prefer to use actual API calls rather than hack into a poor excuse
 * of conformance. Since putenv requires ownership of the string, its use
 * is discouraged (and _putenv_s isn't available in MinGW); thus the
 * assumption that the most common APIs are GetEnvironmentVariable and
 * SetEnvironmentVariable. We try to abstract this away from the rest of the
 * library.
 */

#ifdef _WIN32
int lcb_getenv_nonempty(const char *key, char *buf, lcb_size_t len)
{
    DWORD nvalue = GetEnvironmentVariable(key, buf, (DWORD)len);

    if (nvalue == 0 || nvalue >= len) {
        return 0;
    }

    if (!buf[0]) {
        return 0;
    }
    return 1;
}

#else
int lcb_getenv_nonempty(const char *key, char *buf, lcb_size_t len)
{
    const char *cur = getenv(key);
    if (cur == nullptr || *cur == '\0') {
        return 0;
    }

    strncpy(buf, cur, len);
    return 1;
}
#endif

int lcb_getenv_boolean(const char *key)
{
    char value[4096] = {0};
    int rv;
    rv = lcb_getenv_nonempty(key, value, sizeof(value));
    return rv != 0 && value[0] != '\0' && value[0] != '0';
}

#ifdef _WIN32
lcb_STATUS lcb_initialize_socket_subsystem(void)
{
    static volatile LONG initialized = 0;
    WSADATA wsaData;

    if (InterlockedCompareExchange(&initialized, 1, 0)) {
        return LCB_SUCCESS;
    }
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
        lcb_assert("Winsock initialization error" && 0);
    }
    return LCB_SUCCESS;
}
#else
lcb_STATUS lcb_initialize_socket_subsystem(void)
{
    return LCB_SUCCESS;
}
#endif

int lcb_getenv_nonempty_multi(char *buf, lcb_size_t nbuf, ...)
{
    va_list ap;
    const char *cur;
    int found = 0;

    va_start(ap, nbuf);
    while ((cur = va_arg(ap, const char *))) {
        if ((found = lcb_getenv_nonempty(cur, buf, nbuf))) {
            break;
        }
    }
    va_end(ap);
    return found;
}

int lcb_getenv_boolean_multi(const char *key, ...)
{
    va_list ap;
    const char *cur;
    int ret = 0;

    va_start(ap, key);
    if (lcb_getenv_boolean(key)) {
        va_end(ap);
        return 1;
    }

    while ((cur = va_arg(ap, const char *))) {
        if ((ret = lcb_getenv_boolean(cur))) {
            break;
        }
    }
    va_end(ap);
    return ret;
}

const char *lcb_get_tmpdir(void)
{
#if defined(_WIN32)
    static char buf[MAX_PATH + 1] = {0};
    if (buf[0]) {
        return buf;
    }
    GetTempPath(sizeof buf, buf);
    return buf;
#else
    const char *ret;
    if ((ret = getenv("TMPDIR")) != nullptr) {
        return ret;
    } else {

#if defined(_POSIX_VERSION)
        return "/tmp";
#else
        return ".";
#endif
    }
#endif
}

LCB_INTERNAL_API
char *lcb_strdup(const char *str)
{
    size_t len;
    char *copy;

    len = strlen(str) + 1;
    copy = static_cast<char *>(malloc(len));
    if (copy == nullptr) {
        return nullptr;
    }
    memcpy(copy, str, len);

    return copy;
}

lcb_STATUS lcb::flexible_framing_extras::encode_impersonate_user(const std::string &username,
                                                                 std::vector<std::uint8_t> &flexible_framing_extras)
{
    auto username_len = username.size();
    if (username_len > std::numeric_limits<std::uint8_t>::max() + 0xfU) {
        return LCB_ERR_INVALID_ARGUMENT;
    }
    std::uint8_t frame_id = 0x04;
    if (username_len < 15) {
        auto frame_size = static_cast<std::uint8_t>(username_len);
        flexible_framing_extras.emplace_back(frame_id << 4U | frame_size);
    } else {
        flexible_framing_extras.emplace_back(frame_id << 4U | 0xfU);
        flexible_framing_extras.emplace_back(username_len - 0xfU);
    }
    for (const auto byte : username) {
        flexible_framing_extras.emplace_back(byte);
    }
    return LCB_SUCCESS;
}

lcb_STATUS lcb::flexible_framing_extras::encode_impersonate_users_extra_privilege(
    const std::string &privilege, std::vector<std::uint8_t> &flexible_framing_extras)
{
    auto privilege_len = privilege.size();
    if (privilege_len > std::numeric_limits<std::uint8_t>::max() + 0xfU) {
        return LCB_ERR_INVALID_ARGUMENT;
    }
    std::uint8_t frame_id = 0x06;
    if (privilege_len < 15) {
        auto frame_size = static_cast<std::uint8_t>(privilege_len);
        flexible_framing_extras.emplace_back(frame_id << 4U | frame_size);
    } else {
        flexible_framing_extras.emplace_back(frame_id << 4U | 0xfU);
        flexible_framing_extras.emplace_back(privilege_len - 0xfU);
    }
    for (const auto byte : privilege) {
        flexible_framing_extras.emplace_back(byte);
    }
    return LCB_SUCCESS;
}
