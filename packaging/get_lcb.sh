#!/bin/sh

git clone --branch release-2.10 git://github.com/couchbase/libcouchbase.git src
git clone --branch OpenSSL_1_1_1 git://github.com/openssl/openssl.git src/thirdparty/openssl
git clone --branch release-2.1.8-stable git://github.com/libevent/libevent.git src/thirdparty/libevent
git clone --branch v1.24.1 git://github.com/libuv/libuv.git src/thirdparty/libuv
curl http://dist.schmorp.de/libev/Attic/libev-4.24.tar.gz | tar zx -C src/thirdparty
