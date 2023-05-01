/**
 *
 * @mainpage
 *
 * If you're new to this page, you may wish to read the @ref intro_sec first
 * to get started. If you're coming back here for reference, here are some
 * handy links to look at.
 *
 * * @subpage lcb-init
 * * @subpage lcb-kv-api
 * * @subpage lcb-cntl-settings
 *
 * You may read about related Couchbase software at http://docs.couchbase.com/
 *
 *
 * @section lcb_examples Examples
 *
 * * @ref example/minimal/minimal.c - Minimal example for connecting to a cluster
 *   and performing operations
 *
 * * @ref example/libeventdirect/main.c - Shows how to integrate with an external
 *   event library (libevent, in this case).
 *
 * @see more examples in devguides repository: https://github.com/couchbaselabs/devguide-examples/tree/master/c
 *
 * Some more extensive examples may be observed in the SDKs wrapping libcouchbase
 * to expose interfaces in their native languages.
 *
 * * Couchbase Python SDK (http://github.com/couchbase/couchbase-python-client).
 * * Couchbase node.js SDK (http://github.com/couchbase/couchnode)
 *
 *
 * @section lcb_jira Reporting Issues
 *
 * If you think you've found an issue, please file a bug on
 * https://couchbase.com/issues. Select the _Couchbase C Client_ project. Before
 * filing an issue, search for existing issues to determine if your issue has
 * not yet been fixed in a newer version.
 *
 */

/**
 * @example example/minimal/minimal.c
 * Shows how to connect to the cluster and perform operations
 *
 * @example example/libeventdirect/main.c
 * Shows how to integrate the library with an external event loop
 *
 * @example example/subdoc/subdoc-simple.cc
 * Shows how to use subdocument API.
 *
 * @example example/subdoc/subdoc-multi.cc
 * Shows how to make multi-path requests using subdocument API.
 *
 * @example example/subdoc/subdoc-xattrs.c
 * Shows how to work with XATTRs using subdocument API.
 *
 * @example example/crypto/openssl_symmetric_provider.c
 * Shows how to implement crypto provider using OpenSSL for field-level encryption.
 *
 * @example example/crypto/openssl_symmetric_encrypt.c
 * Shows how to use field-encryption API to encrypt JSON values.
 *
 * @example example/crypto/openssl_symmetric_decrypt.c
 * Shows how to use field-encryption API to decrypt JSON values.
 *
 * @example example/observe/observe.c
 * Show how to use oberve to request state of the key on the cluster.
 *
 * @example example/observe/durability.c
 * Show how to enforce durability requirements for store operations.
 *
 * @example example/tracing/tracing.c
 * Shows how to implement custom tracer (e.g. for OpenZipkin)
 *
 * @example example/tracing/views.c
 * Shows tracing for HTTP APIs of the cluster (e.g. Couchbase Views)
 *
 * @example example/fts/fts.c
 * Shows Full Text search queries.
 *
 * @example example/analytics/analytics.c
 * Shows N1QL for Analytics queries.
 *
 * @example example/minimal/query.c
 * Shows N1QL query API. Also because queries executed in a loop, the sample might be used as simple benchmark (more sofisticated shipped with cbc tools, as cbc-n1qlback)
 *
 * @example example/threads-shared/threads-shared.c
 * Shows how to protect single `lcb_INSTANCE` when it is shared between multiple threads.
 *
 * @example example/threads-private/threads-private.c
 * Shows how to bind `lcb_INSTANCE` to each thread, and how to use custom logger in the thread-safe way.
 */

/**
 * @internal
 * @defgroup lcb-public-api Public API
 * @brief Public API Routines
 * @details
 *
 * This covers the functions and structures of the library which are public
 * interfaces. These consist of functions decorated with `LIBCOUCHBASE_API`
 * and which are defined in the `libcouchbase` header directory.
 */

/**
 * @internal
 * @defgroup lcb-generics Generic Types
 * @brief Generic utilities and containers
 * @addtogroup lcb-generics
 * @{
 * @file src/list.h
 * @file src/sllist.h
 * @file src/sllist-inl.h
 * @file src/hostlist.h
 * @}
 *
 *
 * @defgroup lcb-clconfig Bucket/Cluster Configuration
 * @brief This module retrieves and processes cluster configurations from a
 * variety of sources
 * @addtogroup lcb-clconfig
 * @{
 * @file src/bucketconfig/clconfig.h
 * @}
 */

/**
 * @page lcb_thrsafe Thread Safety
 *
 * This library is not designed to be thread-safe. However, it should be safe to use one `lcb_INSTANCE` object per
 * thread, with some caveats and careful consideration.
 *
 * 1. You must be certain that the `lcb_INSTANCE` is not shared with other threads. For performance, there are no
 *    internal locks or other thread safety mechanisms to protect internal data structures.
 *
 * 2. Also for performance reasons, the default logger is not thread-safe, and is not bound to a single `lcb_INSTANCE`.
 *    Therefore, a multi-threaded application must also override the logger with a thread-safe version or use a separate
 *    logger for each instance (see example @ref example/threads-private/threads-private.c).
 *
 * 3. Likewise, any other shared instances that are registered with the library (e.g., `lcb_io_opt_t`) must also be
 *    protected in a similar manner. Such instances must either be protected and made thread-safe internally or a new
 *    instance per `lcb_INSTANCE` can be provided.
 *
 * As with any multi-threaded application extra testing and analysis should be done using a tool like
 * <a href="https://valgrind.org/docs/manual/drd-manual.html">Valgrind/DRD</a>,
 * <a href="https://clang.llvm.org/docs/ThreadSanitizer.html">ThreadSanitizer</a> or similar.
 *
 * * @ref example/threads-shared/threads-shared.c - this example shows how to protect single `lcb_INSTANCE` when it is
 *   shared between multiple threads.
 *
 * * @ref example/threads-private/threads-private.c - this example shows how to bind `lcb_INSTANCE` to each thread, and
 *   how to use custom logger in the thread-safe way.
 */
