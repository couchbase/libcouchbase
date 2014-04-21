/**
 *
 * @mainpage
 *
 * @section intro_sec Introduction
 *
 * libcouchbase is an asynchronous library for connecting to a Couchbase
 * server and performing data operations.
 *
 * This contains the API documentation for the library. The documentation
 * consists of both _internal_ and _public_ interfaces.
 *
 * The library's function/structure prefix is for the most part `lcb_`.
 */

/**
 * @defgroup LCB_PUBAPI Public API
 * @brief Public API Routines
 * @details
 *
 * This covers the functions and structures of the library which are public
 * interfaces. These consist of functions decorated with `LIBCOUCHBASE_API`
 * and which are defined in the `libcouchbase` header directory.
 */


/**
 * @def LIBCOUCHBASE_API
 * @brief Public API Symbol
 * This indicates that the function is suitable for use outside the library's
 * internals
 */

/**
 * @def LCB_INTERNAL_API
 * @brief Internal API Symbol
 * This indicates that the function is for internal use only
 */
