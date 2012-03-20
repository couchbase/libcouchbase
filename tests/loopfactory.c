#include "server.h"
#include "test.h"
#include <stdlib.h>
#include <stdio.h>
#include <libcouchbase/couchbase.h>

#ifdef WIN32
#include <Windows.h>
#include <strsafe.h>
#else
#include <dlfcn.h>
#endif

#define FACTORY_SYMBOL "libcouchbase_create_test_loop"

/* Prototype for loop generator */
typedef struct libcouchbase_io_opt_st *(*loop_generator_func)(void);

/* our loaded generator */
static loop_generator_func loop_generator = NULL;

/* get the loop generator function */
static loop_generator_func get_loop_generator(const char *plugin_name);



static struct libcouchbase_io_opt_st *default_loop_generator(void)
{
    libcouchbase_error_t err;
    struct libcouchbase_io_opt_st *ret;
    ret = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL, &err);
    if (ret == NULL) {
        fprintf(stderr, "Couldn't generate default loop: errcode %d\n", err);
        abort();
    }
    return ret;
}

#ifdef WIN32
static void my_err_exit_win32(const char *operation, const char *arg, DWORD errcode)
{
    LPVOID errbuf;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errcode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &errbuf,
        0, NULL );
    fprintf(stderr, "%s(%s) failed: code=%d: %s\n", operation, arg, errcode, errbuf);
    abort();
}

static loop_generator_func get_loop_generator(const char *libname)
{
    HMODULE handle;
    FARPROC symbol;
    char fq_libname[2048];
    sprintf(fq_libname, "%s.dll", libname);

    handle = GetModuleHandle(fq_libname);
    if (handle == NULL) {
        my_err_exit_win32("LoadLibrary", fq_libname, GetLastError());
    }

    symbol = GetProcAddress(handle, FACTORY_SYMBOL);
    if (symbol == NULL) {
        my_err_exit_win32("GetProcAddress", FACTORY_SYMBOL, GetLastError());
    }

    return (loop_generator_func)symbol;
}
#else
static loop_generator_func get_loop_generator(const char *libname)
{
    char fq_libname[2048];
    void *handle;
    union c99hack {
       void *sym;
       loop_generator_func ret;
    } hack;

    snprintf(fq_libname, sizeof(fq_libname), "%s.so", libname);
    handle = dlopen(fq_libname, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't load %s: %s\n", fq_libname, dlerror());
        abort();
    }

    hack.sym = dlsym(handle, FACTORY_SYMBOL);
    if (hack.ret == NULL) {
        fprintf(stderr, "Could not find symbol %s: %s\n", FACTORY_SYMBOL,
                dlerror());
        abort();
    }
    return hack.ret;
}
#endif



struct libcouchbase_io_opt_st *get_test_io_opts(void)
{
    const char *plugin_base_name;
    char plugin_full_name[2048];

    if (loop_generator) {
        return loop_generator();
    }

    plugin_base_name = getenv("LIBCOUCHBASE_TEST_LOOP");
    if (plugin_base_name == NULL || *plugin_base_name == '\0') {
        if (getenv("LIBCOUCHBASE_VERBOSE_TESTS")) {
            printf("No loop specified. Using default loop\n");
        }
        loop_generator = default_loop_generator;
        return loop_generator();
    }
    printf("Will try to use loop: %s\n", plugin_base_name);

    sprintf(plugin_full_name, "libcouchbase_%s", plugin_base_name);
    loop_generator = get_loop_generator(plugin_full_name);
    return loop_generator();
}
