/* -*- Mode: CPP; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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

/**
 * We don't have a real getopt_long implementation on Windows, so I've
 * added a scaled down version in the win32 directory. This small test
 * program tries to verify that it at least got some basic functionality
 * working.
 *
 * @author Trond Norbye
 */
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <iostream>
#include <getopt.h>
#include <vector>
#include <sstream>

int error = 0;

#define fail(message) \
   do { \
       std::cerr << "Failed: " << __FILE__ << ":" \
                 << __LINE__ << ": " << #message \
                 << std::endl; \
       return 1; \
   } while (0)

#define verify(expression) \
   do { \
       if (!(expression)) { \
           fail(expression); \
       } \
   } while (0)

#define assertTrue(a) verify(a)
#define assertFalse(a) verify(!a)
#define assertEquals(a, b) verify(a == b)

class CommandLineOption {
 public:
 CommandLineOption(char s, const char *l, bool arg) :
    shortopt(s), longopt(strdup(l)), hasArgument(arg), found(false),
        argument(NULL) {}

    ~CommandLineOption() {
        free(longopt);
    }

    char shortopt;
    char *longopt;
    bool hasArgument;
    bool found;
    char *argument;
};

class Getopt {
 public:
    Getopt() {
        verbose = getenv("LIBCOUCHBASE_VERBOSE_TESTS") != 0;
    }

    Getopt &addOption(CommandLineOption* option) {
        options.push_back(option);
        return *this;
    }

    int populateArgv(const std::vector<std::string> &argv, char **av) {
        std::vector<std::string>::const_iterator it;
        av[0] = const_cast<char*>("getopt-test");
        int ii = 1;

        if (verbose) {
            std::cout << "parse: { ";
        }
        bool needcomma = false;

        for (it = argv.begin(); it != argv.end(); ++it, ++ii) {
            av[ii] = const_cast<char*>(it->c_str());
            if (verbose) {
                if (needcomma) {
                    std::cout << ", ";
                }
                std::cout << it->c_str();
            }
            needcomma = true;
        }
        if (verbose) {
            std::cout << " }" << std::endl;
        }
        return ii;
    }

    bool parse(const std::vector<std::string> &argv) {
        optind = 0;
        optarg = NULL;
        if (argv.size() > 256) {
            return false;
        }
        struct option opts[256];
        char *av[256] = {};
        int argc = populateArgv(argv, av);
        memset(opts, 0, 256 * sizeof(*opts));
        std::stringstream ss;
        std::vector<CommandLineOption*>::iterator iter;
        int ii = 0;
        for (iter = options.begin(); iter != options.end(); ++iter, ++ii) {
            opts[ii].name = (*iter)->longopt;
            opts[ii].has_arg = (*iter)->hasArgument ? required_argument : no_argument;
            opts[ii].val = (*iter)->shortopt;
            ss << (*iter)->shortopt;
            if ((*iter)->hasArgument) {
                ss << ":";
            }
        }

        optarg = NULL;
        optind = 0;
        std::string shortopts = ss.str();
        int c;
        while ((c = getopt_long(argc, av, shortopts.c_str(), opts, NULL)) != -1) {
            for (iter = options.begin(); iter != options.end(); ++iter, ++ii) {
                if ((*iter)->shortopt == c) {
                    (*iter)->found = true;
                    (*iter)->argument = optarg;
                    break;
                }
            }
            if (iter == options.end()) {
                return false;
            }
        }

        return true;
    }

    bool verbose;
    std::vector<CommandLineOption*> options;
};

static void setup(Getopt &getopt) {
    getopt.addOption(new CommandLineOption('a', "alpha", true)).
        addOption(new CommandLineOption('b', "bravo", false)).
        addOption(new CommandLineOption('c', "charlie", false));
}

static int testParseEmptyNoOptions(void) {
    std::vector<std::string> argv;
    Getopt getopt;
    if (!getopt.parse(argv)) {
        fail("Parse should allow no arguments");
    }

    // validate that none of the options is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertFalse((*iter)->found);
    }

    return 0;
}

static int testParseEmpty(void) {
    std::vector<std::string> argv;
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("Parse should allow no arguments");
    }

    // validate that none of the options is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertFalse((*iter)->found);
    }
    return 0;
}

static int testParseOnlyArguments(void) {
    std::vector<std::string> argv;
    argv.push_back("foo");
    argv.push_back("bar");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("Parse should allow no arguments");
    }

    // validate that none of the options is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertFalse((*iter)->found);
    }

    assertEquals(1, optind);

    return 0;
}

static int testParseOnlyArgumentsWithSeparatorInThere() {
    std::vector<std::string> argv;
    argv.push_back("foo");
    argv.push_back("--");
    argv.push_back("bar");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("Parse should allow no arguments");
    }

    // validate that none of the options is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertFalse((*iter)->found);
    }

    return 0;
}

static int testParseSingleLongoptWithoutArgument() {
    std::vector<std::string> argv;
    argv.push_back("--bravo");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    // validate that --bravo is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'b') {
            assertTrue((*iter)->found);
        } else {
            assertFalse((*iter)->found);
        }
    }
    return 0;
}

static int testParseSingleLongoptWithoutRequiredArgument() {
    std::vector<std::string> argv;
    argv.push_back("--alpha");
    Getopt getopt;
    setup(getopt);
    if (getopt.parse(argv)) {
        fail("parse should fail");
    }
    return 0;
}

static int testParseSingleLongoptWithRequiredArgument() {
    std::vector<std::string> argv;
    argv.push_back("--alpha=foo");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    // validate that --alpha is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'a') {
            assertTrue((*iter)->found);
            verify(strcmp((*iter)->argument, "foo") == 0);
        } else {
            assertFalse((*iter)->found);
        }
    }
    return 0;
}

static int testParseSingleLongoptWithRequiredArgument1() {
    std::vector<std::string> argv;
    argv.push_back("--alpha");
    argv.push_back("foo");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    // validate that --alpha is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'a') {
            assertTrue((*iter)->found);
            verify(strcmp((*iter)->argument, "foo") == 0);
        } else {
            assertFalse((*iter)->found);
        }
    }
    return 0;
}

static int testParseMulipleLongoptWithArgumentsAndOptions() {
    std::vector<std::string> argv;
    argv.push_back("--alpha=foo");
    argv.push_back("--bravo");
    argv.push_back("--charlie");
    argv.push_back("foo");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    // validate that --alpha, bravo and charlie is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertTrue((*iter)->found);
        if ((*iter)->shortopt == 'a') {
            verify(strcmp((*iter)->argument, "foo") == 0);
        }
    }

    assertEquals(4, optind);
    return 0;
}

static int testParseMulipleLongoptWithArgumentsAndOptionsAndSeparator() {

    std::vector<std::string> argv;
    argv.push_back("--alpha=foo");
    argv.push_back("--");
    argv.push_back("--bravo");
    argv.push_back("--charlie");
    argv.push_back("foo");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'a') {
            assertTrue((*iter)->found);
            verify(strcmp((*iter)->argument, "foo") == 0);
        } else {
            assertFalse((*iter)->found);
        }
    }
    assertEquals(3, optind);
    return 0;
}

static int testParseMulipleLongoptWithArgumentsAndOptionsAndSeparator1() {

    std::vector<std::string> argv;
    argv.push_back("--alpha");
    argv.push_back("foo");
    argv.push_back("--");
    argv.push_back("--bravo");
    argv.push_back("--charlie");
    argv.push_back("foo");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'a') {
            assertTrue((*iter)->found);
            verify(strcmp((*iter)->argument, "foo") == 0);
        } else {
            assertFalse((*iter)->found);
        }
    }
    assertEquals(4, optind);
    return 0;
}

static int testParseSingleShortoptWithoutArgument() {
    std::vector<std::string> argv;
    argv.push_back("-b");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    // validate that -b is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'b') {
            assertTrue((*iter)->found);
        } else {
            assertFalse((*iter)->found);
        }
    }
    return 0;
}

static int testParseSingleShortoptWithoutRequiredArgument() {
    std::vector<std::string> argv;
    argv.push_back("-a");
    Getopt getopt;
    setup(getopt);
    if (getopt.parse(argv)) {
        fail("parse should fail with a missing argument");
    }

    // validate that none is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertFalse((*iter)->found);
    }
    return 0;
}

static int testParseSingleShortoptWithRequiredArgument() {
    std::vector<std::string> argv;
    argv.push_back("-a");
    argv.push_back("foo");
    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }

    // validate that none is set
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'a') {
            assertTrue((*iter)->found);
            verify(strcmp((*iter)->argument, "foo") == 0);
        } else {
            assertFalse((*iter)->found);
        }
    }
    return 0;
}

static int testParseMulipleShortoptWithArgumentsAndOptions() {
    std::vector<std::string> argv;
    argv.push_back("-a");
    argv.push_back("foo");
    argv.push_back("-b");
    argv.push_back("-c");
    argv.push_back("foo");

    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertTrue((*iter)->found);
        if ((*iter)->shortopt == 'a') {
            verify(strcmp((*iter)->argument, "foo") == 0);
        }
    }

    assertEquals(5, optind);
    return 0;
}

static int testParseMulipleShortoptWithArgumentsAndOptionsAndSeparator() {
    std::vector<std::string> argv;
    argv.push_back("-a");
    argv.push_back("foo");
    argv.push_back("--");
    argv.push_back("-b");
    argv.push_back("-c");
    argv.push_back("foo");

    Getopt getopt;
    setup(getopt);
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->shortopt == 'a') {
            assertTrue((*iter)->found);
            verify(strcmp((*iter)->argument, "foo") == 0);
        } else {
            assertFalse((*iter)->found);
        }
    }

    assertEquals(4, optind);
    return 0;
}

static int testParseMix() {
    std::vector<std::string> argv;
    argv.push_back("-alpha");
    argv.push_back("foo");
    argv.push_back("-a");
    argv.push_back("bar");
    argv.push_back("-c");
    argv.push_back("--bravo");
    argv.push_back("-bc");
    argv.push_back("foo");

    Getopt getopt;
    setup(getopt);

#ifdef _WIN32
    assertFalse(getopt.parse(argv));
#else
    if (!getopt.parse(argv)) {
        fail("parse should succeed");
    }
    std::vector<CommandLineOption*>::const_iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        assertTrue((*iter)->found);
        if ((*iter)->shortopt == 'a') {
            // the second -a overrides the first
            verify(strcmp((*iter)->argument, "bar") == 0);
        }
    }

    assertEquals(7, optind);
#endif
    return 0;
}

int main()
{
    error += testParseEmptyNoOptions();
    error += testParseEmpty();
    error += testParseOnlyArguments();
    error += testParseOnlyArgumentsWithSeparatorInThere();
    error += testParseSingleLongoptWithoutArgument();
    error += testParseSingleLongoptWithoutRequiredArgument();
    error += testParseSingleLongoptWithRequiredArgument();
    error += testParseSingleLongoptWithRequiredArgument1();
    error += testParseMulipleLongoptWithArgumentsAndOptions();
    error += testParseMulipleLongoptWithArgumentsAndOptionsAndSeparator();
    error += testParseMulipleLongoptWithArgumentsAndOptionsAndSeparator1();
    error += testParseSingleShortoptWithoutArgument();
    error += testParseSingleShortoptWithoutRequiredArgument();
    error += testParseSingleShortoptWithRequiredArgument();
    error += testParseMulipleShortoptWithArgumentsAndOptions();
    error += testParseMulipleShortoptWithArgumentsAndOptionsAndSeparator();
    error += testParseMix();

    if (error != 0) {
        std::cerr << error << " tests failed" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
