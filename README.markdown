What is libcouchbase
====================

libcouchbase is a callback oriented client which makes it very easy to
write high performance, thread safe programs. If you're interested in
the early history of libcouchbase you might want to check out the blog
post

http://trondn.blogspot.com/2011/10/libcouchbase-explore-full-features-of.html

The key component of libcouchbase is that its asynchronous, giving you
full freedom in adding it to your application logic. From using the
asynchronous interface you may schedule a lot of operations to be
performed, and then you'll get the callbacks whenever they are
performed. I do know that there are a lot of people who _don't_ care
about an async interface, so you _may_ also enable synchronous
mode. When synchronous mode is enabled you can't use this batching.

Examples
--------

You might want to read the blog post I wrote where I create a small
example program and explains why we need to do certain stuff at:

http://trondn.blogspot.com/2012/01/so-how-do-i-use-this-libcouchbase.html

Unfortunately for you we've later completely refactored the API, so
when you've read and understood the idea behind the library in the
above blog post you should read the following post explaining the
rationale behind changing the API, and what you as a user have to do..

http://trondn.blogspot.no/2012/08/libcouchbase-overhauling.html

Bugs
----

Please see: http://www.couchbase.com/issues/browse/CCBC

Run the testsuite towards a running cluster
-------------------------------------------

    LCB_TEST_CLUSTER_CONF=<hostname>,<bucket>,<user>,<password> ./tests/unit-tests

Example:

    LCB_TEST_CLUSTER_CONF=localhost,default,Administrator,mypass ./tests/unit-tests

Hacking
-------

Please note that the version from git requires autotools to be
installed. You should consult with your package manager to ensure that
the following packages are installed and updated: autoconf (2.60+),
automake, and libtool. Follow the steps below to checkout the most
recent version from git and build from source on your hardware.

1. Grab the sources using git:

        git clone git://github.com/couchbase/libcouchbase.git

2. Generate `./configure` script using autoconf. Note: this step
   requires that you have cloned this repository from git and that the
   `.git` directory exists. If you have used the tarball from github, it
   will complain on this step, see [config/autorun.sh][2] file for
   details.

        ./config/autorun.sh

3. Generate Makefile. Take a look at possible options to the script:
   `./configure --help`.

        ./configure

4. Make and check the build (you can also use `make check` to only run
   test suite):

        make && make distcheck && make install


Contact us
----------

The developers of libcouchbase usually hang out in the `#libcouchbase`
IRC channel on freenode.net.


Happy hacking!

Cheers,

Trond Norbye

[1]: https://github.com/couchbase/libcouchbase/archive/master.tar.gz
[2]: https://github.com/couchbase/libcouchbase/blob/master/config/autorun.sh
