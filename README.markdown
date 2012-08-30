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

Contact us
----------

The developers of libcouchbase usually hangs out in the #libcouchbase
IRC channel on freenode.net.


Happy hacking!

Cheers,

Trond Norbye
