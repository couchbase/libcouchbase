# cbcrc(4) - Configuration file for Couchbase command line tools

# DESCRIPTION

cbcrc is an ASCII file that allows you to specify default
configuration values for cbc.

Each entry in the cbcrc file is a line with a key-value pair in the
following form:

    # optional comments
    key=value

The keys may be specified in random order, and if you specify the same
key multiple times the last value "wins". The following keys exists:

* `connstr`:
  This is the URI-like string used to connect to the cluster. Its format
  consists of a _scheme_ followed by a list of hosts, an optional
  bucket for the path and an optional `?` followed by key-value options.

  Using SSL without verification:

    couchbases://foo.com,bar.com,baz.com/mybucket?ssl=no_verify

  Using custom REST API ports (without SSL)

    http://localhost:9000,localhost:9001,localhost:9002

  Using custom memcached ports:

    couchbase://localhost:9100,localhost:9200,localhost:9300


* `user`:
    This is the username used during authentication to your cluster.

* `password`:
    This is the password used during authentication to your bucket

* `timeout`:
    The timeout value to use for the operations.
