# cbc-pillowfight(1) - Stress Test for Couchbase Client and Cluster

## SYNOPSIS

`cbc-pillowfight` [_OPTIONS_]

## DESCRIPTION

`cbc-pillowfight` creates a specified number of threads each looping and
performing get and set operations within the cluster.


The command will loop a certain number of _cycles_, in each cycle it will
schedule a certain number of _batched_ operations (which can be a single
operation). The operations will be either storage or retrieval operations,
controlled by a given _ratio_.

The number of total items operated upon as well as the sizes of these options
may also be configured.


## OPTIONS

Options may be read either from the command line, or from a configuration file
(see cbcrc(4)):

The following options control workload generation:

* `-B`, `--iterations`=_BATCHSIZE_:
  This controls how many commands are scheduled per cycles. To simulate one operation
  at a time, set this value to 1.

* `-I`, `--num-items`=_NUMITEMS_:
  Set the _total_ number of items the workload will access within the cluster. This
  will also determine the working set size at the server and may affect disk latencies
  if set to a high number.

* `-p`, `--key-prefix`=_PREFIX_:
  Set the prefix to prepend to all keys in the cluster. Useful if you do not wish the items
  to conflict with existing data.

* `-t`, `--num-threads`=_NTHREADS_:
  Set the number of threads (and thus the number of client instances) to run
  concurrently. Each thread is assigned its own client object.

* `-r`, `--ratio`=_SETRATIO_:
  Set the ratio of gets to sets. This controls how many get operations should
  be performed before a set operation is performed.

* `-n`, `--no-population`:
  By default `cbc-pillowfight` will load all the items (see `--num-items`) into
  the cluster and then begin performing the normal workload. Specifying this
  option bypasses this stage. Useful if the items have already been loaded in a
  previous run.

* `-m`, `--min-size`=_MINSIZE_:
* `-M`, `--max-size`=_MAXSIZE_:
  Specify the minimum and maximum value sizes to be stored into the cluster.
  This is typically a range, in which case each value generated will be between
  `--min-size` and `--max-size` bytes.

* `-E`, `--pause-at-end`:
  When the workload completes, do not exit immediately, but wait for user input.
  This is helpful for analyzing open socket connections and state.

* `-c`, `--num-cycles`:
  Specify the number of times the workload should cycle. During each cycle
  an amount of `--batch-size` operations are executed. Setting this to `-1`
  will cause the workload to run infinitely.

* `-T`, `--timings`:
  Dump a histogram of command timings and latencies to the screen every second.


The following options control how `cbc-pillowfight` connects to the cluster

* `--dsn`=_SPEC_:
  A string describing the cluster to connect to. The string is in a URI-like syntax,
  and may also contain other options. See the [EXAMPLES](#examples) section for information.
  Typically such a URI will look like `couchbase://host1,host2,host3/bucket`.

  The default for this option is `couchbase://localhost/default`

* `-u`, `--username`=_USERNAME_:
  Specify the _username_ for the bucket. As of Couchbase Server 2.5 this field
  should be either left empty or set to the name of the bucket itself.

* `-P`, `--password`=_SASLPASS_:
  Specify the SASL password for the bucket. This is only needed if the bucket is
  protected with a password. Note that this is _not_ the administrative password
  used to log into the web interface.

* `-C`, `--bootstrap-protocol`=_CCCP|HTTP|BOTH_:
  Specify the bootstrap protocol the client should used when attempting to connect
  to the cluster. Options are: `CCCP`: Bootstrap using the Memcached protocol
  (supported on clusters 2.5 and greater); `HTTP`: Bootstrap using the HTTP REST
  protocol (supported on any cluster version); and `BOTH`: First attempt bootstrap
  over the Memcached protocol, and use the HTTP protocol if Memcached bootstrap fails.
  The default is `BOTH`

* `-t`, `--timeout`=_USECS_:
  Specify the operation timeout in microseconds. This is the time the client will
  wait for an operation to complete before timing it out. The default is
  `2500000`

* `-T`, `--timings`:
  Dump command timings at the end of execution. This will display a histogram
  showing the latencies for the commands executed.

* `-S` `--force-sasl-mech`=_MECH_:
  Force a specific _SASL_ mechanism to be used when performing the initial
  connection. This should only need to be modified for debugging purposes.
  The currently supported mechanisms are `PLAIN` and `CRAM-MD5`

* `-Z`, `--config-cache`:
  Enables the client to make use of a file based configuration cache rather
  than connecting for the bootstrap operation. If the file does not exist, the
  client will first connect to the cluster and then cache the bootstrap information
  in the file.


* `--ssl`=*ON|OFF|NO_VERIFY*:
  Use SSL for connecting to the cluster. The options are `ON` to enable full SSL
  support, `OFF` to disable SSL support, and `NO_VERIFY` to use SSL encryption
  but not attempt to verify the authenticity of the server's certificate.

* `--capath`=_CERTIFICATE_:
  The path to the CA certificate with which the server's certificate was signed. May
  be necessary if the certificate is not recognized by the default OpenSSL
  installation.

* `-v`, `--verbose`:
  Specify more information to standard error about what the client is doing. You may
  specify this option multiple times for increased output detail.


## TODO

Rather than spawning threads for multiple instances, offer a way to have multiple
instances function cooperatively inside an event loop.

## BUGS

This command's options are subject to change.

## SEE ALSO

cbc(1), cbcrc(4)

## HISTORY

The `cbc-pillowfight` tool was first introduced in libcouchbase 2.0.7
