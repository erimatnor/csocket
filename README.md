csocket
=======

A small C-library that provides a network socket API with a
higher-level of abstraction than the plain BSD sockets API. The goal
is to support IPv4, IPv6 and TLS/SSL sockets using one simple API.

Requirements
------------

* autotools (autoconf, automake)
* libtool
* openssl (optional)

Installation
------------

```
autoreconf --install
./configure
make
make install
```

Contact
-------

Erik Nordström <erik.nordstrom@gmail.com>
