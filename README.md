# `zq` [![Tests][tests-img]][tests]

The `zq` repository contains tools and components used to search, analyze,
and store structured log data, including:

* The [zq](cmd/zq/README.md) command line tool, for searching and analyzing log
 files
* The [zqd](ppl/cmd/zqd/README.md) daemon, which serves a REST API to manage
 and query log archives, and is the backend for the [Brim](https://github.com/brimsec/brim)
 application
* The [zar](ppl/cmd/zar/README.md) command line tool, for working with log data
 archives
* The [zapi](cmd/zapi/README.md) command line tool, for interacting with the
API provided by zqd
* The [ZQL](zql/docs/README.md) query language definition and implementation
* The [ZNG](zng/docs/README.md) structured log specification and supporting components

## Installation

To install `zq` or any other tool from this repo, you can either clone the repo
 and compile from source, or use a pre-compiled
 [release](https://github.com/brimsec/zq/releases), available for Windows, macOS, and Linux.

If you don't have Go installed, download and install it from the
[Go downloads page](https://golang.org/dl/). Go version 1.15 or later is
required.

To install the binaries in `$GOPATH/bin`, clone this repo and
execute `make install`:

```
git clone https://github.com/brimsec/zq
cd zq
make install
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) on how you can help improve `zq`!

## Join the Community

Join our [Public Slack](https://www.brimsecurity.com/join-slack/) workspace for announcements, Q&A, and to trade tips!

[tests-img]: https://github.com/brimsec/zq/workflows/Tests/badge.svg
[tests]: https://github.com/brimsec/zq/actions?query=workflow%3ATests

