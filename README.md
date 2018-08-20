# sssp

Golang SSSP Client

[![Build Status](https://travis-ci.org/baruwa-enterprise/sssp.svg?branch=master)](https://travis-ci.org/baruwa-enterprise/sssp)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/sssp)](https://goreportcard.com/report/github.com/baruwa-enterprise/sssp)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/sssp?status.svg)](https://godoc.org/github.com/baruwa-enterprise/sssp)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

sssp is a Golang library and cmdline tool that implements the
Sophos SSSP protocol.

## Requirements

* Golang 1.10.x or higher

## Getting started

### SSSP client

The sssp client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/sssp/cmd/ssspscan
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/ssspscan
```

### SSSP library

To install the library

```console
go get get github.com/baruwa-enterprise/sssp
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/sssp"
```

### Testing

``make test``

## License

MPL-2.0
