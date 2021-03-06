# sssp

Golang SSSP Client

[![Ci](https://github.com/baruwa-enterprise/sssp/workflows/Ci/badge.svg)](https://github.com/baruwa-enterprise/sssp/actions?query=workflow%3ACi)
[![codecov](https://codecov.io/gh/baruwa-enterprise/sssp/branch/master/graph/badge.svg)](https://codecov.io/gh/baruwa-enterprise/sssp)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/sssp)](https://goreportcard.com/report/github.com/baruwa-enterprise/sssp)
[![Go Reference](https://pkg.go.dev/badge/github.com/baruwa-enterprise/sssp.svg)](https://pkg.go.dev/github.com/baruwa-enterprise/sssp)
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
go get github.com/baruwa-enterprise/sssp
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/sssp"
```

### Testing

``make test``

## License

MPL-2.0
