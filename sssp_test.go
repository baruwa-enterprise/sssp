// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package sssp implements the SSSP protocol
SSSP - Golang SSSP protocol implementation
*/
package sssp

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"go/build"
	"net"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

const (
	localSock  = "/Users/andrew/sssp.sock"
	eicarVirus = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
)

type CommandTestKey struct {
	in  Command
	out string
}

var TestCommands = []CommandTestKey{
	{ScanFile, "SCANFILE"},
	{ScanDir, "SCANDIR"},
	{ScanDirr, "SCANDIRR"},
	{ScanData, "SCANDATA"},
	{Quit, "BYE"},
	{Command(100), ""},
}

func TestCommand(t *testing.T) {
	for _, tt := range TestCommands {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
	}
}

func TestBasics(t *testing.T) {
	var expected, testSock string
	// Test Non existent socket
	testSock = "/tmp/.dumx.sock"
	_, e := NewClient("unix", "/tmp/.dumx.sock", 1*time.Second, 30*time.Second, 0)
	if e == nil {
		t.Fatalf("An error should be returned as sock does not exist")
	}
	expected = fmt.Sprintf(unixSockErr, testSock)
	if e.Error() != expected {
		t.Errorf("Expected %q want %q", expected, e)
	}
	// Test defaults
	_, e = NewClient("", "", 1*time.Second, 30*time.Second, 0)
	if e == nil {
		t.Fatalf("An error should be returned as sock does not exist")
	}
	expected = fmt.Sprintf(unixSockErr, defaultSock)
	if e.Error() != expected {
		t.Errorf("Got %q want %q", expected, e)
	}
	// Test udp
	_, e = NewClient("udp", "127.1.1.1:4020", 1*time.Second, 30*time.Second, 0)
	if e == nil {
		t.Fatalf("Expected an error got nil")
	}
	expected = fmt.Sprintf(unsupportedProtoErr, "udp")
	if e.Error() != expected {
		t.Errorf("Got %q want %q", expected, e)
	}
	// Test tcp
	network := "tcp"
	address := "127.1.1.1:4020"
	c, e := NewClient(network, address, 1*time.Second, 30*time.Second, 0)
	if e == nil {
		t.Fatalf("An error should be returned")
	}
	if c.network != network {
		t.Errorf("Got %q want %q", c.network, network)
	}
	if c.address != address {
		t.Errorf("Got %q want %q", c.address, address)
	}
}

func TestSettings(t *testing.T) {
	var e error
	var c *Client
	network := "tcp"
	address := "127.1.1.1:4020"
	if c, e = NewClient(network, address, 1*time.Second, 30*time.Second, 0); e == nil {
		t.Fatalf("An error should be returned")
	}
	if _, ok := e.(*net.OpError); !ok {
		t.Errorf("Expected *net.OpError want %q", e)
	}
	if c.connTimeout != 1*time.Second {
		t.Errorf("The default conn timeout should be set")
	}
	if c.connSleep != defaultSleep {
		t.Errorf("The default conn sleep should be set")
	}
	if c.connRetries != 0 {
		t.Errorf("The default conn retries should be set")
	}
	expected := 2 * time.Second
	c.SetCmdTimeout(expected)
	if c.cmdTimeout != expected {
		t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
	}
	c.SetConnSleep(expected)
	if c.connSleep != expected {
		t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
	}
}

func TestTCPScanFile(t *testing.T) {
	var e error
	var c *Client
	var s *Response
	var fn, an, exp string

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		fn = "/var/spool/testfiles/eicar.tar.bz2"
		an = "/var/spool/testfiles/eicar.tar.bz2/Bzip2/var/spool/testfiles/eicar.txt"
		s, e = c.ScanFile(fn)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != fn {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.Filename, fn)
		}
		if s.ArchiveItem != an {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.ArchiveItem, an)
		}
		if !s.Infected {
			t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
		fn = "/var/spool/testfiles/1fiOJM-000424-0R.eml"
		s, e = c.ScanFile(fn)
		if e == nil {
			t.Fatalf("An error should be returned: %v", s)
		}
		exp = "0210 Could not open item passed to SAVI for scanning"
		if e.Error() != exp {
			t.Errorf("e.Error() = %s, want %s", e, exp)
		}
		fn = "/var/spool/testfiles/install.log"
		s, e = c.ScanFile(fn)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != fn {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.Filename, fn)
		}
		if s.ArchiveItem != "" {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.ArchiveItem, "")
		}
		if s.Infected {
			t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn, s.Infected, false)
		}
		if s.Signature != "" {
			t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn, s.Signature, "")
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}

func TestTCPScanDir(t *testing.T) {
	var e error
	var c *Client
	var s []*Response
	var fn1, fn2, fn3, an string
	var fd1, fd2, fd3 bool

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		fn1 = "/var/spool/testfiles/eicar.tar.bz2"
		fn2 = "/var/spool/testfiles/1fiOJM-000424-0R.eml"
		fn3 = "/var/spool/testfiles/install.log"
		an = "/var/spool/testfiles/eicar.tar.bz2/Bzip2/var/spool/testfiles/eicar.txt"
		s, e = c.ScanDir("/var/spool/testfiles", false)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		for _, rs := range s {
			if rs.Filename == fn1 {
				fd1 = true
				if rs.ArchiveItem != an {
					t.Errorf("c.ScanFile(%q) = %q, want %q", fn1, rs.ArchiveItem, an)
				}
				if !rs.Infected {
					t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn1, rs.Infected, true)
				}
				if rs.Signature != "EICAR-AV-Test" {
					t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn1, rs.Signature, "EICAR-AV-Test")
				}
			} else if rs.Filename == fn2 {
				fd2 = true
				if !rs.ErrorOccured {
					t.Errorf("rs.ErrorOccured = %t, want %t", rs.ErrorOccured, true)
				}
			} else if rs.Filename == fn3 {
				fd3 = true
			}
		}
		if !fd1 {
			t.Errorf("fd1 = %t, want %t", fd1, true)
		}
		if !fd2 {
			t.Errorf("fd2 = %t, want %t", fd2, true)
		}
		if fd3 {
			t.Errorf("fd3 = %t, want %t", fd3, false)
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}

func TestTCPScanDirr(t *testing.T) {
	var e error
	var c *Client
	var s []*Response
	var fn1, fn2, fn3, an string
	var fd1, fd2, fd3 bool

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		fn1 = "/var/spool/testfiles/eicar.tar.bz2"
		fn2 = "/var/spool/testfiles/1fiOJM-000424-0R.eml"
		fn3 = "/var/spool/testfiles/install.log"
		an = "/var/spool/testfiles/eicar.tar.bz2/Bzip2/var/spool/testfiles/eicar.txt"
		s, e = c.ScanDir("/var/spool/testfiles", true)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		for _, rs := range s {
			if rs.Filename == fn1 {
				fd1 = true
				if rs.ArchiveItem != an {
					t.Errorf("c.ScanFile(%q) = %q, want %q", fn1, rs.ArchiveItem, an)
				}
				if !rs.Infected {
					t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn1, rs.Infected, true)
				}
				if rs.Signature != "EICAR-AV-Test" {
					t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn1, rs.Signature, "EICAR-AV-Test")
				}
			} else if rs.Filename == fn2 {
				fd2 = true
				if !rs.ErrorOccured {
					t.Errorf("rs.ErrorOccured = %t, want %t", rs.ErrorOccured, true)
				}
			} else if rs.Filename == fn3 {
				fd3 = true
			}
		}
		if !fd1 {
			t.Errorf("fd1 = %t, want %t", fd1, true)
		}
		if !fd2 {
			t.Errorf("fd2 = %t, want %t", fd2, true)
		}
		if fd3 {
			t.Errorf("fd3 = %t, want %t", fd3, false)
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}

func TestTCPScanStream(t *testing.T) {
	var e error
	var c *Client
	var s *Response
	var fn, an string

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		fn = path.Join(gopath, "src/github.com/baruwa-enterprise/sssp/examples/data/eicar.tar.bz2")
		an = "/Bzip2/eicar.txt"
		s, e = c.ScanStream(fn)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != "stream" {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.Filename, "stream")
		}
		if s.ArchiveItem != an {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.ArchiveItem, an)
		}
		if !s.Infected {
			t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
		fn = path.Join(gopath, "src/github.com/baruwa-enterprise/sssp/examples/data")
		s, e = c.ScanStream(fn)
		if e == nil {
			t.Fatalf("An error should be returned")
		}
		if e.Error() != dirScanErr {
			t.Errorf("Error returned: %s, want %s", e.Error(), dirScanErr)
		}
		fn = path.Join(gopath, "src/github.com/baruwa-enterprise/sssp/examples/data/xxxx.pdf")
		s, e = c.ScanStream(fn)
		if e == nil {
			t.Fatalf("An error should be returned")
		}
		if !os.IsNotExist(e) {
			t.Errorf("Expected a os.IsNotExist error got %v", e)
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}

func TestTCPScanReaderFile(t *testing.T) {
	var e error
	var c *Client
	var f *os.File
	var s *Response
	var fn, an string

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		fn = path.Join(gopath, "src/github.com/baruwa-enterprise/sssp/examples/data/eicar.tar.bz2")
		an = "/Bzip2/eicar.txt"
		if f, e = os.Open(fn); e != nil {
			t.Fatalf("Failed to open file: %s", fn)
		}
		defer f.Close()
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != "stream" {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.Filename, "stream")
		}
		if s.ArchiveItem != an {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.ArchiveItem, an)
		}
		if !s.Infected {
			t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
		s, e = c.ScanReader(bzip2.NewReader(f))
		if e == nil {
			t.Fatalf("An error should be returned")
		}
		if e.Error() != noSizeErr {
			t.Errorf("Error returned: %s, want %s", e.Error(), noSizeErr)
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}

func TestTCPScanReaderBytes(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		fn := "stream"
		m := []byte(eicarVirus)
		f := bytes.NewReader(m)
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != "stream" {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.Filename, "stream")
		}
		if !s.Infected {
			t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}

func TestTCPScanReaderBuffer(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		fn := "stream"
		f := bytes.NewBufferString(eicarVirus)
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != "stream" {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.Filename, "stream")
		}
		if !s.Infected {
			t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}

func TestTCPScanReaderString(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	skip := false
	address := os.Getenv("SSSP_TCP_ADDRESS")
	if address == "" {
		address = localSock
		if _, e = os.Stat(address); os.IsNotExist(e) {
			skip = true
		}
	}

	if !skip {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4020", 2*time.Second, 30*time.Second, 1)
		} else {
			c, e = NewClient("tcp", address, 2*time.Second, 30*time.Second, 1)
		}
		if e != nil {
			t.Fatalf("An error should not be returned:%s", e)
		}
		defer c.Close()
		fn := "stream"
		f := strings.NewReader(eicarVirus)
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != "stream" {
			t.Errorf("c.ScanFile(%q) = %q, want %q", fn, s.Filename, "stream")
		}
		if !s.Infected {
			t.Errorf("c.ScanFile(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.ScanFile(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
	} else {
		t.Skip("skipping test; $SSSP_TCP_ADDRESS not set")
	}
}
