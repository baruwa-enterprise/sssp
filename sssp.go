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
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout  = 15 * time.Second
	defaultSleep    = 1 * time.Second
	defaultSock     = "/var/lib/savdid/sssp.sock"
	protocolVersion = "SSSP/1.0"
	okResp          = "OK"
	ackResp         = "ACC"
)

var (
	// ZeroTime holds the zero value of time
	ZeroTime time.Time
)

// Response represents the response from the server
type Response struct {
	Filename    string
	ArchiveItem string
	Signature   string
	Status      string
	Infected    bool
	Raw         string
}

// A Client represents an SSSP client.
type Client struct {
	network     string
	address     string
	connTimeout time.Duration
	connRetries int
	connSleep   time.Duration
	cmdTimeout  time.Duration
	tc          *textproto.Conn
	m           sync.Mutex
	conn        net.Conn
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	c.cmdTimeout = t
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	c.connSleep = s
}

// Scan a file or directory
func (c *Client) Scan(p string) (r *Response, err error) {
	r, err = c.fileCmd(p)
	return
}

// ScanReader scans an io.reader
func (c *Client) ScanReader(i io.Reader) (r *Response, err error) {
	return
}

func (c *Client) dial() (conn net.Conn, err error) {
	d := &net.Dialer{
		Timeout: c.connTimeout,
	}

	for i := 0; i <= c.connRetries; i++ {
		conn, err = d.Dial("unix", c.address)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			time.Sleep(c.connSleep)
			continue
		}
		break
	}
	return
}

func (c *Client) basicCmd() (s string, err error) {
	return
}

func (c *Client) fileCmd(p string) (r *Response, err error) {
	return
}

func (c *Client) readerCmd(i io.Reader) (r *Response, err error) {
	return
}

// NewClient creates and returns a new instance of Client
func NewClient(network, address string, connTimeOut, ioTimeOut time.Duration, connRetries int) (c *Client, err error) {
	var line string

	if network == "" && address == "" {
		network = "unix"
		address = defaultSock
	}

	if network != "unix" && network != "unixpacket" && network != "tcp" && network != "tcp4" && network != "tcp6" {
		err = fmt.Errorf("Protocol: %s is not supported", network)
		return
	}

	if network == "unix" || network == "unixpacket" {
		if _, err = os.Stat(address); os.IsNotExist(err) {
			err = fmt.Errorf("The unix socket: %s does not exist", address)
			return
		}
	}

	c = &Client{
		network:     network,
		address:     address,
		connTimeout: connTimeOut,
		connSleep:   defaultSleep,
		cmdTimeout:  ioTimeOut,
		connRetries: connRetries,
	}

	c.m.Lock()
	defer c.m.Unlock()

	if c.conn, err = c.dial(); err != nil {
		return
	}

	defer c.conn.SetDeadline(ZeroTime)

	c.tc = textproto.NewConn(c.conn)

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if line, err = c.tc.ReadLine(); err != nil {
		return
	}

	if !strings.HasPrefix(line, okResp) {
		err = fmt.Errorf("Greeting failed: %s", line)
		c.tc.Close()
		return
	}

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if err = c.tc.PrintfLine("%s", protocolVersion); err != nil {
		c.tc.Close()
		return
	}

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if line, err = c.tc.ReadLine(); err != nil {
		c.tc.Close()
		return
	}

	if !strings.HasPrefix(line, ackResp) {
		err = fmt.Errorf("Ack failed: %s", line)
		c.tc.Close()
		return
	}

	return
}
