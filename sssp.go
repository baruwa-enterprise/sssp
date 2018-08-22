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
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout  = 15 * time.Second
	defaultSleep    = 1 * time.Second
	protocolVersion = "SSSP/1.0"
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
	address     string
	connTimeout time.Duration
	connRetries int
	connSleep   time.Duration
	cmdTimeout  time.Duration
	tc          *textproto.Conn
	m           sync.Mutex
}

// SetConnTimeout sets the connection timeout
func (c *Client) SetConnTimeout(t time.Duration) {
	c.connTimeout = t
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	c.cmdTimeout = t
}

// SetConnRetries sets the number of times
// connection is retried
func (c *Client) SetConnRetries(s int) {
	if s < 0 {
		s = 0
	}
	c.connRetries = s
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	c.connSleep = s
}

func (c *Client) dial() (conn net.Conn, err error) {
	d := &net.Dialer{}

	if c.connTimeout > 0 {
		d.Timeout = c.connTimeout
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

// NewClient creates and returns a new instance of Client
func NewClient(address string) (c *Client, err error) {
	var line string
	var conn net.Conn

	c = &Client{
		address:     address,
		connTimeout: defaultTimeout,
		connSleep:   defaultSleep,
	}

	c.m.Lock()
	defer c.m.Unlock()

	if c.tc == nil {
		if conn, err = c.dial(); err != nil {
			return
		}

		c.tc = textproto.NewConn(conn)
	}

	if line, err = c.tc.ReadLine(); err != nil {
		return
	}

	if !strings.HasPrefix(line, "OK") {
		err = fmt.Errorf("Greeting failed: %s", line)
		c.tc.Close()
		return
	}

	if err = c.tc.PrintfLine("%s", protocolVersion); err != nil {
		c.tc.Close()
		return
	}

	if line, err = c.tc.ReadLine(); err != nil {
		c.tc.Close()
		return
	}

	if !strings.HasPrefix(line, "ACC") {
		err = fmt.Errorf("Ack failed: %s", line)
		c.tc.Close()
		return
	}

	return
}
