// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package sssp implements the SSSP protocol
SSSP - Golang SSSP protocol implementation
*/
package sssp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout      = 15 * time.Second
	defaultSleep        = 1 * time.Second
	defaultCmdTimeout   = 1 * time.Minute
	defaultSock         = "/var/lib/savdid/sssp.sock"
	protocolVersion     = "SSSP/1.0"
	okResp              = "OK"
	ackResp             = "ACC"
	failResp            = "FAIL"
	doneResp            = "DONE"
	doneOk              = "DONE OK"
	doneFail            = "DONE FAIL"
	virusResp           = "VIRUS"
	unixSockErr         = "The unix socket: %s does not exist"
	unsupportedProtoErr = "Protocol: %s is not supported"
	noSizeErr           = "The content length could not be determined"
	dirScanErr          = "Scanning directories is not supported"
	invalidRespErr      = "Invalid server response: %s"
	virusMatchErr       = "Virus match failure: %s"
	greetingErr         = "Greeting failed: %s"
	ackErr              = "Ack failed: %s"
)

const (
	// ScanFile represents the SCANFILE command
	ScanFile Command = iota + 1
	// ScanDir represents the SCANDIR command
	ScanDir
	// ScanDirr represents the SCANDIRR command
	ScanDirr
	// ScanData represents the SCANDATA command
	ScanData
	// Quit reprsents the BYE command
	Quit
)

var (
	// ZeroTime holds the zero value of time
	ZeroTime   time.Time
	responseRe = regexp.MustCompile(`^VIRUS\s(?P<signature>\S+)\s(?P<filename>\S+)?$`)
)

type readerWithLen interface {
	Len() int
}

// A Command represents a SSSP Command
type Command int

func (c Command) String() (s string) {
	n := [...]string{
		"",
		"SCANFILE",
		"SCANDIR",
		"SCANDIRR",
		"SCANDATA",
		"BYE",
	}
	if c < ScanFile || c > Quit {
		s = ""
		return
	}
	s = n[c]
	return
}

// Response represents the response from the server
type Response struct {
	Filename     string
	ArchiveItem  string
	Signature    string
	Status       string
	Infected     bool
	ErrorOccured bool
	Raw          string
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
	if t > 0 {
		c.cmdTimeout = t
	}
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	if s > 0 {
		c.connSleep = s
	}
}

// Close closes the connection to the server gracefully
// and frees up resources used by the connection
func (c *Client) Close() (err error) {
	_, err = c.basicCmd(Quit)
	if err != nil {
		c.tc.Close()
	} else {
		err = c.tc.Close()
	}

	return
}

// ScanFile submits a single file for scanning
func (c *Client) ScanFile(p string) (r *Response, err error) {
	r, err = c.fileCmd(p)
	return
}

// ScanDir submits a directory for scanning
func (c *Client) ScanDir(p string, recurse bool) (r []*Response, err error) {
	r, err = c.dirCmd(p, recurse)
	return
}

// ScanStream submits a single file via a stream for scanning
func (c *Client) ScanStream(p string) (r *Response, err error) {
	var f *os.File
	var stat os.FileInfo

	if stat, err = os.Stat(p); os.IsNotExist(err) {
		return
	}

	if stat.IsDir() {
		err = fmt.Errorf(dirScanErr)
		return
	}

	if f, err = os.Open(p); err != nil {
		return
	}
	defer f.Close()

	r, err = c.readerCmd(f)

	return
}

// ScanReader submits an io reader via a stream for scanning
func (c *Client) ScanReader(i io.Reader) (r *Response, err error) {
	r, err = c.readerCmd(i)

	return
}

func (c *Client) dial(ctx context.Context) (conn net.Conn, err error) {
	d := &net.Dialer{
		Timeout: c.connTimeout,
	}

	for i := 0; i <= c.connRetries; i++ {
		conn, err = d.DialContext(ctx, c.network, c.address)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			time.Sleep(c.connSleep)
			continue
		}
		break
	}

	return
}

func (c *Client) basicCmd(cmd Command) (s string, err error) {
	var id uint

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if id, err = c.tc.Cmd("%s", cmd); err != nil {
		return
	}

	defer c.conn.SetDeadline(ZeroTime)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	s, err = c.tc.ReadLine()

	return
}

func (c *Client) fileCmd(p string) (r *Response, err error) {
	var id uint

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if id, err = c.tc.Cmd("%s %s", ScanFile, p); err != nil {
		return
	}

	defer c.conn.SetDeadline(ZeroTime)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	r, err = c.processResponse(p)

	return
}

func (c *Client) readerCmd(i io.Reader) (r *Response, err error) {
	var id uint
	var clen int64
	var stat os.FileInfo

	defer c.conn.SetDeadline(ZeroTime)

	switch v := i.(type) {
	case readerWithLen:
		clen = int64(v.Len())
	case *os.File:
		stat, err = v.Stat()
		if err != nil {
			return
		}
		clen = stat.Size()
	default:
		err = fmt.Errorf(noSizeErr)
		return
	}

	id = c.tc.Next()
	c.tc.StartRequest(id)

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if err = c.tc.PrintfLine("%s %d", ScanData, clen); err != nil {
		c.tc.EndRequest(id)
		return
	}

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if _, err = io.Copy(c.tc.Writer.W, i); err != nil {
		c.tc.EndRequest(id)
		return
	}
	if err = c.tc.W.Flush(); err != nil {
		c.tc.EndRequest(id)
		return
	}

	c.tc.EndRequest(id)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	r, err = c.processResponse("stream")

	return
}

func (c *Client) dirCmd(p string, rc bool) (r []*Response, err error) {
	var id uint

	cmd := ScanDir
	if rc {
		cmd = ScanDirr
	}

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if id, err = c.tc.Cmd("%s %s", cmd, p); err != nil {
		return
	}

	defer c.conn.SetDeadline(ZeroTime)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	r, err = c.processResponses()

	return
}

func (c *Client) processResponse(p string) (r *Response, err error) {
	var ierr error
	var line string

	r = &Response{
		Filename: p,
	}

	for {
		c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
		if line, err = c.tc.ReadLine(); err != nil {
			return
		}

		if strings.HasPrefix(line, ackResp) {
			continue
		}

		if strings.HasPrefix(line, doneResp) {
			if strings.HasPrefix(line, doneFail) {
				ierr = fmt.Errorf("%s", strings.TrimLeft(strings.TrimLeft(line, doneFail), " "))
			}
		}

		if line == "" {
			break
		}

		if r.Signature != "" {
			continue
		}

		if m := responseRe.FindStringSubmatch(line); m != nil {
			if r.Filename != m[2] {
				r.ArchiveItem = m[2]
			}
			r.Infected = true
			r.Signature = m[1]
			r.Raw = line
			continue
		}

		if strings.HasPrefix(line, virusResp) {
			ierr = fmt.Errorf(virusMatchErr, line)
			continue
		}
	}

	if err == nil && ierr != nil {
		err = ierr
	}

	return
}

func (c *Client) processResponses() (r []*Response, err error) {
	var ierr error
	var line string

	for {
		c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
		if line, err = c.tc.ReadLine(); err != nil {
			return
		}

		if strings.HasPrefix(line, ackResp) {
			continue
		}

		if strings.HasPrefix(line, doneResp) {
			if strings.HasPrefix(line, doneFail) {
				ierr = fmt.Errorf("%s", strings.TrimLeft(strings.TrimLeft(line, doneFail), " "))
			}
		}

		if line == "" {
			break
		}

		if strings.HasPrefix(line, failResp) {
			rs := &Response{}
			rs.ErrorOccured = true
			rs.Raw = line
			pts := strings.Split(line, " ")
			if len(pts) != 3 {
				ierr = fmt.Errorf(invalidRespErr, line)
			} else {
				rs.Filename = pts[2]
			}

			r = append(r, rs)
			continue
		}

		if m := responseRe.FindStringSubmatch(line); m != nil {
			rs := &Response{}
			rs.Infected = true
			rs.Signature = m[1]
			rs.Raw = line
			rs.ArchiveItem = m[2]
			for {
				c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
				if line, err = c.tc.ReadLine(); err != nil {
					return
				}
				if strings.HasPrefix(line, virusResp) {
					continue
				}
				if strings.HasPrefix(line, okResp) {
					pts := strings.Split(line, " ")
					if len(pts) != 3 {
						ierr = fmt.Errorf(invalidRespErr, line)
					} else {
						rs.Filename = pts[2]
						if rs.ArchiveItem == rs.Filename {
							rs.ArchiveItem = ""
						}
					}
					break
				}
			}

			r = append(r, rs)
		}

		if strings.HasPrefix(line, virusResp) {
			ierr = fmt.Errorf(virusMatchErr, line)
			continue
		}

	}

	if err == nil && ierr != nil {
		err = ierr
	}

	return
}

func (c *Client) greeting() (err error) {
	var line string

	defer c.conn.SetDeadline(ZeroTime)

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if line, err = c.tc.ReadLine(); err != nil {
		return
	}

	if !strings.HasPrefix(line, okResp) {
		err = fmt.Errorf(greetingErr, line)
		return
	}

	return
}

func (c *Client) proto() (err error) {
	var line string

	defer c.conn.SetDeadline(ZeroTime)

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if err = c.tc.PrintfLine("%s", protocolVersion); err != nil {
		return
	}

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if line, err = c.tc.ReadLine(); err != nil {
		return
	}

	if !strings.HasPrefix(line, ackResp) {
		err = fmt.Errorf(ackErr, line)
		return
	}

	return
}

// Dial setup clients network connection
// This is called automatically when you call NewClient
// It is provided to allow for reconnection if the underlying
// connection is dropped due to inactivity.
func (c *Client) Dial(ctx context.Context) (err error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.conn, err = c.dial(ctx); err != nil {
		return
	}

	defer c.conn.SetDeadline(ZeroTime)

	c.tc = textproto.NewConn(c.conn)

	if err = c.greeting(); err != nil {
		c.tc.Close()
		return
	}

	if err = c.proto(); err != nil {
		c.tc.Close()
		return
	}

	return
}

// NewClient creates and returns a new instance of Client
func NewClient(ctx context.Context, network, address string, connTimeOut, ioTimeOut time.Duration, connRetries int) (c *Client, err error) {
	if network == "" && address == "" {
		network = "unix"
		address = defaultSock
	}

	if network != "unix" && network != "unixpacket" && network != "tcp" && network != "tcp4" && network != "tcp6" {
		err = fmt.Errorf(unsupportedProtoErr, network)
		return
	}

	if network == "unix" || network == "unixpacket" {
		if _, err = os.Stat(address); os.IsNotExist(err) {
			err = fmt.Errorf(unixSockErr, address)
			return
		}
	}

	if connTimeOut == 0 {
		connTimeOut = defaultTimeout
	}

	if ioTimeOut == 0 {
		ioTimeOut = defaultCmdTimeout
	}

	c = &Client{
		network:     network,
		address:     address,
		connTimeout: connTimeOut,
		connSleep:   defaultSleep,
		cmdTimeout:  ioTimeOut,
		connRetries: connRetries,
	}

	err = c.Dial(ctx)

	return
}
