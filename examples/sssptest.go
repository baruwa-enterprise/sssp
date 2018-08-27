// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main SSSP - Golang cmdline SSSP client
*/
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/baruwa-enterprise/sssp"
	flag "github.com/spf13/pflag"
)

const (
	eicarVirus = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
)

var (
	cfg     *Config
	cmdName string
)

// Config holds the configuration
type Config struct {
	Address string
	Port    int
}

func init() {
	cfg = &Config{}
	cmdName = path.Base(os.Args[0])
	flag.StringVarP(&cfg.Address, "host", "H", "192.168.1.126",
		`Specify Fprot host to connect to.`)
	flag.IntVarP(&cfg.Port, "port", "p", 4020,
		`In TCP/IP mode, connect to Fprot server listening on given port`)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", cmdName)
	fmt.Fprint(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}

func scan(c *sssp.Client, w *sync.WaitGroup, p string) {
	defer func() {
		w.Done()
	}()

	s, err := c.ScanFile(p)
	if err != nil {
		log.Println("ERROR:=>", err)
	}
	fmt.Printf("F=>%s; A=>%s; I=>%t; S=>%s; E=>%t\n", s.Filename, s.ArchiveItem, s.Infected, s.Signature, s.ErrorOccured)
}

func main() {
	fns := []string{
		"/var/spool/testfiles/eicar.tar.bz2",
		"/var/spool/testfiles/1fiOJM-000424-0R.eml",
	}
	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	address := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	c, e := sssp.NewClient("tcp", address, 2*time.Second, 30*time.Second, 0)
	if e != nil {
		log.Println(e)
		return
	}
	defer c.Close()
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go scan(c, &wg, fn)
		wg.Add(1)
		go scan(c, &wg, fn)
	}
	wg.Wait()
	rs, e := c.ScanDir("/var/spool/testfiles", false)
	if e != nil {
		log.Fatalln("ERROR:=>", e)
	}
	for _, r := range rs {
		fmt.Printf("F=>%s; A=>%s; I=>%t; S=>%s; E=>%t\n", r.Filename, r.ArchiveItem, r.Infected, r.Signature, r.ErrorOccured)
	}
	m := []byte(eicarVirus)
	f := bytes.NewReader(m)
	s, e := c.ScanReader(f)
	if e != nil {
		log.Fatalln("ERROR:=>", e)
	}
	fmt.Printf("%v\n", s)
}
