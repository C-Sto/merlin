package testserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Ne0nd0g/merlin/pkg/messages"
)

func (ts *TestServer) handler(w http.ResponseWriter, r *http.Request) {
	bod := ""

	var payload json.RawMessage
	j := messages.Base{
		Payload: &payload,
	}
	json.NewDecoder(r.Body).Decode(&j)

	switch r.UserAgent() {
	case "BrokenJSON":
		w.Header().Set("Content-Type", "application/json")
		bod = "{this is hella broken"
	}

	//fmt.Println(fmt.Sprintf("Request: %+v\nBody:%+v", r, j)) //uncomment here if you want to print out exactly what the test server receives
	respCode := http.StatusOK
	//perform logic here to determine if the agent is behaving as expected
	w.WriteHeader(respCode)
	fmt.Fprintln(w, bod)
}

//TestServer is a webserver instance that facilitates functional testing of code that requires the ability to send web requests
type TestServer struct {
	tes *testing.T
}

//since tls/pki is such a pain in the ass, and I'm morally against storing certs on the repo - let's generate them every time :)
func generateTLSConfig() *tls.Config {
	//https://golang.org/src/crypto/tls/generate_cert.go taken from here mostly
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	tpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "127.0.0.1",
			Organization: []string{"Joey is the best hacker in Hackers"},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"127.0.0.1", "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24), //like 24 hours? idk, it's irrelevant anyway
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	crtBytes, e := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if e != nil {
		panic(e)
	}

	crt := tls.Certificate{
		Certificate: [][]byte{crtBytes},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{crt},
		NextProtos:   []string{"h2", "hq"},
	}
}

//Start starts the test HTTP server
func (TestServer) Start(port string, finishedTest, setup chan struct{}, t *testing.T) {

	s := http.NewServeMux()
	ts := TestServer{
		tes: t,
	}
	s.HandleFunc("/", ts.handler)
	srv := http.Server{}

	srv.TLSConfig = generateTLSConfig()
	srv.Handler = s
	srv.Addr = "127.0.0.1:" + port
	go func() {
		ln, e := net.Listen("tcp", srv.Addr)
		defer ln.Close()
		if e != nil {
			panic(e)
		}
		tlsListener := tls.NewListener(ln, srv.TLSConfig)
		e = srv.Serve(tlsListener)
		//e := srv.ListenAndServeTLS("", "")
		if e != nil { //should be set by the tls config
			panic(e)
		}
	}()
	for {
		time.Sleep(time.Second * 1)
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Get("https://localhost:" + port)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		// Reached this point: server is up and running!
		break
	}

	close(setup)
	<-finishedTest //this is an ultra gross hack :(
}
