package main

import (
	"crypto/subtle"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/authn"
)

var (
	token     = flag.String("token", "", "Bearer Token for Proxy-Authenticate")
	port      = flag.String("port", "18888", "Port to start server")
	enableLog = flag.Bool("log", false, "Enable log to stderr")
)

func main() {
	flag.Parse()

	if envPort := os.Getenv("PORT"); envPort != "" {
		*port = envPort
	}

	srv := parapet.New()
	srv.Addr = ":" + *port
	srv.Handler = http.HandlerFunc(proxy)

	if *token != "" {
		srv.Use(authn.Authenticator{
			Type: "Bearer",
			Authenticate: func(req *http.Request) bool {
				reqToken := req.Header.Get("Proxy-Authenticate")
				return subtle.ConstantTimeCompare([]byte(reqToken), []byte(*token)) == 1
			},
		})
	}
	log.Println("start httpproxy at 0.0.0.0:" + *port)
	log.Fatal(srv.ListenAndServe())
}

func proxy(w http.ResponseWriter, r *http.Request) {
	if *enableLog {
		log.Printf("%s %s", r.Method, r.RequestURI)
	}

	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
		return
	}

	handleHTTP(w, r)
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Proxy not support hijacker", http.StatusInternalServerError)
		return
	}

	// dial to upstream
	upstream, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer upstream.Close()

	w.WriteHeader(http.StatusOK)

	client, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	go io.Copy(upstream, client)
	io.Copy(client, upstream)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
