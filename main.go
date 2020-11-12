package main

import (
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/authn"
)

var (
	token      = flag.String("token", "", "Bearer Token for Proxy-Authenticate")
	authUser   = flag.String("auth-user", "", "Basic User for Proxy-Authenticate")
	authPass   = flag.String("auth-pass", "", "Basic Password for Proxy-Authenticate")
	port       = flag.String("port", "18888", "Port to start server")
	bufferSize = flag.Int64("buffer", 32*1024, "Buffer Size")
	enableLog  = flag.Bool("log", false, "Enable log to stderr")
)

func main() {
	flag.Parse()

	if *bufferSize <= 0 {
		log.Fatal("invalid buffer size")
	}

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
				req.Header.Del("Proxy-Authenticate")
				return subtle.ConstantTimeCompare([]byte(reqToken), []byte(*token)) == 1
			},
		})
	}
	if *authUser != "" && *authPass != "" {
		authStr := base64.StdEncoding.EncodeToString([]byte(*authUser + ":" + *authPass))
		srv.Use(authn.Authenticator{
			Type: "Basic",
			Authenticate: func(req *http.Request) bool {
				auth := req.Header.Get("Proxy-Authenticate")
				req.Header.Del("Proxy-Authenticate")

				const prefix = "Basic "
				if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
					return false
				}
				c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
				if err != nil {
					return false
				}

				return subtle.ConstantTimeCompare(c, []byte(authStr)) == 1
			},
		})
	}

	log.Println("httpproxy")
	log.Println("port:", *port)
	log.Println("buffer:", *bufferSize)
	log.Fatal(srv.ListenAndServe())
}

func proxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if *enableLog {
			log.Printf("%s %s", r.Method, r.RequestURI)
		}
		handleTunnel(w, r)
		return
	}

	if *enableLog {
		log.Printf("%s %s", r.Method, r.Host)
	}
	handleHTTP(w, r)
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	upstream, err := net.Dial("tcp", r.RequestURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer upstream.Close()

	client, wr, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	wr.WriteString("HTTP/1.1 200 OK\n\n")
	wr.Flush()

	go copyBuffer(upstream, client)
	copyBuffer(client, upstream)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.RequestURI, "http://") {
		http.NotFound(w, r)
		return
	}

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
	copyBuffer(w, resp.Body)
}

func copyBuffer(dst io.Writer, src io.ReadCloser) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	io.CopyBuffer(dst, src, buf)
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, *bufferSize)
	},
}
