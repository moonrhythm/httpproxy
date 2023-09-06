package main

import (
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/authn"
	"github.com/moonrhythm/parapet/pkg/upstream"
)

var (
	token     = flag.String("token", "", "Bearer Token for Proxy-Authorization")
	authUser  = flag.String("auth-user", "", "Basic User for Proxy-Authorization")
	authPass  = flag.String("auth-pass", "", "Basic Password for Proxy-Authorization")
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
			Authenticate: func(req *http.Request) error {
				// TODO: change to Proxy-Authorization but breaking change
				reqToken := req.Header.Get("Proxy-Authorization")
				req.Header.Del("Proxy-Authorization")
				if subtle.ConstantTimeCompare([]byte(reqToken), []byte(*token)) != 1 {
					return authn.ErrInvalidCredentials
				}
				return nil
			},
		})
	}
	if *authUser != "" && *authPass != "" {
		authStr := base64.StdEncoding.EncodeToString([]byte(*authUser + ":" + *authPass))
		srv.Use(authn.Authenticator{
			Type: "Basic",
			Authenticate: func(req *http.Request) error {
				auth := req.Header.Get("Proxy-Authorization")
				req.Header.Del("Proxy-Authorization")

				const prefix = "Basic "
				if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
					return authn.ErrInvalidCredentials
				}
				if subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(authStr)) != 1 {
					return authn.ErrInvalidCredentials
				}
				return nil
			},
		})
	}

	slog.Info("httpproxy",
		"port", *port,
	)
	err := srv.ListenAndServe()
	if err != nil {
		slog.Error("start server error", "error", err)
	}
}

func proxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
		return
	}

	handleHTTP(w, r)
}

var dialer = net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 15 * time.Second,
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	if *enableLog {
		slog.Info("tunnel connect", "addr", r.RequestURI)
	}

	upstream, err := dialer.DialContext(r.Context(), "tcp", r.RequestURI)
	if err != nil {
		slog.Error("dial upstream error", "network", "tcp", "addr", r.RequestURI, "error", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer upstream.Close()

	client, wr, err := w.(http.Hijacker).Hijack()
	if err != nil {
		slog.Error("hijack error", "addr", r.RequestURI, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	wr.WriteString("HTTP/1.1 200 OK\n\n")
	wr.Flush()

	errc := make(chan error, 1)
	c := conCopier{
		src: upstream,
		dst: client,
	}
	go c.copyToDst(errc)
	go c.copyToSrc(errc)
	<-errc

	if *enableLog {
		slog.Info("tunnel closed", "addr", r.RequestURI)
	}
}

type conCopier struct {
	src net.Conn
	dst net.Conn
}

func (c *conCopier) copyToDst(errc chan error) {
	_, err := io.Copy(c.src, c.dst)
	errc <- err
}

func (c *conCopier) copyToSrc(errc chan error) {
	_, err := io.Copy(c.dst, c.src)
	errc <- err
}

var httpTransport = upstream.HTTPTransport{
	DialTimeout:     5 * time.Second,
	TCPKeepAlive:    10 * time.Second,
	MaxIdleConns:    1000,
	IdleConnTimeout: 1 * time.Minute,
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if *enableLog {
		slog.Info("http", "method", r.Method, "host", r.Host, "path", r.URL.Path)
	}

	if !strings.HasPrefix(r.RequestURI, "http://") {
		http.NotFound(w, r)
		return
	}

	// remove headers
	r.Header.Del("X-Real-Ip")
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Forwarded-Proto")

	resp, err := httpTransport.RoundTrip(r)
	if err != nil {
		slog.Error("http round trip error", "host", r.Host, "error", err)
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
