package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type stringGroup []string

func (group stringGroup) String() string {
	return strings.Join(group, ",")
}

func (group *stringGroup) Set(s string) error {
	*group = append(*group, s)
	return nil
}

type programArguments struct {
	showHelp bool
	proxies  stringGroup
	useHTTP  bool
}

func parseProgramArguments(args []string) (programArguments, error) {
	progArgs := programArguments{
		showHelp: false,
		proxies:  stringGroup{},
	}

	set := flag.NewFlagSet("roxy", flag.ContinueOnError)

	set.BoolVar(&progArgs.showHelp, "help", false, "show help")
	set.BoolVar(&progArgs.showHelp, "h", false, "show help (shorthand)")

	set.Var(&progArgs.proxies, "p", "add a new proxy (domain=port)")
	set.Var(&progArgs.proxies, "proxy", "add a new proxy (domain=port)")

	set.BoolVar(&progArgs.useHTTP, "http", false, "use http, instead of https with autocerts")

	err := set.Parse(args)

	if progArgs.showHelp {
		set.Usage()
		err = flag.ErrHelp // set err since we showed program usage.
	}
	return progArgs, err

}

type proxyDefinition struct {
	origin   *url.URL
	upstream *url.URL
}

func parseProxyDefinition(def string, incomingPort int) (proxyDefinition, error) {
	parts := strings.Split(def, "=")
	if len(parts) != 2 {
		return proxyDefinition{}, fmt.Errorf("proxy definition must be of form origin=upstream: %s", def)
	}

	// If origin is missing HTTP(S) prefix, add it.
	if !strings.HasPrefix(parts[0], "http") {
		if incomingPort == 80 {
			parts[0] = fmt.Sprintf("http://%s", parts[0])
		} else if incomingPort == 443 {
			parts[0] = fmt.Sprintf("https://%s", parts[0])
		} else {
			return proxyDefinition{}, fmt.Errorf("could not prefix origin due to invalid port")
		}
	}

	// If upstream is missing HTTP(S) prefix, add it.
	if !strings.HasPrefix(parts[1], "http") {
		upstreamParts := strings.Split(parts[1], ":")
		if len(upstreamParts) == 2 && upstreamParts[1] == "443" {
			parts[1] = fmt.Sprintf("https://%s", parts[1])
		} else {
			parts[1] = fmt.Sprintf("http://%s", parts[1])
		}
	}

	origin, err := url.Parse(parts[0])
	if err != nil {
		return proxyDefinition{}, fmt.Errorf("could not parse origin: %w", err)
	}

	if origin.Port() != "" && origin.Port() != fmt.Sprintf("%d", incomingPort) {
		return proxyDefinition{}, fmt.Errorf("origin port must be %d or unspecified", incomingPort)
	}

	upstream, err := url.Parse(parts[1])
	if err != nil {
		return proxyDefinition{}, fmt.Errorf("could not parse upstream: %w", err)
	}

	return proxyDefinition{
		origin:   origin,
		upstream: upstream,
	}, nil
}

type statusCodeCapturer struct {
	statusCode     int
	originalWriter http.ResponseWriter
}

func newStatusCodeCapturer(w http.ResponseWriter) *statusCodeCapturer {
	return &statusCodeCapturer{
		statusCode:     0,
		originalWriter: w,
	}
}

func (capturer *statusCodeCapturer) Header() http.Header {
	return capturer.originalWriter.Header()
}

func (capturer *statusCodeCapturer) Write(b []byte) (int, error) {
	if capturer.statusCode == 0 {
		capturer.statusCode = 200
	}

	return capturer.originalWriter.Write(b)
}

func (capturer *statusCodeCapturer) WriteHeader(i int) {
	capturer.statusCode = i
	capturer.originalWriter.WriteHeader(i)
}

func main() {
	args := os.Args[1:]

	progArgs, err := parseProgramArguments(args)
	if err != nil {
		os.Exit(1)
	}

	var allowList []string
	reverseProxies := make(map[string]*httputil.ReverseProxy)
	expectedPort := 443
	if progArgs.useHTTP {
		expectedPort = 80
	}

	for _, proxyString := range progArgs.proxies {
		def, err := parseProxyDefinition(proxyString, expectedPort)
		if err != nil {
			fmt.Printf("error: %s\n", err)
			os.Exit(1)
		}

		log.Println(fmt.Sprintf("creating reverse proxy mapping: %s to %s", def.origin.Host, def.upstream.Host))
		allowList = append(allowList, def.origin.Host)
		reverseProxies[def.origin.Host] = httputil.NewSingleHostReverseProxy(def.upstream)
	}

	mutex := new(sync.RWMutex)

	log.Printf("origin allow list: %s\n", allowList)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapper := newStatusCodeCapturer(w)

		defer func() {
			dur := time.Since(start)
			status := wrapper.statusCode

			log.Printf("method=%s host=%s path=%s status=%d dur=%s\n", r.Method, r.Host, r.URL.Path, status, dur)
		}()

		host := r.Host
		mutex.RLock()
		upstream, ok := reverseProxies[host]
		mutex.RUnlock()

		if ok {
			upstream.ServeHTTP(wrapper, r)
		} else {
			log.Println("could not find upstream")
			w.WriteHeader(404)
		}
	})

	if progArgs.useHTTP {
		log.Fatal(http.ListenAndServe(":http", nil))
	} else {
		m := &autocert.Manager{
			Cache:      autocert.DirCache("secret-dir"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(allowList...),
		}
		s := &http.Server{
			Addr:      ":https",
			TLSConfig: m.TLSConfig(),
		}
		log.Fatal(s.ListenAndServeTLS("", ""))
	}
}
