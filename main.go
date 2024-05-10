package main

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

func main() {
	args := os.Args[1:]
	progArgs, err := parseProgramArguments(args)
	if err != nil {
		log.Fatal(err)
	}

	if len(progArgs.proxies) <= 0 {
		log.Fatal("no proxies specified use `-h` for help")
	}

	proxies := setupProxyConfigs(progArgs)

	httpsProxies := make(map[proxyKey]proxyConfig)
	httpProxies := make(map[proxyKey]proxyConfig)

	// For inbound HTTPS non-localhost origins, add their hostname to an allow-list to be used by autocert.
	var autoCertAllowList []string

	for k, v := range proxies {
		isHttps := v.origin.Scheme == "https"
		isLocalhost := strings.HasSuffix(v.origin.Host, "localhost")

		if !isHttps {
			httpProxies[k] = v
			continue
		}

		httpsProxies[k] = v

		if !isLocalhost {
			autoCertAllowList = append(autoCertAllowList, v.origin.Host)
		}
	}

	if len(httpProxies) > 0 {
		log.Printf("http proxies: %v", keys(httpProxies))
	}

	if len(httpsProxies) > 0 {
		log.Printf("https proxies: %v", keys(httpsProxies))
	}

	if len(autoCertAllowList) > 0 {
		log.Printf("autocert allow list: %v", autoCertAllowList)
	} else {
		log.Printf("autocert wont be used as only locahost domains as origins were specified \n")
	}

	mutex := new(sync.RWMutex)

	var tlsConfig *tls.Config

	m := &autocert.Manager{
		Cache:      autocert.DirCache(progArgs.certPath), // Provide a directory to store and cache certificates
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(autoCertAllowList...), // Only allow autocert for specified hosts
	}

	tlsConfig = &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if strings.HasSuffix(info.ServerName, "localhost") {
				cert, err := loadLocalhostCert(progArgs.certPath, info.ServerName)
				if err != nil {
					err = fmt.Errorf("failed to load localhost cert: %w", err)
				}
				return cert, err
			}

			// Use autocert for other domains
			cert, err := m.GetCertificate(info)
			if err != nil {
				err = fmt.Errorf("failed to get cert from autocert: %w", err)
			}
			return cert, err
		},
		MinVersion: tls.VersionTLS12,
	}

	// Update proxies to use correct TLS config
	for _, v := range proxies {
		v.proxy.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		if !canLookupHost(v.origin.Host) {
			log.Printf("lookup failed for origin host: %s", v.origin.Host)
		}
		if !canLookupHost(v.upstream.Host) {
			log.Printf("lookup failed for upstream host: %s", v.origin.Host)
		}
	}

	go func() {
		log.Println("starting server for :http")
		httpMux := http.NewServeMux()
		httpMux.HandleFunc("/", proxyInboundRequest(mutex, httpProxies, progArgs.noHttpRedirect))
		httpServer := &http.Server{
			Addr:    ":http",
			Handler: httpMux,
		}
		err := httpServer.ListenAndServe()
		if err != nil {
			log.Fatalf("failed to listen and serve http server: %v", err)
		}
	}()

	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", proxyInboundRequest(mutex, httpsProxies, progArgs.noHttpRedirect))
	httpsServer := &http.Server{
		Addr:      ":https",
		TLSConfig: tlsConfig,
		Handler:   httpsMux,
	}

	log.Println("starting server for :https")
	err = httpsServer.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("failed to listen and serve https server: %v", err)
	}
}

func keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
