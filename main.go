package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// atLeastOnceValue is to represent the presence of one of a number of flags, eg: -h and -help
type atLeastOnceValue bool

// String returns true when the associated flag is present at least once.
func (v *atLeastOnceValue) String() string {
	if v != nil && *v {
		return "true"
	}
	return "false"
}

// Set will always set the value of the type to true.
func (v *atLeastOnceValue) Set(s string) error {
	*v = true
	return nil
}

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
	certPath string
}

func parseProgramArguments(args []string) (programArguments, error) {
	progArgs := programArguments{
		showHelp: false,
		proxies:  stringGroup{},
	}

	set := flag.NewFlagSet("roxy", flag.ContinueOnError)

	set.BoolVar(&progArgs.showHelp, "h", false, "show help & usage")

	set.Var(&progArgs.proxies, "p", "proxy definition describing an origin and upstream url to proxy, eg: origin=upstream")

	set.StringVar(&progArgs.certPath, "c", "./certs", "Path to store auto-generated or self-signed certs")

	err := set.Parse(args)

	if progArgs.showHelp {
		set.Usage()
		_, _ = fmt.Fprintf(set.Output(), "\nProxy pattern\n")
		_, _ = fmt.Fprintf(set.Output(), "  origin, upstream:\t[scheme://]hostname[:port]\n\n")

		_, _ = fmt.Fprintf(set.Output(), "  [scheme://]\n  \tOptional; origin defaults to https; upstream defaults to http.\n")
		_, _ = fmt.Fprintf(set.Output(), "  [:port]\n  \tOptional; defaults to :80 and :443 for HTTP and HTTPS if not specified.\n\n")

		_, _ = fmt.Fprintf(set.Output(), "  examples:\n")
		_, _ = fmt.Fprintf(set.Output(), "  \tBare minimum:\t\torigin=upstream\n")
		_, _ = fmt.Fprintf(set.Output(), "  \tWith schemes:\t\thttps://origin=http://upstream\n")
		_, _ = fmt.Fprintf(set.Output(), "  \tWith ports:\t\torigin:443=upstream:9090\n")
		_, _ = fmt.Fprintf(set.Output(), "  \tWith subdomains:\thttps://sub.origin=upstream:8001\n")

		return progArgs, flag.ErrHelp
	}

	if !strings.HasSuffix(progArgs.certPath, "/") {
		progArgs.certPath = progArgs.certPath + "/"
	}

	if len(progArgs.proxies) == 0 {
		return progArgs, fmt.Errorf("no proxy definitions provided, use -h for help")
	}
	if len(progArgs.certPath) == 0 {
		log.Println("cert path is empty which is unusual; certs will be created in the current working directory")
	}

	return progArgs, err
}

// proxyKey is a composite structure to use as a Golang map key, pointing to a httputil.ReverseProxy instance.
type proxyKey struct {
	Scheme string
	Host   string
}

type proxySettings struct {
	redirectInboundHttp bool
	origin              *url.URL
	upstream            *url.URL
	proxy               *httputil.ReverseProxy
}

func parseProxyDefinition(def string) (proxySettings, error) {
	var settings proxySettings

	parts := strings.Split(def, "=")
	if len(parts) != 2 {
		return settings, fmt.Errorf("proxy definition must be of form origin=upstream: %s", def)
	}

	first := parts[0]
	last := parts[1]

	// if no scheme is specified for the origin, assume https.
	if !strings.HasPrefix(first, "http") {
		first = "https://" + first
	}

	// If no scheme is specified for the upstream, assume http (not S).
	if !strings.HasPrefix(last, "http") {
		last = "http://" + last
	}

	origin, err := url.Parse(first)
	if err != nil {
		return settings, fmt.Errorf("could not parse origin: %w", err)
	}

	if origin.Path == "" {
		origin.Path = "/"
	}

	upstream, err := url.Parse(last)
	if err != nil {
		return settings, fmt.Errorf("could not parse upstream: %w", err)
	}

	settings.origin = origin
	settings.upstream = upstream
	settings.proxy = httputil.NewSingleHostReverseProxy(upstream)

	log.Println(fmt.Sprintf("creating reverse proxy: %s to %s", origin, upstream))
	return settings, nil
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

// httpRedirect redirects all HTTP requests to HTTPS
func httpRedirect(w http.ResponseWriter, r *http.Request) {
	// Get the host from the request header
	host := r.Host

	// Change the URL scheme to https
	target := "https://" + host + r.RequestURI

	// Set HTTP status code to 301 Moved Permanently for SEO and caching purposes
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func main() {
	args := os.Args[1:]
	progArgs, err := parseProgramArguments(args)
	if err != nil {
		log.Fatal(err)
	}

	proxies := setupProxySettings(progArgs)

	// For inbound HTTPS origins, add their hostname to an allow-list to be used by autocert.
	var autoCertAllowList []string
	for _, v := range proxies {
		isHttps := v.origin.Scheme == "https"
		isNotLocalHost := !strings.HasSuffix(v.origin.Host, "localhost")

		if isHttps && isNotLocalHost {
			autoCertAllowList = append(autoCertAllowList, v.origin.Host)
		}
	}

	if len(autoCertAllowList) > 0 {
		log.Printf("autocert allow list: %s\n", autoCertAllowList)
	} else {
		log.Printf("no autocert allow list present; only expected when using self-signed localhost certs for origins\n")
	}

	mutex := new(sync.RWMutex)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapper := newStatusCodeCapturer(w)

		defer func() {
			dur := time.Since(start)
			status := wrapper.statusCode

			log.Printf("method=%s host=%s path=%s status=%d dur=%s\n", r.Method, r.Host, r.URL.Path, status, dur)
		}()

		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}

		mutex.RLock()
		settings, ok := proxies[proxyKey{
			Scheme: scheme,
			Host:   r.Host,
		}]
		mutex.RUnlock()

		if ok {
			settings.proxy.ServeHTTP(wrapper, r)
		} else {
			log.Println("could not find upstream")
			w.WriteHeader(404)
		}
	})

	// TLS configuration with autocert
	var tlsConfig *tls.Config

	m := &autocert.Manager{
		Cache:      autocert.DirCache(progArgs.certPath), // Provide a directory to store and cache certificates
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(autoCertAllowList...), // Only allow autocert for specified hosts
	}

	tlsConfig = &tls.Config{

		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if strings.HasSuffix(info.ServerName, "localhost") {
				// Load self-signed certificate for localhost
				return loadLocalhostCert(progArgs.certPath)
			}
			// Use autocert for other domains
			return m.GetCertificate(info)
		},
		MinVersion: tls.VersionTLS12,
	}

	// Update proxies to use correct TLS config
	for _, v := range proxies {
		v.proxy.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		if !canLookupHost(v.origin.Host) {
			log.Printf("review hosts file as cannot lookup origin host: %s", v.origin.Host)
		}
		if !canLookupHost(v.upstream.Host) {
			log.Printf("review hosts file as cannot lookup upstream host: %s", v.origin.Host)
		}
	}

	go func() {
		log.Println("starting server for :http")
		err := http.ListenAndServe(":http", http.HandlerFunc(httpRedirect))
		if err != nil {
			log.Fatalf("failed to listen and serve http server: %v", err)
		}
	}()

	s := &http.Server{
		Addr:      ":https",
		TLSConfig: tlsConfig,
	}

	log.Println("starting server for :https")
	err = s.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("failed to listen and serve https server: %v", err)
	}
}

func canLookupHost(host string) bool {
	parts := strings.Split(host, ":") // Disregard port, if present.
	_, err := net.LookupHost(parts[0])

	return err == nil
}

func setupProxySettings(progArgs programArguments) map[proxyKey]proxySettings {
	proxyMap := make(map[proxyKey]proxySettings)
	for _, def := range progArgs.proxies {
		settings, err := parseProxyDefinition(def)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to parse proxy definitions: %w", err))
		}

		proxyMap[proxyKey{
			Scheme: settings.origin.Scheme,
			Host:   settings.origin.Host,
		}] = settings
	}

	// Verify there are no proxies setup to reference other proxies:
	for _, v := range proxyMap {
		if _, ok := proxyMap[proxyKey{
			Scheme: v.upstream.Scheme,
			Host:   v.upstream.Host,
		}]; ok {
			log.Fatalf("proxy definition cannot use upstream which points to another proxy: %v=%v", v.origin, v.upstream)
		}
	}
	return proxyMap
}

func loadLocalhostCert(certPath string) (*tls.Certificate, error) {
	_, err := os.ReadFile(certPath + "localhost.crt")
	if errors.Is(err, os.ErrNotExist) {
		if err := generateSelfSignedCert(certPath); err != nil {
			return nil, fmt.Errorf("could not generate self-signed cert: %w", err)
		}
	}

	certPEMBlock, err := os.ReadFile(certPath + "localhost.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read local certificate: %w", err)
	}
	keyPEMBlock, err := os.ReadFile(certPath + "localhost.key")
	if err != nil {
		return nil, fmt.Errorf("failed to read local cert key: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	return &cert, nil
}

// generateSelfSignedCert generates a self-signed certificate and saves it to files.
func generateSelfSignedCert(certPath string) error {
	// Generate a new private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("could not generate private key: %w", err)
	}

	// Set up a certificate template.
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("could not generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"localhost"},
			CommonName:   "localhost",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,

		DNSNames:    []string{"localhost", "first.localhost", "second.localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create a self-signed certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("could not create certificate: %w", err)
	}

	// Encode and save the private key.
	keyFile, err := os.Create(certPath + "localhost.key")
	if err != nil {
		return fmt.Errorf("could not create key file: %w", err)
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("could not marshal private key: %w", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("could not write data to key file: %w", err)
	}
	_ = keyFile.Close()

	// Encode and save the certificate.
	certFile, err := os.Create(certPath + "localhost.crt")
	if err != nil {
		return fmt.Errorf("could not create certificate file: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("could not write data to certificate file: %w", err)
	}
	_ = certFile.Close()

	return nil
}
