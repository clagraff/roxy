package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// statusCodeCapturer is a http.ResponseWriter wrapper which will save the response status code once it has been
// set.
// Used to log out the status code.
type statusCodeCapturer struct {
	statusCode     int
	originalWriter http.ResponseWriter
}

// newStatusCodeCapturer returns a new instance of the statusCodeCapturer wrapping the provided http.ResponseWriter.
func newStatusCodeCapturer(w http.ResponseWriter) *statusCodeCapturer {
	return &statusCodeCapturer{
		statusCode:     0, // Needs a default, ideally should NEVER stay at zero.
		originalWriter: w,
	}
}

// Header proxies calls to the wrapped http.ResponseWriter's header method.
func (capturer *statusCodeCapturer) Header() http.Header {
	return capturer.originalWriter.Header()
}

// Write proxies calls to the wrapped http.ResponseWriter's write method.
// If the status code has not already been set, set to http.StatusOK.
func (capturer *statusCodeCapturer) Write(b []byte) (int, error) {
	if capturer.statusCode == 0 {
		capturer.statusCode = 200
	}
	return capturer.originalWriter.Write(b)
}

// WriteHeader captures the desired http status code, and forwards to the underlying http.ResponseWriter.
func (capturer *statusCodeCapturer) WriteHeader(i int) {
	capturer.statusCode = i
	capturer.originalWriter.WriteHeader(i)
}

func proxyInboundRequest(mutex *sync.RWMutex, proxies map[proxyKey]proxyConfig, noHttpRedirect bool) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
			if !noHttpRedirect && scheme == "http" {
				http.Redirect(wrapper, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
				return
			}
			log.Printf("could not find upstream: %s://%s", scheme, r.Host)
			w.WriteHeader(404)
		}
	}
}

func canLookupHost(host string) bool {
	parts := strings.Split(host, ":") // Disregard port, if present.
	_, err := net.LookupHost(parts[0])

	return err == nil
}

func loadLocalhostCert(certPath string, serverName string) (*tls.Certificate, error) {
	baseFilePath := certPath + sha256Hash(serverName)

	_, err := os.ReadFile(baseFilePath + ".crt")
	if errors.Is(err, os.ErrNotExist) {
		if err := generateSelfSignedCert(certPath, serverName); err != nil {
			return nil, fmt.Errorf("could not generate self-signed cert: %w", err)
		}
	}

	certPEMBlock, err := os.ReadFile(baseFilePath + ".crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read local certificate: %w", err)
	}
	keyPEMBlock, err := os.ReadFile(baseFilePath + ".key")
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
func generateSelfSignedCert(certPath, serverName string) error {
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
			Organization: []string{serverName},
			CommonName:   serverName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,

		DNSNames:    []string{serverName},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create a self-signed certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("could not create certificate: %w", err)
	}

	err = os.MkdirAll(certPath, 0700)
	if err != nil {
		return fmt.Errorf("could not create certificate directory: %w", err)
	}

	// Encode and save the private key.
	baseFilePath := certPath + sha256Hash(serverName)
	keyFile, err := os.Create(baseFilePath + ".key")
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
	certFile, err := os.Create(baseFilePath + ".crt")
	if err != nil {
		return fmt.Errorf("could not create certificate file: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("could not write data to certificate file: %w", err)
	}
	_ = certFile.Close()

	return nil
}

func sha256Hash(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hashBytes := hasher.Sum(nil)

	return hex.EncodeToString(hashBytes)
}
