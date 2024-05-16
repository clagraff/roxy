// MIT License
//
// Copyright (c) 2021 Curtis La Graff
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const ecPrivateKeyBlockType = "EC PRIVATE KEY"
const certificateBlockType = "CERTIFICATE"

func canLookupHost(host string) bool {
	parts := strings.Split(host, ":") // Disregard port, if present.
	_, err := net.LookupHost(parts[0])

	return err == nil
}

func loadLocalhostCert(certPath string, serverName string) (*tls.Certificate, error) {
	pemFile, err := os.ReadFile(certPath + serverName)
	if errors.Is(err, os.ErrNotExist) {
		if pemFile, err = generateSelfSignedCert(certPath, serverName); err != nil {
			return nil, fmt.Errorf("could not generate self-signed cert: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to read local certificate: %w", err)
	}

	keyBlock, rest := pem.Decode(pemFile)

	if keyBlock == nil || keyBlock.Type != ecPrivateKeyBlockType {
		return nil, fmt.Errorf("failed to decode %s block of PEM certificate for %v", ecPrivateKeyBlockType, serverName)
	}

	certBlock, _ := pem.Decode(rest)
	if certBlock == nil || certBlock.Type != certificateBlockType {
		return nil, fmt.Errorf("failed to decode %s block of PEM certificate for %v", certificateBlockType, serverName)
	}

	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certBlock), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	return &cert, nil
}

// generateSelfSignedCert generates a self-signed certificate and saves it to files.
func generateSelfSignedCert(certPath, serverName string) ([]byte, error) {
	// Generate a new private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	// Set up a certificate template.
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("could not generate serial number: %w", err)
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
		return nil, fmt.Errorf("could not create certificate: %w", err)
	}

	err = os.MkdirAll(certPath, 0755)
	if err != nil {
		return nil, fmt.Errorf("could not create certificate directory: %w", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("could not marshal private key: %w", err)
	}

	buff := new(bytes.Buffer)

	// Encode and save the certificate.
	certFile, err := os.Create(certPath + serverName)
	if err != nil {
		return nil, fmt.Errorf("could not create certificate file: %w", err)
	}
	defer func(certFile *os.File) {
		err := certFile.Close()
		if err != nil {
			log.Fatalf("failed to close certificate file: %v", err)
		}
	}(certFile)

	if err := pem.Encode(buff, &pem.Block{Type: ecPrivateKeyBlockType, Bytes: privBytes}); err != nil {
		return nil, fmt.Errorf("could not write data to key file: %w", err)
	}

	if err := pem.Encode(buff, &pem.Block{Type: certificateBlockType, Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("could not write data to certificate file: %w", err)
	}

	if _, err = certFile.Write(buff.Bytes()); err != nil {
		return nil, fmt.Errorf("could not write pem file: %w", err)
	}

	return buff.Bytes(), nil
}
