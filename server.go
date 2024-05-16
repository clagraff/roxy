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
	"log"
	"net/http"
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
