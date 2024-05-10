package main

import (
	"fmt"
	"log"
	"net/http/httputil"
	"net/url"
	"strings"
)

// proxyKey is a composite structure to use as a Golang map key when fetching proxyConfig for an inbound request.
type proxyKey struct {
	Scheme string
	Host   string
}

func (k proxyKey) String() string {
	return k.Scheme + "://" + k.Host
}

// proxyConfig has the origin, upstream, and httputil.ReverseProxy instance that appropriate requests should be
// forwarded to.
type proxyConfig struct {
	origin   *url.URL
	upstream *url.URL
	proxy    *httputil.ReverseProxy
}

// parseProxyDefinition takes a `origin=upstream` proxy definition and returns a proxyConfig or an error.
func parseProxyDefinition(def string) (proxyConfig, error) {
	var settings proxyConfig

	// split the definition.
	parts := strings.Split(def, "=")
	if len(parts) != 2 {
		return settings, fmt.Errorf("proxy definition must be of form origin=upstream: %s", def)
	}

	first := parts[0] // origin
	last := parts[1]  // upstream

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

	// TODO: I am not sure this is actually needed anymore. When we used to include the base path
	// in the proxyKey, we ensures the origin's path wasnt empty. But I dont believe this is required anymore.
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

func setupProxyConfigs(progArgs programArguments) map[proxyKey]proxyConfig {
	proxyMap := make(map[proxyKey]proxyConfig)
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
