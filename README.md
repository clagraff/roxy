![](.github/logo.png)

[![Go Workflow](https://github.com/clagraff/roxy/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/clagraff/roxy/actions/workflows/main.yml?query=branch%3Amain)
[![Go Reference](https://pkg.go.dev/badge/github.com/clagraff/roxy.svg)](https://pkg.go.dev/github.com/clagraff/roxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/clagraff/roxy)](https://goreportcard.com/report/github.com/clagraff/roxy)

![](./.github/roxy.png)

# roxy

`roxy` is a minimalistic reverse proxy server for forwarding requests based on the requested (sub) domain. 

It is for servicing external requests, supporting both http (`:80`) and https (`:443`). For HTTPS, `roxy`
utilizes automatic certificate generation using Golang's `autocert` package for non-localhost domains.. 

Eg:

```bash
$ go install github.com/clagraff/roxy
$ roxy -p blog.mydomain.com=127.0.0.1:9010 -p wiki.mydomain.com=127.0.0.1:9020 -p http://old.mydomain.com=127.0.0.1:8001
``` 

or using docker:

```bash
$ docker pull clagraff/roxy
$ docker run -d -p 80:80 -p 443:443 clagraff/roxy -p blog.mydomain.com=blog:80 -p wiki.mydomain.com=wiki:80 -p http://old.mydomain.com=https://new.domain
```


```bash
$ roxy -h
Usage of roxy:    
  -c string
        Path to store auto-generated certs for non-localhost hosts (default "./certs")
  -h    show help & usage
  -p value
        proxy definition describing an origin and upstream url to proxy, eg: origin=upstream
  -r    turn off automatic HTTP redirects (on by default)

Proxy pattern
  origin, upstream:     [scheme://]hostname[:port]

  [scheme://]
        Optional; origin defaults to https; upstream defaults to http.
  [:port]
        Optional; defaults to :80 and :443 for HTTP and HTTPS if not specified.

  examples:
        Bare minimum:           origin=upstream
        With schemes:           https://origin=http://upstream
        With ports:             origin:443=upstream:9090
        With subdomains:        https://sub.origin=upstream:8001

Self-signed localhost cert(s)
  When a localhost domain is specified as an origin, a self-signed,
  untrusted certificate will be created for it.
  Depending on your HTTP client, you may need to install/trust the certificate
  for requests to be successful, or use a non-https version of the domain.
    	
    	
$ roxy -p api.localhost=localhost:9090
```


## Example
**Example Setup**

We are going to setup `roxy` to serve requests between two different servers (we will run using python).
One server will be for `http://server1.localhost` and is listening on `:9001`.
The second server will be for `http://server2.localhost` and listen on `:9002`.

```bash
$ # This is an HTTP-only example for simplicity...
$ mkdir /tmp/server{1,2}
$ echo "Server 1" > /tmp/server1/index.html
$ echo "Server 2" > /tmp/server2/index.html
$ # To test the reverse proxy functionality, 
$ # we will setup some "fake" local subdomains.
$ echo "127.0.0.1    server1.localhost" | sudo tee -a /etc/hosts
127.0.0.1    server1.local
$ echo "127.0.0.1    server2.localhost" | sudo tee -a /etc/hosts
127.0.0.1    server2.local
$ # Spin up some servers to proxy to...
$ python3 -m http.server 9001 --directory /tmp/server1 &
$ python3 -m http.server 9002 --directory /tmp/server2 &
```

**Run the server**

Download and install `roxy`, then run it in HTTP-only mode.

```bash
$ # Let's go!!
$ go install github.com/clagraff/roxy
$ roxy -p server1.localhost=127.0.0.1:9001 -p server2.localhost=127.0.0.1:9002
``` 

**Try it out**

Try out the reverse proxy by making some requests.

```bash
$ curl http://server1.localhost
Server 1
$ curl http://server2.localhost
Server 2
```

## Usage
### Automatic Certificate Generation
`roxy` will use HTTPS (`:443`) by default, and generate certificates automatically based
on the host(s) specified using `-p` flag. For origins with an explicit `http` scheme, cert generation does not occur.

Take the following command as an example:

```bash
$ roxy -p dev.local=127.0.0.1:9000 -p docs.local=127.0.0.1:9010 -p ci.local=127.0.0.1:9020
```

In the above example, `roxy` will listen for HTTPS requests, and will generate certificates on-the-fly for 
the domains `dev.local`, `docs.local`, and `ci.local`. 

These domains must 1.) be correctly setup to point to the server `roxy` is running on (via A-records), and 2.) `roxy`
must be allowed to communicate to Let's Encrypt to perform the certificate generation (firewall rules may block it).

Note: cert generation does not happen at startup; rather, it happens upon the first request when a certificate has not been
generated or is expired.

Please be aware of [Let's Encrypt's rate limiting](https://letsencrypt.org/docs/rate-limits/), which at the time
of writing is 50 per week.

## Help
You can use `-h / --help` at any time to view available options.