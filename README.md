# roxy

`roxy` is a minimalistic reverse proxy server for forwarding requests based on the requested (sub) domain. 

It is for servicing external requests, supporting both http (`:80`) and https (`:443`). For HTTPS, `roxy`
utilizes automatic certificate generation using Let's Encrypt. 

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
$ go install scm.lagraff.me/roxy
$ roxy -http -p server1.localhost=127.0.0.1:9001 -p server2.localhost=127.0.0.1:9002 &
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
on the host(s) specified using `-p` / `-proxy`.

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

```bash
$ roxy -h
Usage of roxy:
  -h	show help (shorthand)
  -help
    	show help
  -http
    	use http, instead of https with autocerts
  -p value
    	add a new proxy (domain=port)
  -proxy value
    	add a new proxy (domain=port)
```