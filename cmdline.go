package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
)

// stringList implements flag.Var for capturing multiple instances of the flag appearing on the commandline.
// Eg: `-s one -s two` would result in: `[]stringList{"one", "two"}`
type stringList []string

// String() displays the current values, comma-separated.
func (sl stringList) String() string {
	return strings.Join(sl, ",")
}

// Set will append the value to the current list.
func (sl *stringList) Set(s string) error {
	*sl = append(*sl, s)
	return nil
}

// programArguments will store all cmdline-based flags and values.
type programArguments struct {
	// showHelp indicates the -h flag was present from the cmdline args.
	showHelp bool

	// proxies stores all user-specified origin=upstream proxy pairs.
	proxies stringList

	// certPath is a directory where autocert should store generated TLS certificates.
	certPath string

	// noHttpRedirect indicates if non-proxied HTTP requests should be redirected to their HTTPS equivalent.
	// Note that no checks are done to ensure the new HTTPS origin actually exists.
	noHttpRedirect bool
}

// parseProgramArguments creates a flag group, parses argument flags, and populates a programArguments instance
// as applicable.
func parseProgramArguments(args []string) (programArguments, error) {
	progArgs := programArguments{
		showHelp: false,
		proxies:  stringList{},
	}

	set := flag.NewFlagSet("roxy", flag.ContinueOnError)

	set.BoolVar(&progArgs.showHelp, "h", false, "show help & usage")
	set.Var(&progArgs.proxies, "p", "proxy definition describing an origin and upstream url to proxy, eg: origin=upstream")
	set.StringVar(&progArgs.certPath, "c", "./certs", "Path to store auto-generated certs for non-localhost hosts")
	set.BoolVar(&progArgs.noHttpRedirect, "r", false, "turn off automatic HTTP redirects (on by default)")

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

		_, _ = fmt.Fprintf(set.Output(), "\nSelf-signed localhost cert(s)\n")
		_, _ = fmt.Fprintf(set.Output(), "  When a localhost domain is specified as an origin, a self-signed,\n")
		_, _ = fmt.Fprintf(set.Output(), "  untrusted certificate will be created for it.\n")
		_, _ = fmt.Fprintf(set.Output(), "  Depending on your HTTP client, you may need to install/trust the certificate\n")
		_, _ = fmt.Fprintf(set.Output(), "  for requests to be successful, or use a non-https version of the domain.\n\n")

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
