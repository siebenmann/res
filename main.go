// res resolves one or more IP addresses to DNS names, normally
// validating that the DNS name (or names) also points to the IP
// address. By default only the first (valid) DNS name for an IP is
// reported; give -A to validate and/or report on all names. -A with
// -q will only report the valid names (if any); -A without -q will
// report on the validation status of all names. Names are reported in
// some random order, probably the order that the DNS server gives
// them to us.
//
// The normal case is that an IP has only a single DNS name, and
// ideally that DNS name is valid.
//
// IP addresses are normally given on the command line, but can also
// be given on standard input (one per line) with the -S switch.
//
// See 'res -h' for help.
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pborman/getopt/v2"
)

// Sometimes globals are the simplest answer.
var allnames, quiet, nounknown, verbose, novalidate, help, readstdin bool
var tmout time.Duration

// validateIpName validates one name that is supposed to mape to a given IP
// (provided in string form). It returns either true or false, and if it
// returns false it returns a non-empty reason.
func validateIpName(ctx context.Context, ips, name string) (ok bool, reason string) {
	if novalidate {
		return true, ""
	}

	// The net documentation specifically says that if we use the
	// host C library resolver, only one name will be returned.
	res := &net.Resolver{
		PreferGo: true,
	}
	if net.ParseIP(name) != nil {
		if !quiet {
			return false, "RESOLVES-TO-IP"
		}
		return
	}
	var cancel context.CancelFunc
	if tmout != 0 {
		ctx, cancel = context.WithTimeout(ctx, tmout)
		defer cancel()
	}
	r, err := res.LookupHost(ctx, name)
	if err != nil || len(r) == 0 {
		return false, "CANNOT-FIND"
	}
	for _, a := range r {
		if a == ips {
			return true, ""
		}
	}
	return false, "INCONSISTENT"
}

// checkIp checks one IP address and prints the results.
//
// TODO: should we support a timeout for the entire process, in
// addition to a timeout on each DNS request? Tentatively no.
func checkIp(ips string) {
	// If we don't force PreferGo, we can only ever get one
	// result for the IP to name lookup, apparently.
	res := &net.Resolver{
		PreferGo: true,
	}

	ip := net.ParseIP(ips)
	if ip == nil {
		// We always report this result in full even if you
		// asked for quiet results because lol no.
		fmt.Printf("%s NOT-IP-ADDRESS\n", ips)
		return
	}
	// We deliberately canonicalize the IP address here.
	ips = ip.String()

	var cancel context.CancelFunc
	ctx := context.Background()
	if tmout != 0 {
		ctx, cancel = context.WithTimeout(ctx, tmout)
		defer cancel()
	}

	// LookupAddr() filters the raw PTR lookup results to only have
	// valid domain names. If this filtering excludes some things,
	// it will return with err != nil but len(r) > 0. If this happens,
	// we want to still check the available results but also (if non
	// quiet) report that we had bad PTR data, since that bad data
	// would have failed reverse validation.
	r, err := res.LookupAddr(ctx, ips)
	if len(r) == 0 {
		if !quiet && !nounknown {
			fmt.Printf("%s UNKNOWN\n", ips)
		}
		return
	}
	// If we aren't quiet and there were some PTR records excluded,
	// we want to report this. In practice the error is a constant
	// in current Go (1.21). We report this even if validation is
	// off, for reasons.
	if err != nil && !quiet {
		fmt.Printf("%s BAD-PTR-DATA %s\n", ips, err)
	}

	// If we are not reporting all names and we are validating, we
	// keep trying to validate until we succeed. If we fail, we
	// report the failure for the *last* name checked, because
	// that's easiest.
	var ok bool
	var reason, hn2 string
	for _, hn := range r {
		ok, reason = validateIpName(context.Background(), ips, hn)
		hn2 = strings.TrimSuffix(hn, ".")
		switch {
		case ok && verbose:
			fmt.Printf("%s %s\n", ips, hn2)
		case ok:
			fmt.Printf("%s\n", hn2)
		case !ok && !allnames:
			// We do nothing ... yet.
		case !ok && !quiet:
			fmt.Printf("%s %s %s\n", ips, reason, hn2)
		default:
			// We are silent on failures with quiet.
		}
		if !allnames && ok {
			break
		}
	}
	if !allnames && !quiet && !ok {
		fmt.Printf("%s %s %s\n", ips, reason, hn2)
	}
}

func main() {
	getopt.FlagLong(&help, "help", 'h', "Print help.")
	getopt.FlagLong(&novalidate, "no-validate", 'N', "Do not validate reverse host names.")
	getopt.FlagLong(&allnames, "all-names", 'A', "Report or validate all names returned for an IP, not just the first.")
	getopt.FlagLong(&quiet, "quiet", 'q', "Be quiet and only report (validated) names.")
	getopt.FlagLong(&verbose, "verbose", 'v', "Report IP as well as name for successful resolutions.")
	getopt.FlagLong(&nounknown, "no-unknown", 'U', "Don't report IPs that have no reverse DNS names.")
	getopt.FlagLong(&tmout, "timeout", 't', "Timeout for each DNS lookup, if any; use eg '1s'.", "DURATION")
	getopt.FlagLong(&readstdin, "stdin", 'S', "Read IPs to resolve from standard input (one per line) instead of arguments.")
	getopt.SetParameters("IP [IP ...]")

	getopt.Parse()
	if help {
		getopt.Usage()
		return
	}

	args := getopt.Args()
	if len(args) == 0 && !readstdin {
		fmt.Fprintf(os.Stderr, "%s: no IPs given to resolve (and no -S).\n", os.Args[0])
		getopt.Usage()
		return
	}
	if len(args) != 0 && readstdin {
		fmt.Fprintf(os.Stderr, "%s: cannot use -S with IPs on the command line.\n", os.Args[0])
		getopt.Usage()
		return
	}

	if len(args) > 0 {
		for _, ips := range args {
			checkIp(ips)
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			checkIp(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: reading standard input: %s\n", os.Args[0], err)
		}
	}
}
