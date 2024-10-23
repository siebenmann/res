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
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pborman/getopt/v2"
)

// Sometimes globals are the simplest answer.
var allnames, quiet, nounknown, verbose, novalidate, help, readstdin bool
var tmout time.Duration
var npar int

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
// The results are printed to the io.Writer we're given.
//
// TODO: should we support a timeout for the entire process, in
// addition to a timeout on each DNS request? Tentatively no.
func checkIp(ips string, to io.Writer) {
	// If we don't force PreferGo, we can only ever get one
	// result for the IP to name lookup, apparently.
	res := &net.Resolver{
		PreferGo: true,
	}

	ip := net.ParseIP(ips)
	if ip == nil {
		// We always report this result in full even if you
		// asked for quiet results because lol no.
		fmt.Fprintf(to, "%s NOT-IP-ADDRESS\n", ips)
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
			fmt.Fprintf(to, "%s UNKNOWN\n", ips)
		}
		return
	}
	// If we aren't quiet and there were some PTR records excluded,
	// we want to report this. In practice the error is a constant
	// in current Go (1.21). We report this even if validation is
	// off, for reasons.
	if err != nil && !quiet {
		fmt.Fprintf(to, "%s BAD-PTR-DATA %s\n", ips, err)
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
			fmt.Fprintf(to, "%s %s\n", ips, hn2)
		case ok:
			fmt.Fprintf(to, "%s\n", hn2)
		case !ok && !allnames:
			// We do nothing ... yet.
		case !ok && !quiet:
			fmt.Fprintf(to, "%s %s %s\n", ips, reason, hn2)
		default:
			// We are silent on failures with quiet.
		}
		if !allnames && ok {
			break
		}
	}
	if !allnames && !quiet && !ok {
		fmt.Fprintf(to, "%s %s %s\n", ips, reason, hn2)
	}
}

// A DNS lookup request is a struct with the IP to look up and a channel
// to send the result. A DNS reply is a channel of *bytes.Buffer, which
// will receive exactly one message.
//
// An industrial version would probably pass a context around too.
type dnsReply chan *bytes.Buffer
type dnsSend struct {
	ips   string
	reply dnsReply
}

// the promises slice is only used in the main thread.
type dnsCheckPool struct {
	requests chan dnsSend   // common channel for requests
	wg       sync.WaitGroup // signals all resolvers have exited
	promises []dnsReply     // accumulated replies (channels)
}

// checkIp is called from the main thread to initiate the check of one
// IP address. It submits the request to the pool and adds the reply
// channel to the promises slice.
func (d *dnsCheckPool) checkIp(ips string) {
	if d == nil {
		checkIp(ips, os.Stdout)
		return
	}
	// the reply channel must have a buffer so that resolvers never
	// block while writing answers to it.
	ds := dnsSend{
		ips:   ips,
		reply: make(dnsReply, 1),
	}
	d.requests <- ds
	d.promises = append(d.promises, ds.reply)
}

// resolver is run in N goroutines to read requests, perform DNS
// lookups, and send the reply to the reply channel. The reply channel
// must have a one-item buffer so that the resolver doesn't block in
// replying.
func (d *dnsCheckPool) resolver() {
	for ds := range d.requests {
		var b bytes.Buffer
		checkIp(ds.ips, &b)
		ds.reply <- &b
	}
}

// drain reads and prints the first N results, assuming that there are
// at least N available. It's intended to let you avoid having too many
// unprocessed results pile up.
func (d *dnsCheckPool) drain(num int) {
	if d == nil || len(d.promises) < num {
		return
	}
	for i := range d.promises[:num] {
		b := <-d.promises[i]
		_, _ = b.WriteTo(os.Stdout)
		close(d.promises[i])
	}
	d.promises = d.promises[num:]
}

// Finish a DNS check pool, reading and printing all results and
// closing down the resolver goroutines.
func (d *dnsCheckPool) finish() {
	if d == nil {
		return
	}
	// signal resolvers to exit but don't wait for them yet
	close(d.requests)
	// receive and print results, many of which will already be
	// ready (we hope).
	for i := range d.promises {
		b := <-d.promises[i]
		_, _ = b.WriteTo(os.Stdout)
		close(d.promises[i])
	}
	// help the garbage collector out.
	clear(d.promises)
	// wait for resolver goroutines to all signal completion.
	d.wg.Wait()
}

// newDnsCheckPool creates a new DNS IP resolution pool that is expected
// to handle (at least) 'size' entries.
func newDnsCheckPool(size int) *dnsCheckPool {
	if npar <= 1 {
		// no parallelism? arrange to call directly.
		return nil
	}
	var d = &dnsCheckPool{}
	// Requests are all submitted before any replies are printed,
	// so we'd like to not have that submission block. So size the
	// requests channel for our expected maximum capacity.
	d.requests = make(chan dnsSend, size)
	// Don't start extra goroutines if we have too few requests.
	for range min(npar, size) {
		d.wg.Add(1)
		go func() {
			d.resolver()
			d.wg.Done()
		}()
	}
	return d
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
	getopt.FlagLong(&npar, "parallel", 'n', "Perform this many DNS lookups in parallel.", "NUM")
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

	pl := newDnsCheckPool(max(len(args), npar))
	if len(args) > 0 {
		for _, ips := range args {
			//checkIp(ips, os.Stdout)
			pl.checkIp(ips)
		}
		pl.finish()
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			//checkIp(scanner.Text(), os.Stdout)
			pl.checkIp(scanner.Text())
			// Don't allow too many to build up.
			pl.drain(npar * 3)
		}
		pl.finish()
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: reading standard input: %s\n", os.Args[0], err)
		}
	}
}
