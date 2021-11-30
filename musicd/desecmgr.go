/*
 * Johan Stenstam
 */
package main

import (
	"fmt"
	"log"
	//	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	music "github.com/DNSSEC-Provisioning/music/common"
)

type DesecOp struct {
	Command  string
	Signer   *music.Signer
	Zone     string
	Owner    string
	RRtype   uint16
	Inserts  *[][]dns.RR
	Removes  *[][]dns.RR
	Response chan DesecResponse
}

type DesecResponse struct {
	Status   int
	RRs      []dns.RR
	Error    error
	Response string
}

// According to https://desec.readthedocs.io/en/latest/rate-limits.html
// these are the rate limits we have to plan for:
// dns_api_read: 10/s, 50/min
// dns_api_write_domain: 10/s, 300/min, 1000/h
// dns_api_write_rrsets: 2/s, 15/min, 30/h, 300/day

func deSECmgr(conf *Config, done <-chan struct{}) {

	desecfetch := conf.Internal.DesecFetch
	desecupdate := conf.Internal.DesecUpdate

	// we use the limit per minute
	var fetch_limit = viper.GetInt("signers.desec.limits.fetch")   // per second
	var update_limit = viper.GetInt("signers.desec.limits.update") // per second

	if fetch_limit == 0 {
		log.Fatalf("Error: signers.desec.limits.fetch must be defined and > 0. Likely value: 5 (op/s).")
	}
	if update_limit == 0 {
		log.Fatalf("Error: signers.desec.limits.update must be defined and > 0. Likely value: 2 (op/s).")
	}

	log.Println("Starting deSEC Manager. Will rate-limit deSEC API requests.")

	// use our own http client, with custom timeouts
	//	client := &http.Client{
	//		// CheckRedirect: redirectPolicyFunc,
	//		Timeout: 5 * time.Second, // should be smaller
	//	}

	fetch_ticker := time.NewTicker(time.Minute)
	update_ticker := time.NewTicker(time.Minute)

	var fetch_ops, update_ops int
	var fdop, udop DesecOp

	go func() {
		var status int
		var rrs []dns.RR
		var err error
		for {
			select {
			case <-fetch_ticker.C:
				fmt.Printf("%v: This is the fetch_ticker executing.\n", time.Now())
				fetch_ops = 0
				for {
					fdop = <-desecfetch
					fetch_ops++
					if fetch_ops > fetch_limit {
						break
					}
					// Do stuff
					fmt.Printf("Fetch channel: %v\n", fdop)
					status, err, rrs = music.DesecBFetchRRset(fdop.Signer,
						fdop.Zone, fdop.Owner, fdop.RRtype)
					fmt.Printf("DesecMgr: status: %d err: %v rrs: %v\n", status, err, rrs)
				}

			case <-done:
				fetch_ticker.Stop()
				log.Println("deSEC fetch ticker: stop signal received.")
			}
		}
	}()

	go func() {
		for {
			select {
			case <-update_ticker.C:
				fmt.Printf("%v: This is the update_ticker executing.\n", time.Now())
				update_ops = 0
				for {
					udop = <-desecupdate
					update_ops++
					if update_ops > update_limit {
						break
					}
					// Do stuff
					fmt.Printf("Update channel: %v\n", udop)
				}

			case <-done:
				update_ticker.Stop()
				log.Println("deSEC update ticker: stop signal received.")
			}
		}
	}()

}
