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

// According to https://desec.readthedocs.io/en/latest/rate-limits.html
// these are the rate limits we have to plan for:
// dns_api_read: 10/s, 50/min
// dns_api_write_domain: 10/s, 300/min, 1000/h
// dns_api_write_rrsets: 2/s, 15/min, 30/h, 300/day

func ddnsmgr(conf *Config, done <-chan struct{}) {

	ddnsfetch := conf.Internal.DdnsFetch
	ddnsupdate := conf.Internal.DdnsUpdate

	// we use the limit per minute
	var fetch_limit = viper.GetInt("signers.ddns.limits.fetch")   // per second
	var update_limit = viper.GetInt("signers.ddns.limits.update") // per second

	if fetch_limit == 0 {
		log.Fatalf("Error: signers.ddns.limits.fetch must be defined and > 0. Likely value: 5 (op/s).")
	}
	if update_limit == 0 {
		log.Fatalf("Error: signers.ddns.limits.update must be defined and > 0. Likely value: 2 (op/s).")
	}

	log.Println("Starting DDNS Manager. Will rate-limit DDNS requests (queries and updates).")

	// fetch_ticker := time.NewTicker(time.Minute)
	fetch_ticker := time.NewTicker(5 * time.Second)
	update_ticker := time.NewTicker(time.Minute)

	var fetch_ops, update_ops int
	var fdop, udop music.DesecOp

	var fetchOpQueue []music.DesecOp
	var updateOpQueue []music.DesecOp

	go func() {
	   	var rl bool
		var err error
		var op music.DesecOp
		for {
			select {
			case op = <-ddnsfetch:
			     	 fetchOpQueue = append(fetchOpQueue, op)
				 fmt.Printf("ddnsmgr: request for '%s %s' (length of fetch channel: %d)\n", op.Owner, dns.TypeToString[op.RRtype], len(ddnsfetch))

			case <-fetch_ticker.C:
				fmt.Printf("%v: DDNS fetch_ticker: Total fetch ops last period: %d. Ops in queue: %d\n", time.Now(), fetch_ops, len(fetchOpQueue))
				fetch_ops = 0

				for _, fdop = range fetchOpQueue {
					// Do stuff
					fmt.Printf("ddnsmgr: about to issue fetch for '%s %s'\n", fdop.Owner, dns.TypeToString[fdop.RRtype])
					rl = false // "rate-limited"
					var hold int
					for {
					    rl, hold, err = music.RLDdnsFetchRRset(fdop)
					    fmt.Printf("ddnsmgr: response from RLDdnsFetchRRset: rl: %v hold: %d err: %v\n", rl, hold, err)
					    if !rl {
					       fmt.Printf("ddnsmgr: all ok, done with this request\n")
					       break
					    } else {
					      fmt.Printf("ddnsmgr: fetch was rate-limited. Will sleep for %d seconds\n", hold)
					      time.Sleep(time.Duration(hold))
					    }
					}
					fetch_ops++
					if fetch_ops > fetch_limit {
						break // the loop for this minute
					}

				}

			case <-done:
				fetch_ticker.Stop()
				log.Println("DDNS Mgr fetch ticker: stop signal received.")
			}
		}
	}()

	go func() {
	   	var rl bool
		var err error
		var op music.DesecOp
		for {
			select {
			case op = <-ddnsupdate:
			     	 updateOpQueue = append(updateOpQueue, op)

			case <-update_ticker.C:
				fmt.Printf("%v: DDNS update_ticker: Total fetch ops last period: %d. Ops in queue: %d\n", time.Now(), update_ops, len(updateOpQueue))
				update_ops = 0

				for _, udop = range updateOpQueue {
					update_ops++
					if update_ops > fetch_limit {
					   	updateOpQueue = append(updateOpQueue,
									udop)
						break // the loop for this minute
					}
					// Do stuff
					fmt.Printf("DDNS Update channel: %v\n", udop)
					rl = false // "rate-limited"
					var hold int
					for {
					    rl, hold, err = music.RLDdnsUpdate(udop)
					    fmt.Printf("DDNS Mgr: rate-limited: %v hold: %d err: %v\n", rl, hold, err)
					    if !rl {
					       break
					    } else {
					      fmt.Printf("DDNS Mgr: update rate-limited. Will sleep for %d seconds\n", hold)
					      time.Sleep(time.Duration(hold))
					    }
					}
				}

			case <-done:
				update_ticker.Stop()
				log.Println("DDNS Mgr update ticker: stop signal received.")
			}
		}
	}()

}
