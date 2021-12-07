/*
 * Johan Stenstam
 */
package main

import (
	"fmt"
	"log"
	//	"net/http"
	"time"

	// "github.com/miekg/dns"
	"github.com/spf13/viper"

	music "github.com/DNSSEC-Provisioning/music/common"
)

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
	var fdop, udop music.DesecOp

	var fetchOpQueue []music.DesecOp
	var updateOpQueue []music.DesecOp

	go func() {
	   	var rl bool
		var err error
		var op music.DesecOp
		for {
			select {
			case op = <-desecfetch:
			     	 fetchOpQueue = append(fetchOpQueue, op)

			case <-fetch_ticker.C:
				fmt.Printf("%v: deSEC fetch_ticker: Total fetch ops last period: %d. Ops in queue: %d\n", time.Now(), fetch_ops, len(fetchOpQueue))
				fetch_ops = 0

				for _, fdop := range fetchOpQueue {
					fetch_ops++
					if fetch_ops > fetch_limit {
					   	fetchOpQueue = append(fetchOpQueue, fdop)
						break // the loop for this minute
					}
					// Do stuff
					fmt.Printf("deSEC fetch channel: %v\n", fdop)
					rl = false // "rate-limited"
					var hold int
					for {
					    rl, hold, err = music.RLDesecFetchRRset(fdop)
					    fmt.Printf("deSECMgr: rate-limited: %v hold: %d err: %v\n", rl, hold, err)
					    if !rl {
					       break
					    } else {
					      fmt.Printf("deSECMgr: fetch rate-limited. Will sleep for %d seconds\n", hold)
					      time.Sleep(time.Duration(hold))
					    }
					}
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
				fmt.Printf("%v: deSEC update_ticker: Total update ops: %d\n", time.Now(), update_ops)
				update_ops = 0
				for {
					udop = <-desecupdate
					update_ops++
					if update_ops > update_limit {
					   	updateOpQueue = append(updateOpQueue, fdop)
						break // the loop for this minute
					}
					// Do stuff
					fmt.Printf("deSEC update channel: %v\n", udop)
				}

			case <-done:
				update_ticker.Stop()
				log.Println("deSEC update ticker: stop signal received.")
			}
		}
	}()

}
