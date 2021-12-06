/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type RLDesecUpdater struct {
     FetchCh	    chan DesecOp
     UpdateCh	    chan DesecOp
     Api	    Api
}

func init() {
	Updaters["rldesec-api"] = &RLDesecUpdater{
					Api:	Api{},
				   }
}

func (u *RLDesecUpdater) SetChannels(fetch, update chan DesecOp) {
     u.FetchCh = fetch
     u.UpdateCh = update
}

func (u *RLDesecUpdater) SetApi(api Api) {
     u.Api = api
}

func (u *RLDesecUpdater) GetApi() Api {
     return u.Api
}

func (u *RLDesecUpdater) FetchRRset(s *Signer, zone, owner string,
	rrtype uint16) (error, []dns.RR) {

	// what we want:
	op := DesecOp{
			Signer:	s,
			Zone:	zone,
			Owner:	owner,
			RRtype:	rrtype,
			Response: make(chan DesecResponse),
	}
	u.FetchCh <- op
	time.Sleep(1 * time.Second)
	resp := <- op.Response
	return resp.Error, resp.RRs
	// return nil, []dns.RR{} // no-op
}

// Returns: rrl=true if reate-limited, int=seconds penalty (now testing with status),
//          error (if any), []dns.RR data
func RLDesecFetchRRset(s *Signer, zone, owner string,
			rrtype uint16) (bool, int, error, []dns.RR) {
	mdb := s.MusicDB()
	tokvip := mdb.Tokvip
	verbose := viper.GetBool("common.verbose")
	// log.Printf("FetchRRset: looking up '%s IN %s' from %s\n", owner,
	//    dns.TypeToString[rrtype], s.Address)

	zone = StripDot(zone)
	owner = StripDot(owner)

	endpoint := fmt.Sprintf("/domains/%s/rrsets/%s/%s/", 
		      		  zone, DesecSubname(zone, owner, true),
				  dns.TypeToString[rrtype])

	DesecTokenRefreshIfNeeded(tokvip)

	// apiurl := viper.GetString("signers.desec.baseurl") + endpoint
	apikey := tokvip.GetString("desec.token")
	tokvip.Set("desec.touched", time.Now().Format(layout))
	// Let's not do this every time:
	// tokvip.WriteConfig()

	fmt.Printf("FetchRRset: deSEC API endpoint: %s. token: %s\n", endpoint, apikey)

	// temporary kludge
	api := GetUpdater("rldesec-api").GetApi()

//	status, buf, err := GenericAPIget(apiurl, apikey, "Authorization",
//		true, verbose, debug, nil)
	status, buf, err := api.Get(endpoint)

	if status == 429 { // we have been rate-limited
	   fmt.Printf("desec.FetchRRset: rate-limit. This is what we got: '%v'. Retry in %d seconds.\n", string(buf), 10)
	   return true, status, nil, []dns.RR{}
	}

	if err != nil {
		log.Printf("Error from api.Get (desec): %v\n", err)
		return false, status, fmt.Errorf("Error from deSEC API for %s: %v",
		       endpoint, err), []dns.RR{}
	}

	fmt.Printf("FetchRRset: got a response from deSEC:\n%v\n", string(buf))
	if verbose {
		fmt.Printf("FetchRRset: status: %d\n", status)
	}

	var dr DesecResponseRRset
	err = json.Unmarshal(buf, &dr)
	if err != nil {
		log.Fatalf("FetchRRset: Error from unmarshal: %v\n", err)
	}

	var rrs []dns.RR

	for _, r := range dr.RData {
		rrstr := fmt.Sprintf("%s %d IN %s %s", dr.Name, dr.TTL, dr.RRtype, r)
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			return false, status, 
			       fmt.Errorf("FetchRRset: Error parsing RR into dns.RR: %v\n",
			       			       err), []dns.RR{}
		}
		rrs = append(rrs, rr)
	}

	mdb.WriteRRs(s, dns.Fqdn(owner), zone, rrtype, rrs)
	return false, status, nil, DNSFilterRRsetOnType(rrs, rrtype)
}

func (u *RLDesecUpdater) Update(signer *Signer, zone, owner string, 
     		       		     inserts, removes *[][]dns.RR) error {
	mdb := signer.MusicDB()
	tokvip := mdb.Tokvip
	// address := signer.Address
	verbose := viper.GetBool("common.verbose")
	// debug := viper.GetBool("common.debug")

	zone = StripDot(zone)
	fmt.Printf("DesecUpdater: inserts: %v removes: %v\n", inserts, removes)

	DesecTokenRefreshIfNeeded(tokvip)
	endpoint := fmt.Sprintf("/domains/%s/rrsets/", zone)
	//endpoint := fmt.Sprintf("/domains/%s/rrsets/%s/%s/", 
	//	      		  zone, DesecSubname(zone, owner, true),
	//			  dns.TypeToString[rrtype])

	// apiurl := viper.GetString("signers.desec.baseurl") + endpoint
	apikey := tokvip.GetString("desec.token")
	tokvip.Set("desec.touched", time.Now().Format(layout))

	desecRRsets := []DesecRRset{}

	if inserts != nil {
	for _, rrset := range *inserts {
		if len(rrset) == 0 {
			continue
		}

		desecRRset, err := CreateDesecRRset(zone, owner, rrset, false)
		if err != nil {
			log.Printf("Error from DesecCreateRRset: %v\n", err)
		} else {
			desecRRsets = append(desecRRsets, desecRRset)
		}
	}
	}

	if removes != nil {
	for _, rrset := range *removes {
		if len(rrset) == 0 {
			continue
		}

		desecRRset, err := CreateDesecRRset(zone, owner, rrset, true)
		if err != nil {
			log.Printf("Error from DesecCreateRRset: %v\n", err)
		} else {
			desecRRsets = append(desecRRsets, desecRRset)
		}
	}
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(desecRRsets)

	fmt.Printf("DesecUpdater: deSEC API endpoint: %s. token: %s Data: %v\n",
		endpoint, apikey, desecRRsets)

	api := GetUpdater("rldesec-api").GetApi()

//	status, buf, err := GenericAPIput(apiurl, apikey, "Authorization",
//		bytebuf.Bytes(), true, verbose, debug, nil)
	status, buf, err := api.Put(endpoint, bytebuf.Bytes())
	if err != nil {
		log.Printf("Error from api.Post (desec): %v\n", err)
		return fmt.Errorf("Error from deSEC API for %s: %v",
			endpoint, err)
	}

	if verbose {
		fmt.Printf("DesecUpdateRRset: status: %d\n", status)
	}

	fmt.Printf("DesecUpdateRRset: buf: %v\n", string(buf))
	return nil
}

func (u *RLDesecUpdater) RemoveRRset(signer *Signer, zone, owner string, rrsets [][]dns.RR) error {

	fmt.Printf("Desec RemoveRRset: rrsets: %v\n", rrsets)
	return u.Update(signer, zone, owner, &[][]dns.RR{}, &rrsets)
}


