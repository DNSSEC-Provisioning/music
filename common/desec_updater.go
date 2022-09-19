/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	// "time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type DesecUpdater struct {
	Api Api
}

func init() {
	Updaters["desec-api"] = &DesecUpdater{}
}

func (u *DesecUpdater) SetChannels(fetch, update chan SignerOp) {
	// no-op
}

func (u *DesecUpdater) SetApi(api Api) {
	u.Api = api
}

func (u *DesecUpdater) GetApi() Api {
	return u.Api
}

func DesecSubname(zone, owner string, urluse bool) string {
	newowner := owner
	if strings.HasSuffix(owner, zone) {
		if len(owner) > (len(zone) + 1) {
			newowner = owner[:len(owner)-len(zone)-1]
		} else if len(owner) == len(zone) {
			if urluse {
				newowner = "@"
			} else {
				newowner = ""
			}
		}
		//fmt.Printf("DesecSubname: removing zone %s from owner name %s returning '%s'\n",
		// zone, owner, newowner)
		// owner = strings.TrimSuffix(owner, zone)
	}

	return newowner
}

func (u *DesecUpdater) FetchRRset(s *Signer, zone, owner string,
	rrtype uint16) (error, []dns.RR) {

	mdb := s.MusicDB()
	verbose := viper.GetBool("common.verbose")

	zone = StripDot(zone)
	owner = StripDot(owner)

	/* we need to differentiate if it is a DNSKEY record we want. deSEC does not allow
	access to the DNSKEYS through the rrsets endpoint
	*/
	rrType := dns.TypeToString[rrtype]
	var endpoint string
	if rrType == "DNSKEY" {
		fmt.Printf("FetchRRSET: rrtype is DNSKEY, use the DOMAIN endpoint\n")
		endpoint = fmt.Sprintf("/domains/%s/", zone)
		fmt.Printf("FetchRRset: deSEC API url: %s.\n", endpoint)
	} else {
		fmt.Printf("rrtype is %s\n, use the RRSET endpoint", rrType)
		endpoint = fmt.Sprintf("/domains/%s/rrsets/%s/%s/",
			zone, DesecSubname(zone, owner, true), rrType)
		fmt.Printf("FetchRRset: deSEC API url: %s.\n", endpoint)
	}
	//apikey := tokvip.GetString("desec.token")

	api := GetUpdater("desec-api").GetApi() // kludge
	api.DesecTokenRefresh()

	status, buf, err := api.Get(endpoint)
	if status == 429 { // we have been rate-limited
		fmt.Printf("desec.FetchRRset: rate-limit. This is what we got: '%v'. Retry in %d seconds.\n", string(buf), 10)
		return nil, []dns.RR{}
	}

	if err != nil {
		log.Printf("Error from GenericAPIget (desec): %v\n", err)
		return fmt.Errorf("Error from deSEC API for %s: %v", endpoint, err),
			[]dns.RR{}
	}

	fmt.Printf("FetchRRset: got a response from deSEC:\n%v\n", string(buf))
	if verbose {
		fmt.Printf("FetchRRset: status: %d\n", status)
	}

	/* the return data is handled differently dependent on the rrset type DNSKEY needs special handling
	 */
	if rrType == "DNSKEY" {
		var dr DesecDomain
		err = json.Unmarshal(buf, &dr)
		if err != nil {
			log.Fatal("FetchRRset: Error from unmarshal: %v\n", err)
		}
		var rrs []dns.RR

		for _, r := range dr.Keys {
			rrstr := fmt.Sprintf("%s %d IN %s %s", dr.Name, dr.MinimumTTL, rrType, r.DNSKEY)
			fmt.Println("#######################################################")
			fmt.Printf("FetchRRset: Received following DNSKEYS: %s\n", rrstr)
			fmt.Println("#######################################################")
			rr, err := dns.NewRR(rrstr)
			if err != nil {
				return fmt.Errorf("FetchRRset: Error parsing Domain into dns.RR.: %v\n", err), []dns.RR{}
			}
			rrs = append(rrs, rr)
		}

		//fmt.Printf(" -signer: %v\n -fqdn: %s\n -zone: %s\n -rrtype: %d\n -rrs: %s\n", s, dns.Fqdn(owner), zone, rrtype, rrs) // debug code
		mdb.WriteRRs(s, dns.Fqdn(owner), zone, rrtype, rrs)
		return nil, DNSFilterRRsetOnType(rrs, rrtype)

	} else {
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
				return fmt.Errorf("FetchRRset: Error parsing RR into dns.RR: %v\n",
					err), []dns.RR{}
			}
			rrs = append(rrs, rr)
		}

		mdb.WriteRRs(s, dns.Fqdn(owner), zone, rrtype, rrs)
		return nil, DNSFilterRRsetOnType(rrs, rrtype)
	}
}

type DesecRRset struct {
	// Domain    string     `json:"domain"`
	Subname string   `json:"subname"`
	RRtype  string   `json:"type"`
	TTL     int      `json:"ttl"`
	RData   []string `json:"records"`
}

type DesecResponseRRset struct {
	Created string   `json:"created"`
	Touched string   `json:"touched"`
	Domain  string   `json:"domain"`
	Subname string   `json:"subname"`
	Name    string   `json:"name"`
	RRtype  string   `json:"type"`
	TTL     int      `json:"ttl"`
	RData   []string `json:"records"`
}

type Key struct {
	DNSKEY  string
	DS      []string
	MANAGED bool
}

type DesecDomain struct {
	Created    time.Time `json:"created,omitempty"`
	Keys       []Key     `json:"keys,omitempty"`
	MinimumTTL int       `json:"minimum_ttl,omitempty"`
	Name       string    `json:"name,omitempty"`
	Published  time.Time `json:"published,omitempty"`
	Touched    time.Time `json:"touched,omitempty"`
}

func DesecBuildRData(rrs []dns.RR) (error, []string) {
	var parts, rdata []string
	for _, r := range rrs {
		parts = strings.Split(r.String(), "\t")

		if len(parts) < 5 {
			return errors.New(fmt.Sprintf("DesecBuildRData: danger: parts: %v\n", parts)),
				[]string{}
		}
		parts = parts[4:]
		rdata = append(rdata, strings.Join(parts, " "))
	}
	return nil, rdata
}

// XXX: not used anymore, should die
/*
func DesecUpdateRRset(s *Signer, zone, owner string, rrtype uint16, rrs []dns.RR) (error, string) {
	verbose := viper.GetBool("common.verbose")

	// log.Printf("DesecUpdateRRset: sending update of RRset '%s IN %s' to %s\n", owner,
	//    dns.TypeToString[rrtype], s.Address)

	endpoint := fmt.Sprintf("/domains/%s/rrsets/", zone)

	err, rdata := DesecBuildRData(rrs)
	if err != nil {
		fmt.Printf("Error from DesecBuildRData: %v\n", err)
	}

	rrType := dns.TypeToString[rrtype]
	data := DesecRRset{}

	if rrType == "DNSKEY" || rrType == "CDS" || rrType == "CDNSKEY" || rrType == "CSYNC" {
		data = DesecRRset{
			RRtype: dns.TypeToString[rrtype],
			TTL:    3600,
			RData:  rdata,
		}
	} else {
		data = DesecRRset{
			Subname: DesecSubname(zone, owner, false),
			RRtype:  dns.TypeToString[rrtype],
			TTL:     3600,
			RData:   rdata,
		}
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	api := GetUpdater("desec-api").GetApi()
	api.DesecTokenRefresh()
	fmt.Printf("DesecUpdateRRset: deSEC API endpoint: %s. token: %s Data: %v\n",
		endpoint, api.apiKey, data)

	status, buf, err := api.Post(endpoint, bytebuf.Bytes())
	if status == 429 { // we have been rate-limited
		fmt.Printf("desec.UpdateRRset: rate-limit. This is what we got: '%v'. Retry in %d seconds.\n", string(buf), 10)
	}

	if err != nil {
		log.Printf("Error from GenericAPIpost (desec): %v\n", err)
		return fmt.Errorf("Error from deSEC API for %s: %v", endpoint, err), ""
	}

	if verbose {
		fmt.Printf("DesecUpdateRRset: status: %d\n", status)
	}

	fmt.Printf("DesecUpdateRRset: buf: %v\n", string(buf))
	return nil, ""
}
*/

func (u *DesecUpdater) Update(signer *Signer, zone, owner string,
	inserts, removes *[][]dns.RR) error {
	verbose := viper.GetBool("common.verbose")

	zone = StripDot(zone)
	fmt.Printf("DesecUpdater: inserts: %v removes: %v\n", inserts, removes)

	endpoint := fmt.Sprintf("/domains/%s/rrsets/", zone)
	// endpoint := fmt.Sprintf("/domains/%s/rrsets/%s/%s/",
	//	      		  zone, DesecSubname(zone, owner, true),
	//			  dns.TypeToString[rrtype])

	desecRRsets := []DesecRRset{}

	if inserts != nil {
		for _, rrset := range *inserts {
			fmt.Printf("instert this stuff")
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

	api := GetUpdater("desec-api").GetApi()
	api.DesecTokenRefresh()
	fmt.Printf("DesecUpdater: deSEC API url: %s. token: %s Data: %v\n",
		endpoint, api.apiKey, desecRRsets)

	status, buf, err := api.Put(endpoint, bytebuf.Bytes())
	if err != nil {
		log.Printf("Error from GenericAPIpost (desec): %v\n", err)
		return fmt.Errorf("Error from deSEC API for %s: %v",
			endpoint, err)
	}

	if verbose {
		fmt.Printf("DesecUpdater.update: status: %d\n", status)
	}

	fmt.Printf("DesecUpdate.update: buf: %v\n", string(buf))
	return nil
}

func (u *DesecUpdater) RemoveRRset(signer *Signer, zone, owner string, rrsets [][]dns.RR) error {

	fmt.Printf("Desec RemoveRRset: rrsets: %v\n", rrsets)
	return u.Update(signer, zone, owner, &[][]dns.RR{}, &rrsets)
}

func CreateDesecRRset(zone, owner string,
	rrset []dns.RR, remove bool) (DesecRRset, error) {
	var rdata []string
	var err error
	subname := "" // most common case
	if owner != zone {
		subname = DesecSubname(zone, owner, false)
	}

	rr := rrset[0]
	rrtype := rr.Header().Rrtype

	if remove {
		rdata = []string{}
	} else {
		err, rdata = DesecBuildRData(rrset)
		if err != nil {
			log.Printf("Error from DesecBuildRData: %v\n", err)
			return DesecRRset{}, err
		}
	}

	log.Printf("CreateDesecRRset: creating update of RRset '%s IN %s\n",
		owner, dns.TypeToString[rrtype])

	rrType := dns.TypeToString[rrtype]
	data := DesecRRset{}

	if rrType == "DNSKEY" || rrType == "CDS" || rrType == "CDNSKEY" || rrType == "CSYNC" || rrType == "NS" {
		data = DesecRRset{
			RRtype: dns.TypeToString[rrtype],
			TTL:    3600,
			RData:  rdata,
		}
		fmt.Printf("###### dis is our data %v\n", data)
	} else {
		data = DesecRRset{
			Subname: subname,
			RRtype:  dns.TypeToString[rrtype],
			TTL:     3600,
			RData:   rdata,
		}
	}

	fmt.Printf("CreateDesecRRset: data: %v\n", data)

	return data, nil
}
