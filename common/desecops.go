/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "strings"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "github.com/miekg/dns"
    "github.com/spf13/viper"
)

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

func DesecRetrieveRRset(s *Signer, zone, owner string, rrtype uint16) (error, []dns.RR) {
    mdb := s.MusicDB()
    tokvip := mdb.Tokvip
    verbose := viper.GetBool("common.verbose")
    debug := viper.GetBool("common.debug")
    // log.Printf("DesecRetrieveRRset: looking up '%s IN %s' from %s\n", owner,
    //    dns.TypeToString[rrtype], s.Address)

    urldetails := fmt.Sprintf("/domains/%s/rrsets/%s/%s/", zone, DesecSubname(zone, owner, true),
        dns.TypeToString[rrtype])

    DesecTokenRefreshIfNeeded(tokvip)

    apiurl := viper.GetString("signers.desec.baseurl") + urldetails
    apikey := tokvip.GetString("desec.token")
    tokvip.Set("desec.touched", time.Now().Format(layout))
    // Let's not do this every time:
    // tokvip.WriteConfig()

    fmt.Printf("DesecRetrieveRRset: deSEC API url: %s. token: %s\n", apiurl, apikey)

    status, buf, err := GenericAPIget(apiurl, apikey, "Authorization",
        true, verbose, debug, nil)
    if err != nil {
        log.Printf("Error from GenericAPIget (desec): %v\n", err)
        return errors.New(fmt.Sprintf("Error from deSEC API for %s: %v", urldetails, err)),
            []dns.RR{}
    }

    fmt.Printf("DesecRetrieveRRset: got a response from Desec:\n%v\n", string(buf))
    if verbose {
        fmt.Printf("DesecRetrieveRRset: status: %d\n", status)
    }

    var dr DesecResponseRRset
    err = json.Unmarshal(buf, &dr)
    if err != nil {
        log.Fatalf("DesecRetrieveRRset: Error from unmarshal: %v\n", err)
    }

    var rrs []dns.RR

    for _, r := range dr.RData {
        rrstr := fmt.Sprintf("%s %d IN %s %s", dr.Name, dr.TTL, dr.RRtype, r)
        rr, err := dns.NewRR(rrstr)
        if err != nil {
            return errors.New(fmt.Sprintf("DesecRetrieveRRset: Error parsing RR into dns.RR: %v\n",
                err)), []dns.RR{}
        }
        rrs = append(rrs, rr)
    }

    mdb.WriteRRs(s, dns.Fqdn(owner), zone, rrtype, rrs)
    return nil, DNSFilterRRsetOnType(rrs, rrtype)
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

func DesecUpdateRRset(s *Signer, zone, owner string, rrtype uint16, rrs []dns.RR) (error, string) {
    mdb := s.MusicDB()
    tokvip := mdb.Tokvip
    // address := s.Address
    verbose := viper.GetBool("common.verbose")
    debug := viper.GetBool("common.debug")

    // log.Printf("DesecUpdateRRset: sending update of RRset '%s IN %s' to %s\n", owner,
    //    dns.TypeToString[rrtype], s.Address)

    urldetails := fmt.Sprintf("/domains/%s/rrsets/", zone)

    DesecTokenRefreshIfNeeded(tokvip)

    apiurl := viper.GetString("signers.desec.baseurl") + urldetails
    apikey := tokvip.GetString("desec.token")
    tokvip.Set("desec.touched", time.Now().Format(layout))

    err, rdata := DesecBuildRData(rrs)
    if err != nil {
        fmt.Printf("Error from DesecBuildRData: %v\n", err)
    }

    data := DesecRRset{
        Subname: DesecSubname(zone, owner, false),
        RRtype:  dns.TypeToString[rrtype],
        TTL:     3600,
        RData:   rdata,
    }

    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    fmt.Printf("DesecUpdateRRset: deSEC API url: %s. token: %s Data: %v\n", apiurl, apikey, data)

    status, buf, err := GenericAPIpost(apiurl, apikey, "Authorization", bytebuf.Bytes(),
        true, verbose, debug, nil)
    if err != nil {
        log.Printf("Error from GenericAPIpost (desec): %v\n", err)
        return errors.New(fmt.Sprintf("Error from deSEC API for %s: %v", urldetails, err)), ""
    }

    if verbose {
        fmt.Printf("DesecUpdateRRset: status: %d\n", status)
    }

    fmt.Printf("DesecUpdateRRset: buf: %v\n", string(buf))
    return nil, ""
}
