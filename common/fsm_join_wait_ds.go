package music

import (
    "log"
    "time"

    "github.com/miekg/dns"
)

var zoneWaitDs map[string]time.Time // Issue #34: using local store for now

func init() {
    zoneWaitDs = make(map[string]time.Time)
}

func fsmJoinWaitDsCriteria(z *Zone) bool {
    if until, ok := zoneWaitDs[z.Name]; ok {
        if time.Now().Before(until) {
            log.Printf("%s: Waiting until %s (%s)", z.Name, until.String(), time.Until(until).String())
            return false
        }
        log.Printf("%s: Waited enough for DS, critera fullfilled", z.Name)
        return true
    }

    log.Printf("%s: Fetching DNSKEYs and DSes to calculate DS wait until", z.Name)

    var ttl uint32

    for _, s := range z.sgroup.SignerMap {
        m := new(dns.Msg)
        m.SetQuestion(z.Name, dns.TypeDNSKEY)
        c := new(dns.Client)
        r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way
        if err != nil {
            log.Printf("%s: Unable to fetch DNSKEYs from %s: %s", z.Name, s.Name, err)
            return false
        }

        for _, a := range r.Answer {
            dnskey, ok := a.(*dns.DNSKEY)
            if !ok {
                continue
            }

            if dnskey.Header().Ttl > ttl {
                ttl = dnskey.Header().Ttl
            }
        }
    }

    parentAddress := "13.48.238.90:53" // Issue #33: using static IP address for msat1.catch22.se for now

    m := new(dns.Msg)
    m.SetQuestion(z.Name, dns.TypeDS)
    c := new(dns.Client)
    r, _, err := c.Exchange(m, parentAddress)
    if err != nil {
        log.Printf("%s: Unable to fetch DSes from parent: %s", z.Name, err)
        return false
    }

    for _, a := range r.Answer {
        ds, ok := a.(*dns.DS)
        if !ok {
            continue
        }

        if ds.Header().Ttl > ttl {
            ttl = ds.Header().Ttl
        }
    }

    // until := time.Now().Add((time.Duration(ttl*2) * time.Second))
    // TODO: static wait time to enable faster testing
    until := time.Now().Add((time.Duration(5) * time.Second))

    log.Printf("%s: Largest TTL found was %d, waiting until %s (%s)", z.Name, ttl, until.String(), time.Until(until).String())

    zoneWaitDs[z.Name] = until

    return false
}

func fsmJoinWaitDsAction(z *Zone) bool {
    log.Printf("%s: Fetch all NS records from all signers", z.Name)

    nses := make(map[string][]*dns.NS)

    for _, s := range z.sgroup.SignerMap {
        m := new(dns.Msg)
        m.SetQuestion(z.Name, dns.TypeNS)
        c := new(dns.Client)
        r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way
        if err != nil {
            log.Printf("%s: Unable to fetch NSes from %s: %s", z.Name, s.Name, err)
            return false
        }

        nses[s.Name] = []*dns.NS{}

        for _, a := range r.Answer {
            ns, ok := a.(*dns.NS)
            if !ok {
                continue
            }

            nses[s.Name] = append(nses[s.Name], ns)

            // TODO: Store NS origin if never seen before
        }
    }

    log.Printf("%s: Creating NS record sets", z.Name)

    // Map all known NSes
    nsmap := make(map[string]*dns.NS)
    for _, rrs := range nses {
        for _, rr := range rrs {
            nsmap[rr.Ns] = rr
        }
    }
    // Create RRset for insert
    nsset := []dns.RR{}
    for _, rr := range nsmap {
        nsset = append(nsset, rr)
    }

    // TODO: is this needed here also?
    //       Old code made sure the configured NS for each singer was added
    // for _, signer := range signers {
    //     ns := Config.Get("signer-ns:"+signer, "")
    //     if ns == "" {
    //         continue
    //     }
    //     if _, ok := nsmap[ns]; !ok {
    //         rr := new(dns.NS)
    //         rr.Hdr = dns.RR_Header{Name: args[0], Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(ttl)}
    //         rr.Ns = ns
    //         nsset = append(nsset, rr)
    //     }
    // }

    for _, signer := range z.sgroup.SignerMap {
        updater := GetUpdater(signer.Method)
        if err := updater.Update(&signer, z.Name, &[][]dns.RR{nsset}, nil); err != nil {
            log.Printf("%s: Unable to update %s with NS record sets: %s", z.Name, signer.Name, err)
            return false
        }
        log.Printf("%s: Update %s successfully with NS record sets", z.Name, signer.Name)
    }

    z.StateTransition(FsmStateParentDsSynced, FsmStateDsPropagated)
    return true
}

var FsmJoinWaitDs = FSMTransition{
    Description: "Wait enough time for parent DS records to propagate (criteria), then sync NS records between all signers (action)",
    Criteria:    fsmJoinWaitDsCriteria,
    Action:      fsmJoinWaitDsAction,
}
