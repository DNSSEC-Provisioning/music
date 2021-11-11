package music

import (
    "fmt"
    "log"

    "github.com/miekg/dns"
)

func fsmJoinParentDsSyncedCriteria(z *Zone) bool {
    cdses := make(map[string][]*dns.CDS)

    log.Printf("Verifying that DSes in %s's parent are up to date compared to signers CDSes", z.Name)

    for _, s := range z.sgroup.SignerMap {
        m := new(dns.Msg)
        m.SetQuestion(z.Name, dns.TypeCDS)

        c := new(dns.Client)
        r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way

        if err != nil {
            log.Printf("%s: Unable to fetch CDSes from %s: %s", z.Name, s.Name, err)
            return false
        }

        cdses[s.Name] = []*dns.CDS{}
        for _, a := range r.Answer {
            cds, ok := a.(*dns.CDS)
            if !ok {
                continue
            }

            log.Printf("%s: Signer %s CDS found: %d %d %d %s", z.Name, s.Name, cds.KeyTag, cds.Algorithm, cds.DigestType, cds.Digest)
            cdses[s.Name] = append(cdses[s.Name], cds)
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
    dses := []*dns.DS{}
    removedses := make(map[string]*dns.DS)
    for _, a := range r.Answer {
        ds, ok := a.(*dns.DS)
        if !ok {
            continue
        }

        log.Printf("%s: Parent DS found: %d %d %d %s", z.Name, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
        dses = append(dses, ds)
    }

    parent_up_to_date := true

    cdsmap := make(map[string]*dns.CDS)
    for _, keys := range cdses {
        for _, key := range keys {
            cdsmap[fmt.Sprintf("%d %d %d %s", key.KeyTag, key.Algorithm, key.DigestType, key.Digest)] = key
            delete(removedses, fmt.Sprintf("%d %d %d %s", key.KeyTag, key.Algorithm, key.DigestType, key.Digest))
        }
    }
    for _, ds := range dses {
        delete(cdsmap, fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest))
    }
    for _, cds := range cdsmap {
        log.Printf("%s: Missing DS for CDS: %d %d %d %s", z.Name, cds.KeyTag, cds.Algorithm, cds.DigestType, cds.Digest)
        parent_up_to_date = false
    }
    for _, ds := range removedses {
        log.Printf("%s: Unknown DS: %d %d %d %s", z.Name, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
        parent_up_to_date = false // TODO: should unknown DS be allowed?
    }

    if !parent_up_to_date {
        return false
    }

    log.Printf("%s: Parent is up-to-date with it's DS records", z.Name)
    return true
}

func fsmJoinParentDsSyncedAction(z *Zone) bool {
    log.Printf("%s: Removing CDS/CDNSKEY record sets", z.Name)

    cds := new(dns.CDS)
    cds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 0}

    ccds := new(dns.CDNSKEY)
    ccds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDNSKEY, Class: dns.ClassINET, Ttl: 0}

    for _, signer := range z.sgroup.SignerMap {
        updater := GetUpdater(signer.Method)
        if err := updater.RemoveRRset(&signer, z.Name, [][]dns.RR{[]dns.RR{cds}, []dns.RR{ccds}}); err != nil {
            log.Printf("%s: Unable to remove CDS/CDNSKEY record sets from %s: %s", z.Name, signer.Name, err)
            return false
        }
        log.Printf("%s: Removed CDS/CDNSKEY record sets from %s successfully", z.Name, signer.Name)
    }

    z.StateTransition(FsmStateCdscdnskeysAdded, FsmStateParentDsSynced)
    return true
}

var FsmJoinParentDsSynced = FSMTransition{
    Description: "Wait for parent to pick up CDS/CDNSKEYs and update it's DS (criteria), then remove CDS/CDNSKEYs from all signers (action)",
    Criteria:    fsmJoinParentDsSyncedCriteria,
    Action:      fsmJoinParentDsSyncedAction,
}
