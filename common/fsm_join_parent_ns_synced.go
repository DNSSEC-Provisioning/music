package music

import (
    "log"

    "github.com/miekg/dns"
)

func fsmJoinParentNsSyncedCriteria(z *Zone) bool {
    nses := make(map[string][]*dns.NS)

    log.Printf("%s: Verifying that NSes are in sync in the parent", z.Name)

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
        }
    }

    // Map all known NSes
    nsmap := make(map[string]*dns.NS)
    for _, rrs := range nses {
        for _, rr := range rrs {
            nsmap[rr.Ns] = rr
        }
    }

    parentAddress := "13.48.238.90:53" // Issue #33: using static IP address for msat1.catch22.se for now

    m := new(dns.Msg)
    m.SetQuestion(z.Name, dns.TypeNS)
    c := new(dns.Client)
    r, _, err := c.Exchange(m, parentAddress)
    if err != nil {
        log.Printf("%s: Unable to fetch NSes from parent: %s", z.Name, err)
        return false
    }

    for _, a := range r.Ns {
        ns, ok := a.(*dns.NS)
        if !ok {
            continue
        }

        delete(nsmap, ns.Ns)
    }

    if len(nsmap) > 0 {
        for ns, _ := range nsmap {
            log.Printf("%s: Missing NS %s in parent", z.Name, ns)
        }
        return false
    }

    log.Printf("%s: Parent NSes are up-to-date", z.Name)
    return true
}

func fsmJoinParentNsSyncedAction(z *Zone) bool {
    log.Printf("%s: Removing CSYNC record sets", z.Name)

    csync := new(dns.CSYNC)
    csync.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 0}

    for _, signer := range z.sgroup.SignerMap {
        updater := GetUpdater(signer.Method)
        if err := updater.RemoveRRset(signer, z.Name, [][]dns.RR{[]dns.RR{csync}}); err != nil {
            log.Printf("%s: Unable to remove CSYNC record sets from %s: %s", z.Name, signer.Name, err)
            return false
        }
        log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, signer.Name)
    }

    z.StateTransition(FsmStateCsyncAdded, FsmStateParentNsSynced)
    return true
}

var FsmJoinParentNsSynced = FSMTransition{
    Description:         "Wait for parent to pick up CSYNC and update it's NS records (criteria), then remove CSYNC from all signers and STOP (action)",
    MermaidCriteriaDesc: "Wait for parent to update NS RRset",
    MermaidActionDesc:   "Remove CSYNC RR",
    Criteria:            fsmJoinParentNsSyncedCriteria,
    Action:              fsmJoinParentNsSyncedAction,
}
