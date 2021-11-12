package music

import (
    "fmt"
    "log"

    "github.com/miekg/dns"
)

func fsmLeaveAddCdscdnskeysCriteria(z *Zone) bool {
    leavingSignerName := "ns1.msg2.catch22.se." // Issue #34: Static leaving signer until metadata is in place

    // Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
    leavingSigner, err := z.MusicDB.GetSigner(&Signer{ Name: leavingSignerName })
    if err != nil {
        log.Printf("%s: Unable to get leaving signer %s: %s", z.Name, leavingSignerName, err)
        return false
    }

    log.Printf("%s: Verifying that leaving signer %s DNSKEYs has been removed from all signers", z.Name, leavingSigner.Name)

    stmt, err := z.MusicDB.db.Prepare("SELECT dnskey FROM zone_dnskeys WHERE zone = ? AND signer = ?")
    if err != nil {
        log.Printf("%s: Statement prepare failed: %s", z.Name, err)
        return false
    }

    rows, err := stmt.Query(z.Name, leavingSigner.Name)
    if err != nil {
        log.Printf("%s: Statement execute failed: %s", z.Name, err)
        return false
    }

    dnskeys := make(map[string]bool)

    var dnskey string
    for rows.Next() {
        if err = rows.Scan(&dnskey); err != nil {
            log.Printf("%s: Rows.Scan() failed: %s", z.Name, err)
            return false
        }

        dnskeys[dnskey] = true
    }

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

            if _, ok := dnskeys[fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey)]; ok {
                log.Printf("%s: DNSKEY %s still exists in signer %s", z.Name, dnskey.PublicKey, s.Name)
                return false
            }
        }
    }

    return true
}

func fsmLeaveAddCdscdnskeysAction(z *Zone) bool {
    log.Printf("%s: Creating CDS/CDNSKEY record sets", z.Name)

    cdses := []dns.RR{}
    cdnskeys := []dns.RR{}

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

            if f := dnskey.Flags & 0x101; f == 257 {
                cdses = append(cdses, dnskey.ToDS(dns.SHA256).ToCDS())
                cdnskeys = append(cdnskeys, dnskey.ToCDNSKEY())
            }
        }
    }

    // Create CDS/CDNSKEY records sets
    for _, signer := range z.sgroup.SignerMap {
        updater := GetUpdater(signer.Method)
        if err := updater.Update(signer, z.Name, &[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
            log.Printf("%s: Unable to update %s with CDS/CDNSKEY record sets: %s", z.Name, signer.Name, err)
            return false
        }
        log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets", z.Name, signer.Name)
    }

    z.StateTransition(FsmStateDnskeysSynced, FsmStateCdscdnskeysAdded)
    return true
}

var FsmLeaveAddCdscdnskeys = FSMTransition{
    Description: "Once all DNSKEYs are correct in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",
    Criteria:    fsmLeaveAddCdscdnskeysCriteria,
    Action:      fsmLeaveAddCdscdnskeysAction,
}
