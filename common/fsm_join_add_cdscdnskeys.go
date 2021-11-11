package music

import (
    // "fmt"
    "log"

    "github.com/miekg/dns"
)

func fsmJoinAddCdscdnskeysCriteria(z *Zone) bool {
    dnskeys := make(map[string][]*dns.DNSKEY)

    log.Printf("Verifying that DNSKEYs for %s are in sync in group %s", z.Name, z.sgroup.Name)

    for _, s := range z.sgroup.SignerMap {
        m := new(dns.Msg)
        m.SetQuestion(z.Name, dns.TypeDNSKEY)

        c := new(dns.Client)
        r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way

        if err != nil {
            log.Printf("%s: Unable to fetch DNSKEYs from %s: %s", z.Name, s.Name, err)
            return false
        }

        dnskeys[s.Name] = []*dns.DNSKEY{}
        for _, a := range r.Answer {
            dnskey, ok := a.(*dns.DNSKEY)
            if !ok {
                continue
            }

            dnskeys[s.Name] = append(dnskeys[s.Name], dnskey)
        }

        if len(dnskeys[s.Name]) > 0 {
            log.Printf("%s: Fetched DNSKEYs from %s:", z.Name, s.Name)
            for _, k := range dnskeys[s.Name] {
                if f := k.Flags & 0x101; f == 256 {
                    log.Printf("%s: - %s (ZSK)", z.Name, k.PublicKey)
                } else {
                    log.Printf("%s: - %s (KSK)", z.Name, k.PublicKey)
                }
            }
        } else {
            log.Printf("%s: No DNSKEYs found in %s", z.Name, s.Name)
        }
    }

    // for each signer, check every other_signer if it's missing signer's DNSKEYs
    all_found := true
    for signer, keys := range dnskeys {
        for _, key := range keys {
            if f := key.Flags & 0x101; f == 256 { // only process ZSK's
                for other_signer, other_keys := range dnskeys {
                    if other_signer == signer {
                        continue
                    }

                    found := false
                    for _, other_key := range other_keys {
                        if other_key.PublicKey == key.PublicKey {
                            // if other_key.Protocol != key.Protocol {
                            //     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but missmatch Protocol: %s", other_signer, key.PublicKey))
                            //     break
                            // }
                            // if other_key.Algorithm != key.Algorithm {
                            //     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but missmatch Protocol: %s", other_signer, key.PublicKey))
                            //     break
                            // }
                            found = true
                            break
                        }
                    }

                    if !found {
                        log.Printf("%s: Still missing %s's DNSKEY %s in %s", z.Name, signer, key.PublicKey, other_signer)
                        all_found = false
                    }
                }
            }
        }
    }
    if !all_found {
        return false
    }
    log.Printf("%s: All DNSKEYs synced between all signers", z.Name)
    return true
}

func fsmJoinAddCdscdnskeysAction(z *Zone) bool {
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
        if err := updater.Update(&signer, z.Name, &[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
            log.Printf("%s: Unable to update %s with CDS/CDNSKEY record sets: %s", z.Name, signer.Name, err)
            return false
        }
        log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets", z.Name, signer.Name)
    }

    z.StateTransition(FsmStateDnskeysSynced, FsmStateCdscdnskeysAdded)
    return true
}

var FsmJoinAddCdscdnskeys = FSMTransition{
    Description: "Once all DNSKEYs are present in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",
    Criteria:    fsmJoinAddCdscdnskeysCriteria,
    Action:      fsmJoinAddCdscdnskeysAction,
}
