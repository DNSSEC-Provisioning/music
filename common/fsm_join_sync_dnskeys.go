package music

import (
    "fmt"
    "log"

    "github.com/miekg/dns"
)

func fsmJoinSyncDnskeys(z *Zone) bool {
    dnskeys := make(map[string][]*dns.DNSKEY)

    log.Printf("%s: Syncing DNSKEYs in group %s", z.Name, z.sgroup.Name)

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

            if f := dnskey.Flags & 0x101; f == 256 {
                stmt, err := z.MusicDB.db.Prepare("INSERT OR IGNORE INTO zone_dnskeys (zone, dnskey, signer) VALUES (?, ?, ?)")
                if err != nil {
                    log.Printf("%s: Statement prepare failed: %s", z.Name, err)
                    return false
                }

                res, err := stmt.Exec(z.Name, fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey), s.Name)
                if err != nil {
                    log.Printf("%s: Statement execute failed: %s", z.Name, err)
                    return false
                }
                rows, _ := res.RowsAffected()
                if rows > 0 {
                    log.Printf("%s: Origin for %s set to %s", z.Name, dnskey.PublicKey, s.Name)
                }
            }
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
                        // add a DNSKEY that we had but other signer did not
                        s := z.sgroup.SignerMap[other_signer]
                        updater := GetUpdater(s.Method)
                        if err := updater.Update(&s, z.Name, &[][]dns.RR{[]dns.RR{key}}, nil); err != nil {
                            log.Printf("%s: Unable to update %s with new DNSKEY %s: %s", z.Name, other_signer, key.PublicKey, err)
                            return false
                        }
                        log.Printf("%s: Added %s's DNSKEY %s to %s", z.Name, signer, key.PublicKey, other_signer)
                    } else {
                        log.Printf("%s: %s's DNSKEY %s already exists in %s", z.Name, signer, key.PublicKey, other_signer)
                    }
                }
            }
        }
    }

    z.StateTransition(FsmStateSignerUnsynced, FsmStateDnskeysSynced)
    return true
}

var FsmJoinSyncDnskeys = FSMTransition{
    Description: "First step when joining, this transistion has no criteria and will sync DNSKEYs between all signers (action)",
    Criteria:    func(z *Zone) bool { return true },
    Action:      fsmJoinSyncDnskeys,
}
