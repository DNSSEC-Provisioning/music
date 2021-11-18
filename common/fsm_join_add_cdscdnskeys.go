package music

import (
	// "fmt"
	"log"

	"github.com/miekg/dns"
)

var FsmJoinAddCdscdnskeys = FSMTransition{
	// XXX: what is the *criteria* for making this transition?
	Description:         "Once all DNSKEYs are present in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",
	MermaidCriteriaDesc: "Wait for DNSKEY RRset to be consistent",
	MermaidPreCondDesc:  "Wait for all DNSKEY RRsets to be consistent",
	MermaidActionDesc:   "Compute and publish CDS/CDNSKEY RRsets on all signers",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEY RRs are published",
	Criteria:            fsmJoinAddCdscdnskeysCriteria,
	PreCondition:        fsmJoinAddCdscdnskeysCriteria,
	Action:              fsmJoinAddCdscdnskeysAction,
	PostCondition:       fsmVerifyCdsPublished,
}

func fsmJoinAddCdscdnskeysCriteria(z *Zone) bool {
	dnskeys := make(map[string][]*dns.DNSKEY)

	log.Printf("Add CDS/CDNSKEY:\n")
	log.Printf("%s: Verifying that DNSKEYs are in sync in group %s", z.Name, z.sgroup.Name)

	for _, s := range z.sgroup.SignerMap {

		updater := GetUpdater(s.Method)
		log.Printf("VerifyDnskeysSynched: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		dnskeys[s.Name] = []*dns.DNSKEY{}
		for _, a := range rrs {
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
					log.Printf("%s: - %d (ZSK) %s...", z.Name, int(k.KeyTag()), k.PublicKey[:30])
				} else {
					log.Printf("%s: - %d (KSK) %s...", z.Name, int(k.KeyTag()), k.PublicKey[:30])
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
						log.Printf("%s: Still missing %s's DNSKEY %d %s in %s", z.Name, signer, key.KeyTag(), key.PublicKey[:30], other_signer)
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

		updater := GetUpdater(s.Method)
		log.Printf("VerifyDnskeysSynched: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		//        for _, a := range r.Answer {
		// Create CDS/CDNSKEY RRsets
		for _, a := range rrs {
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

	// Publish CDS/CDNSKEY RRsets
	for _, signer := range z.sgroup.SignerMap {
		updater := GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name,
			&[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
			log.Printf("%s: Unable to update %s with CDS/CDNSKEY record sets: %s",
				z.Name, signer.Name, err)
			return false
		}
		log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets",
			z.Name, signer.Name)
	}

	// z.StateTransition(FsmStateDnskeysSynced, FsmStateCdscdnskeysAdded)
	return true
}

func fsmVerifyCdsPublished(z *Zone) bool {
	log.Printf("%s: Verifying Publication of CDS/CDNSKEY record sets", z.Name)

	// cdses := []dns.RR{}
	// cdnskeys := []dns.RR{}
	cdsmap := map[uint16]*dns.CDS{}
	cdsmap2 := map[uint16]*dns.CDS{}

	cdnskeymap := map[uint16]*dns.CDNSKEY{}
	cdnskeymap2 := map[uint16]*dns.CDNSKEY{}

	for _, s := range z.sgroup.SignerMap {
		updater := GetUpdater(s.Method)
		log.Printf("VerifyDnskeysSynched: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		// Create CDS/CDNSKEY RRsets
		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if f := dnskey.Flags & 0x101; f == 257 {
				cdsmap[dnskey.KeyTag()] = dnskey.ToDS(dns.SHA256).ToCDS()
				cdnskeymap[dnskey.KeyTag()] = dnskey.ToCDNSKEY()
			}
		}
	}

	// Check against published CDS/CDNSKEY RRsets.
	for _, signer := range z.sgroup.SignerMap {
		updater := GetUpdater(signer.Method)
		err, cdsrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCDS)
		if err != nil {
			log.Printf("%s: Unable to fetch CDS RRset from %s: %v",
				z.Name, signer.Name, err)
			return false
		}
		err, cdnskeyrrs := updater.FetchRRset(signer, z.Name, z.Name,
			dns.StringToType["CDNSKEY"])
		if err != nil {
			log.Printf("%s: Unable to fetch CDNSKEY RRset from %s: %v",
				z.Name, signer.Name, err)
			return false
		}

		for _, cdsrr := range cdsrrs {
			cds, ok := cdsrr.(*dns.CDS)
			if !ok {
				continue
			}
			cdsmap2[cds.KeyTag] = cds
			if _, exist := cdsmap[cds.KeyTag]; !exist {
				log.Printf("CDS RR with keyid=%d published by %s should not exist\n",
					cds.KeyTag, signer.Name)
				return false
			}
		}
		for _, revcds := range cdsmap {
			if _, exist := cdsmap2[revcds.KeyTag]; !exist {
				log.Printf("CDS RR with keyid=%d should be published by %s, but is not\n",
					revcds.KeyTag, signer.Name)
				return false
			}

		}

		for _, cdnskeyrr := range cdnskeyrrs {
			cdnskey, ok := cdnskeyrr.(*dns.CDNSKEY)
			if !ok {
				continue
			}
			cdnskeymap2[cdnskey.KeyTag()] = cdnskey
			if _, exist := cdnskeymap[cdnskey.KeyTag()]; !exist {
				log.Printf("CDNSKEY RR with keyid=%d published by %s should not exist\n",
					cdnskey.KeyTag, signer.Name)
				return false
			}
		}
		for _, revcdnskey := range cdnskeymap {
			if _, exist := cdnskeymap2[revcdnskey.KeyTag()]; !exist {
				log.Printf("CDNSKEY RR with keyid=%d should be published by %s, but is not\n",
					revcdnskey.KeyTag, signer.Name)
				return false
			}

		}
	}

	return true
}
