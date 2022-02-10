package fsm

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
        music "github.com/DNSSEC-Provisioning/music/common"
)

var FsmJoinAddCDS = music.FSMTransition{
	// XXX: what is the *criteria* for making this transition?
	Description:         "Once all DNSKEYs are present in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",

	MermaidPreCondDesc:  "Wait for all DNSKEY RRsets to be consistent",
	MermaidActionDesc:   "Compute and publish CDS/CDNSKEY RRsets on all signers",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEY RRs are published",

	PreCondition:        JoinAddCdsPreCondition,
	Action:              JoinAddCdsAction,
	PostCondition:       VerifyCdsPublished,
}

func JoinAddCdsPreCondition(z *music.Zone) bool {
	dnskeys := make(map[string][]*dns.DNSKEY)

	log.Printf("Add CDS/CDNSKEY:\n")
	log.Printf("%s: Verifying that DNSKEYs are in sync in group %s", z.Name, z.SGroup.Name)

	if z.ZoneType == "debug" {
	   log.Printf("JoinAddCdsPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
	   return true
	}

	for _, s := range z.SGroup.SignerMap {

		updater := music.GetUpdater(s.Method)
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("JoinAddCdsPreCondition: Error from updater.FetchRRset (signer %s): %v", s.Name, err)
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
		   	keys := ""
			for _, k := range dnskeys[s.Name] {
				if f := k.Flags & 0x101; f == 256 {
					keys += fmt.Sprintf("%d (ZSK) ", int(k.KeyTag()))
				} else {
					keys += fmt.Sprintf("%d (KSK) ", int(k.KeyTag()))
				}
			}
			log.Printf("Fetched %s DNSKEYs from %s: %s", z.Name,
					    s.Name, keys)
		} else {
			log.Printf("JoinAddCdsPreCondition: %s: No DNSKEYs found in %s", z.Name, s.Name)
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
							//     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but mismatch Protocol: %s", other_signer, key.PublicKey))
							//     break
							// }
							// if other_key.Algorithm != key.Algorithm {
							//     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but mismatch Protocol: %s", other_signer, key.PublicKey))
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

func JoinAddCdsAction(z *music.Zone) bool {
	log.Printf("%s: Creating CDS/CDNSKEY record sets", z.Name)

	if z.ZoneType == "debug" {
	   log.Printf("JoinAddCdsAction: zone %s (DEBUG) is automatically ok", z.Name)
	   return true
	}

	cdses := []dns.RR{}
	cdnskeys := []dns.RR{}

	for _, s := range z.SGroup.SignerMap {

		updater := music.GetUpdater(s.Method)
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
	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name,
			&[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
			z.SetStopReason(fmt.Sprintf("Unable to update %s with CDS/CDNSKEY record sets: %s",
				signer.Name, err))
			return false
		}
		log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets",
			z.Name, signer.Name)
	}

	return true
}

func VerifyCdsPublished(z *music.Zone) bool {
	log.Printf("Verifying Publication of CDS/CDNSKEY record sets for %s", z.Name)

	if z.ZoneType == "debug" {
	   log.Printf("VerifyCdsPublished: zone %s (DEBUG) is automatically ok", z.Name)
	   return true
	}

	// cdses := []dns.RR{}
	// cdnskeys := []dns.RR{}
	cdsmap := map[uint16]*dns.CDS{}    // cdsmap: map of CDS RRs created from all KSKs from all signers
	cdsmap2 := map[uint16]*dns.CDS{}   // cdsmap2: map of all CDS RRs found by querying all signers

	cdnskeymap := map[uint16]*dns.CDNSKEY{}
	cdnskeymap2 := map[uint16]*dns.CDNSKEY{}

	for _, s := range z.SGroup.SignerMap {
		updater := music.GetUpdater(s.Method)
		log.Printf("VerifyCdsPublished: %s Using FetchRRset interface\n", z.Name)
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
	keyids := []uint16{}
	for k, _ := range cdsmap {
	    keyids = append(keyids, k)
	}
	log.Printf("Verify Publication of CDS: there are KSKs at the signers with the following keytags: %v\n", keyids)

	// Check against published CDS/CDNSKEY RRsets.
	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		err, cdsrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCDS)
		if err != nil {
			err, _ = z.SetStopReason(fmt.Sprintf("Unable to fetch CDS RRset from %s: %v",
				signer.Name, err))
			return false
		}
		err, cdnskeyrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCDNSKEY)
		if err != nil {
			err, _ = z.SetStopReason(fmt.Sprintf("Unable to fetch CDNSKEY RRset from %s: %v",
				signer.Name, err))
			return false
		}

		for _, cdsrr := range cdsrrs {		// check all CDS RRs from this signer
			cds, ok := cdsrr.(*dns.CDS)
			if !ok {
				continue
			}
			cdsmap2[cds.KeyTag] = cds	// put the CDS into cdsmap2
			if _, exist := cdsmap[cds.KeyTag]; !exist {
				err, _ = z.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d published by signer %s should not exist", cds.KeyTag, signer.Name))
				return false
			}
		}
		for _, revcds := range cdsmap {
			if _, exist := cdsmap2[revcds.KeyTag]; !exist {
				err, _ = z.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d should be published by %s, but is not",
					revcds.KeyTag, signer.Name))
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
				err, _ = z.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d published by %s should not exist",
				     cdnskey.KeyTag, signer.Name))
				return false
			}
		}
		for _, revcdnskey := range cdnskeymap {
			if _, exist := cdnskeymap2[revcdnskey.KeyTag()]; !exist {
				err, _ = z.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d should be published by %s, but is not",
					revcdnskey.KeyTag, signer.Name))
				return false
			}
		}
	}

	return true
}
