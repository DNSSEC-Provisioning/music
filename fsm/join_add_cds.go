package fsm

import (
	"fmt"
	"log"

	"github.com/DNSSEC-Provisioning/music/music"
	"github.com/miekg/dns"
)

var FsmJoinAddCDS = music.FSMTransition{
	// XXX: what is the *criteria* for making this transition?
	Description: "Once all DNSKEYs are present in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",

	MermaidPreCondDesc:  "Wait for all DNSKEY RRsets to be consistent",
	MermaidActionDesc:   "Compute and publish CDS/CDNSKEY RRsets on all signers",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEY RRs are published",

	PreCondition:  JoinAddCdsPreCondition,
	Action:        JoinAddCdsAction,
	PostCondition: VerifyCdsPublished,
}

// JoinAddCdsPreCondition collects DNSKEYS from all signers and confirms that the RRsets Match
func JoinAddCdsPreCondition(zone *music.Zone) bool {
	dnskeyRRsets := make(map[string][]dns.RR)
	var signerNames []string
	matches := true

	log.Printf("Add CDS/CDNSKEY:\n")
	log.Printf("%s: Verifying that DNSKEYs are in sync in group %s", zone.Name, zone.SGroup.Name)

	// Collect all the DNSKEYS per signer
	for signerName, signer := range zone.SGroup.SignerMap {

		signerNames = append(signerNames, signerName)
		updater := music.GetUpdater(signer.Method)
		err, rrSet := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("JoinAddCdsPreCondition: Error from updater.FetchRRset (signer %s): %v", signer.Name, err)
		}
		dnskeyRRsets[signer.Name] = rrSet
	}

	// Check that the RRsets Match between the signers.
	fmt.Printf("signerNames %v\n", signerNames)
	numSigners := len(signerNames)
	if len(signerNames) > 1 {
		for i := numSigners - 1; i > 0; i-- {
			match, rrset1Extra, rrset2Extra := music.RRsetCompare(dnskeyRRsets[signerNames[0]], dnskeyRRsets[signerNames[i]])
			if !match {
				matches = false
				if len(rrset1Extra) > 0 {
					log.Printf("%s: Still missing DNSKEYS: %v\n", signerNames[i], rrset1Extra)
				}
				if len(rrset2Extra) > 0 {
					log.Printf("%s: Still missing DNSKEYS: %v\n", signerNames[0], rrset2Extra)
				}
			}
		}
	}
	if !matches {
		err, _ := zone.SetStopReason(fmt.Sprintf("DNSKEYS not synced on signers"))
		if err != nil {
			log.Printf("Couldn't set stop reason: DNSKEYS not synced on signers")
		}
		return matches
	}

	log.Printf("[JoinAddCdsPreCondition] All DNSKEYS synced.")
	return matches
}

func JoinAddCdsAction(z *music.Zone) bool {
	log.Printf("[JoinAddCDSAction] zone struct: \n %v \n", z)
	log.Printf("%s: Creating CDS/CDNSKEY record sets", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinAddCdsAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	dnskeyMap := make(map[uint16]*dns.DNSKEY)

	for _, s := range z.SGroup.SignerMap {
		updater := music.GetUpdater(s.Method)
		log.Printf("[JoinAddCdsAction]\t Using FetchRRset interface[DNSKEY]\n")
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if f := dnskey.Flags & 0x101; f == 257 {
				dnskeyMap[dnskey.KeyTag()] = dnskey
			}
		}
	}

	var cdses []dns.RR
	var cdnskeys []dns.RR
	for _, dnskey := range dnskeyMap {
		cdses = append(cdses, dnskey.ToDS(dns.SHA256).ToCDS())
		cdses = append(cdses, dnskey.ToDS(dns.SHA384).ToCDS())
		cdnskeys = append(cdnskeys, dnskey.ToCDNSKEY())
	}

	// Publish CDS/CDNSKEY RRsets
	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name,
			&[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
			err, _ := z.SetStopReason(fmt.Sprintf("Unable to update %s with CDS/CDNSKEY record sets: %s",
				signer.Name, err))
			if err != nil {
				log.Printf("Could not set stop reason: Unable to update %s with CDS/CDNSKEY rrset: %s",
					signer.Name, err)
			}
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
	cdsmap := map[uint16]*dns.CDS{}  // cdsmap: map of CDS RRs created from all KSKs from all signers
	cdsmap2 := map[uint16]*dns.CDS{} // cdsmap2: map of all CDS RRs found by querying all signers

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

		for _, cdsrr := range cdsrrs { // check all CDS RRs from this signer
			cds, ok := cdsrr.(*dns.CDS)
			if !ok {
				continue
			}
			cdsmap2[cds.KeyTag] = cds // put the CDS into cdsmap2
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
