package fsm

import (
	"fmt"
	"log"

	"github.com/DNSSEC-Provisioning/music/music"
	"github.com/miekg/dns"
)

var FsmJoinAddCDS = music.FSMTransition{
	Description: "Once all DNSKEYs are present in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",

	MermaidPreCondDesc:  "Verify that all DNSKEYs are present on all signers",
	MermaidActionDesc:   "Compute and publish CDS/CDNSKEY RRsets on all signers",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEY RRs are published",

	PreCondition:  JoinAddCdsPreCondition,
	Action:        JoinAddCdsAction,
	PostCondition: VerifyCdsPublished,
}

// JoinAddCdsPreCondition collects DNSKEYS from all signers and verifys that the RRsets Match
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

func JoinAddCdsAction(zone *music.Zone) bool {
	log.Printf("[JoinAddCDSAction] zone struct: \n %v \n", zone)
	log.Printf("%s: Creating CDS/CDNSKEY record sets", zone.Name)

	if zone.ZoneType == "debug" {
		log.Printf("JoinAddCdsAction: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	// Get DNSKEYS from all the signers.
	// TODO: Figure out how we can just get the keys from when we got them earlier.
	dnskeyMap := make(map[uint16]*dns.DNSKEY)
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		log.Printf("[JoinAddCdsAction]\t Using FetchRRset interface[DNSKEY]\n")
		err, rrs := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeDNSKEY)
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

	var cdses, cdnskeys []dns.RR
	for _, dnskey := range dnskeyMap {
		cdses = append(cdses, dnskey.ToDS(dns.SHA256).ToCDS())
		cdses = append(cdses, dnskey.ToDS(dns.SHA384).ToCDS())
		cdnskeys = append(cdnskeys, dnskey.ToCDNSKEY())
	}

	// Publish CDS/CDNSKEY RRsets
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, zone.Name, zone.Name,
			&[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
			err, _ := zone.SetStopReason(fmt.Sprintf("Unable to update %s with CDS/CDNSKEY record sets: %s",
				signer.Name, err))
			if err != nil {
				log.Printf("Could not set stop reason: Unable to update %s with CDS/CDNSKEY rrset: %s",
					signer.Name, err)
			}
			return false
		}
		log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets",
			zone.Name, signer.Name)
	}
	return true
}

func VerifyCdsPublished(zone *music.Zone) bool {
	log.Printf("Verifying Publication of CDS/CDNSKEY record sets for %s", zone.Name)

	if zone.ZoneType == "debug" {
		log.Printf("VerifyCdsPublished: zone %s (DEBUG) is automatically ok", zone.Name)
		return true
	}

	cdsmap := map[uint16]*dns.CDS{}  // cdsmap: map of CDS RRs created from all KSKs from all signers
	cdsmap2 := map[uint16]*dns.CDS{} // cdsmap2: map of all CDS RRs found by querying all signers

	cdnskeymap := map[uint16]*dns.CDNSKEY{}
	cdnskeymap2 := map[uint16]*dns.CDNSKEY{}

	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		log.Printf("VerifyCdsPublished: %s Using FetchRRset interface\n", zone.Name)
		err, rrSet := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		// Create CDS/CDNSKEY RRsets
		for _, a := range rrSet {
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
	var keyids []uint16
	for k := range cdsmap {
		keyids = append(keyids, k)
	}
	log.Printf("Verify Publication of CDS: there are KSKs at the signers with the following keytags: %v\n", keyids)

	// Check against published CDS/CDNSKEY RRsets.
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		err, cdsRRset := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeCDS)
		if err != nil {
			err, _ = zone.SetStopReason(fmt.Sprintf("Unable to fetch CDS RRset from %s: %v",
				signer.Name, err))
			return false
		}
		err, cdnskeyrrs := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeCDNSKEY)
		if err != nil {
			err, _ = zone.SetStopReason(fmt.Sprintf("Unable to fetch CDNSKEY RRset from %s: %v",
				signer.Name, err))
			return false
		}

		for _, cdsrr := range cdsRRset { // check all CDS RRs from this signer
			cds, ok := cdsrr.(*dns.CDS)
			if !ok {
				continue
			}
			cdsmap2[cds.KeyTag] = cds // put the CDS into cdsmap2
			if _, exist := cdsmap[cds.KeyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d published by signer %s should not exist", cds.KeyTag, signer.Name))
				return false
			}
		}
		for _, revcds := range cdsmap {
			if _, exist := cdsmap2[revcds.KeyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d should be published by %s, but is not",
					revcds.KeyTag, signer.Name))
				return false
			}
		}

		for _, cdnskeyrr := range cdnskeyrrs {
			cdnskey, ok := cdnskeyrr.(*dns.CDNSKEY)
			if !ok {
				continue
			}
			keyTag := cdnskey.KeyTag()
			cdnskeymap2[keyTag] = cdnskey
			if _, exist := cdnskeymap[keyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d published by %s should not exist",
					keyTag, signer.Name))
				return false
			}
		}
		for _, revcdnskey := range cdnskeymap {
			keyTag := revcdnskey.KeyTag()
			if _, exist := cdnskeymap2[keyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d should be published by %s, but is not",
					keyTag, signer.Name))
				return false
			}
		}
	}

	return true
}
