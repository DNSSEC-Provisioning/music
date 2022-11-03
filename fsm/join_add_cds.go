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

	cdsFromKSK := map[uint16]*dns.CDS{}     // cdsFromKSK: map of CDS RRs created from all KSKs from all signers
	cdsFromSigners := map[uint16]*dns.CDS{} // cdsFromSigners: map of all CDS RRs found by querying all signers

	cdnskeyFromKSK := map[uint16]*dns.CDNSKEY{}
	cdnskeyFromSigners := map[uint16]*dns.CDNSKEY{}

	// Fetch DNSKEYS
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
				cdsFromKSK[dnskey.KeyTag()] = dnskey.ToDS(dns.SHA256).ToCDS()
				cdnskeyFromKSK[dnskey.KeyTag()] = dnskey.ToCDNSKEY()
			}
		}
	}
	var keyids []uint16
	for k := range cdsFromKSK {
		keyids = append(keyids, k)
	}
	log.Printf("Verify Publication of CDS: there are KSKs at the signers with the following keytags: %v\n", keyids)

	// Compare DNSKEYs to published CDS/CDNSKEY RRsets.
	for _, signer := range zone.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		err, cdsRRset := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeCDS)
		if err != nil {
			err, _ = zone.SetStopReason(fmt.Sprintf("Unable to fetch CDS RRset from %s: %v",
				signer.Name, err))
			return false
		}
		err, cdnskeyRRset := updater.FetchRRset(signer, zone.Name, zone.Name, dns.TypeCDNSKEY)
		if err != nil {
			err, _ = zone.SetStopReason(fmt.Sprintf("Unable to fetch CDNSKEY RRset from %s: %v",
				signer.Name, err))
			return false
		}

		for _, rr := range cdsRRset {
			cdsRR, ok := rr.(*dns.CDS)
			if !ok {
				continue
			}
			cdsFromSigners[cdsRR.KeyTag] = cdsRR
			if _, exist := cdsFromKSK[cdsRR.KeyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d published by signer %s should not exist", cdsRR.KeyTag, signer.Name))
				return false
			}
		}
		for _, cdsRR := range cdsFromKSK {
			if _, exist := cdsFromSigners[cdsRR.KeyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDS RR with keyid=%d should be published by %s, but is not",
					cdsRR.KeyTag, signer.Name))
				return false
			}
		}

		for _, rr := range cdnskeyRRset {
			cdnskeyRR, ok := rr.(*dns.CDNSKEY)
			if !ok {
				continue
			}
			keyTag := cdnskeyRR.KeyTag()
			cdnskeyFromSigners[keyTag] = cdnskeyRR
			if _, exist := cdnskeyFromKSK[keyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d published by %s should not exist",
					keyTag, signer.Name))
				return false
			}
		}
		for _, cdnskeyRR := range cdnskeyFromKSK {
			keyTag := cdnskeyRR.KeyTag()
			if _, exist := cdnskeyFromSigners[keyTag]; !exist {
				err, _ = zone.SetStopReason(fmt.Sprintf("CDNSKEY RR with keyid=%d should be published by %s, but is not",
					keyTag, signer.Name))
				return false
			}
		}
	}

	return true
}
