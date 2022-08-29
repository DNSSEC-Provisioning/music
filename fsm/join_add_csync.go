package fsm

import (
	"fmt"
	"log"

	music "github.com/DNSSEC-Provisioning/music/common"
	"github.com/miekg/dns"
)

var FsmJoinAddCsync = music.FSMTransition{
	Description: "Once all NS are present in all signers (criteria), build CSYNC record and push to all signers (action)",

	MermaidPreCondDesc:  "Wait for NS RRset to be consistent",
	MermaidActionDesc:   "Generate and push CSYNC record",
	MermaidPostCondDesc: "Verify that CSYNC record has been published",

	PreCondition:  JoinAddCsyncPreCondition,
	Action:        JoinAddCsyncAction,
	PostCondition: VerifyCsyncPublished,
}

func JoinAddCsyncPreCondition(z *music.Zone) bool {
	nses := make(map[string][]*dns.NS)

	log.Printf("%s: Verifying that NSes are in sync in group %s", z.Name, z.SGroup.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinAddCsyncPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	for _, s := range z.SGroup.SignerMap {
		updater := music.GetUpdater(s.Method)
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeNS)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
			// XXX: johani: is it meaningful to continue here? why not just return false?
		}

		nses[s.Name] = []*dns.NS{}

		for _, a := range rrs {
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
	nsset := []*dns.NS{}
	for _, rr := range nsmap {
		nsset = append(nsset, rr)
	}

	group_nses_synced := true
	for signer, keys := range nses {
		for _, ns := range nsset {
			found := false
			for _, key := range keys {
				if ns.Ns == key.Ns {
					found = true
					break
				}
			}
			if !found {
				z.SetStopReason(nil, fmt.Sprintf("NS %s is missing in signer %s", ns.Ns, signer))
				group_nses_synced = false
			}
		}
	}

	if !group_nses_synced {
		return false // stop-reason defined above
	}

	log.Printf("%s: All NSes synced between all signers", z.Name)
	return true
}

func JoinAddCsyncAction(z *music.Zone) bool {
	// TODO: configurable TTL for created CSYNC records
	ttl := 300

	log.Printf("JoinAddCSYNC: Using FetchRRset interface:\n")

	if z.ZoneType == "debug" {
		log.Printf("JoinAddCsyncAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	csync := new(dns.CSYNC)
	csync.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 0}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)

		// check if there is any CSYNC records if there are remove them before adding a csync record
		err, csyncrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCSYNC)
		if err != nil {
			err, _ = z.SetStopReason(nil, fmt.Sprintf("Unable to fetch CSYNC RRset from %s: %v", signer.Name, err))
			return false
		}
		if len(csyncrrs) != 0 {

			if err := updater.RemoveRRset(signer, z.Name, z.Name,
				[][]dns.RR{[]dns.RR{csync}}); err != nil {
				z.SetStopReason(nil, fmt.Sprintf("Unable to remove CSYNC record sets from %s: %s",
					signer.Name, err))
				return false
			}
			log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, signer.Name)
		}

		log.Printf("%s: Creating CSYNC record sets", z.Name)
		err, rrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeSOA)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		for _, a := range rrs {
			soa, ok := a.(*dns.SOA)
			if !ok {
				continue
			}

			csync := new(dns.CSYNC)
			csync.Hdr = dns.RR_Header{
				Name:   z.Name,
				Rrtype: dns.TypeCSYNC,
				Class:  dns.ClassINET,
				Ttl:    uint32(ttl),
			}
			csync.Serial = soa.Serial
			csync.Flags = 3
			csync.TypeBitMap = []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}

			updater := music.GetUpdater(signer.Method)
			if err := updater.Update(signer, z.Name, z.Name,
				&[][]dns.RR{[]dns.RR{csync}}, nil); err != nil {
				z.SetStopReason(nil, fmt.Sprintf("Unable to update %s with CSYNC record sets: %s",
					signer.Name, err))
				return false
			}
			log.Printf("%s: Updated signer %s successfully with CSYNC record sets",
				z.Name, signer.Name)
		}
	}

	return true
}

func VerifyCsyncPublished(z *music.Zone) bool {
	log.Printf("Verifying Publication of CSYNC record sets for %s", z.Name)
	// get all csync records from all the signers
	csynclist := []*dns.CSYNC{}
	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		err, csyncrrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeCSYNC)
		if err != nil {
			err, _ = z.SetStopReason(nil, fmt.Sprintf("Unable to fetch CSYNC RRset from %s: %v", signer.Name, err))
			return false
		}
		switch len(csyncrrs) {
		case 0:
			log.Printf("csyncrrs is %d long", len(csyncrrs))
			z.SetStopReason(nil, fmt.Sprintf("No CSYNC RRset returned from %s", signer.Name))
			return false
		case 1:
			log.Printf("csyncrrs is %d long", len(csyncrrs))
			csynclist = append(csynclist, csyncrrs[0].(*dns.CSYNC))
		default:
			log.Printf("csyncrrs is %d long", len(csyncrrs))
			z.SetStopReason(nil, fmt.Sprintf("Multiple CSYNC RRset returned from %s", signer.Name))
			return false
		}
	}

	// compare that the csync records are the same
	for _, csyncrr := range csynclist {
		if csyncrr.String() != csynclist[0].String() {
			z.SetStopReason(nil, fmt.Sprintf("CSYNC records are not identical"))
			return false
		}
	}
	// should we double check that they are correct as well?
	return true
}
