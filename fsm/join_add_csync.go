package fsm

import (
	"log"

	"github.com/miekg/dns"
        music "github.com/DNSSEC-Provisioning/music/common"
)

var FsmJoinAddCsync = music.FSMTransition{
	Description: "Once all NS are present in all signers (criteria), build CSYNC record and push to all signers (action)",

	MermaidCriteriaDesc: "Wait for NS RRset to be consistent",
	MermaidPreCondDesc:  "Wait for NS RRset to be consistent",
	MermaidActionDesc:   "Generate and push CSYNC record",
	MermaidPostCondDesc: "Verify that CSYNC record has been published",

	Criteria:      fsmJoinAddCsyncCriteria,
	PreCondition:  fsmJoinAddCsyncCriteria,
	Action:        fsmJoinAddCsyncAction,
	PostCondition: func(z *music.Zone) bool { return true },
}

func fsmJoinAddCsyncCriteria(z *music.Zone) bool {
	nses := make(map[string][]*dns.NS)

	log.Printf("%s: Verifying that NSes are in sync in group %s", z.Name, z.SGroup.Name)

	for _, s := range z.SGroup.SignerMap {
		//        m := new(dns.Msg)
		//        m.SetQuestion(z.Name, dns.TypeNS)
		//        c := new(dns.Client)
		//        r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way
		//        if err != nil {
		//            log.Printf("%s: Unable to fetch NSes from %s: %s", z.Name, s.Name, err)
		//            return false
		//        }

		updater := music.GetUpdater(s.Method)
		log.Printf("JoinAddCSYNC: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeNS)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		nses[s.Name] = []*dns.NS{}

		//        for _, a := range r.Answer {
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
				log.Printf("%s: NS %s is missing in signer %s", z.Name, ns.Ns, signer)
				group_nses_synced = false
			}
		}
	}

	if !group_nses_synced {
		return false
	}

	log.Printf("%s: All NSes synced between all signers", z.Name)
	return true
}

func fsmJoinAddCsyncAction(z *music.Zone) bool {
	// TODO: configurable TTL for created CSYNC records
	ttl := 300

	log.Printf("%s: Creating CSYNC record sets", z.Name)

	for _, signer := range z.SGroup.SignerMap {
		//        m := new(dns.Msg)
		//        m.SetQuestion(z.Name, dns.TypeSOA)
		//        c := new(dns.Client)
		//        r, _, err := c.Exchange(m, signer.Address+":53") // TODO: add DnsAddress or solve this in a better way
		//        if err != nil {
		//            log.Printf("%s: Unable to fetch SOA from %s: %s", z.Name, signer.Name, err)
		//            return false
		//        }

		updater := music.GetUpdater(signer.Method)
		log.Printf("JoinAddCSYNC: Using FetchRRset interface:\n")
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
				log.Printf("%s: Unable to update %s with CSYNC record sets: %s",
					z.Name, signer.Name, err)
				return false
			}
			log.Printf("%s: Updated signer %s successfully with CSYNC record sets",
				z.Name, signer.Name)
		}
	}

	return true
}
