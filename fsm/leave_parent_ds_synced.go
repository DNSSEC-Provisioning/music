package fsm

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
        music "github.com/DNSSEC-Provisioning/music/common"
)

var FsmLeaveParentDsSynced = music.FSMTransition{
	Description: "Wait for parent to pick up CDS/CDNSKEYs and update it's DS (criteria), then remove CDS/CDNSKEYs from all signers and STOP (action)",
	MermaidCriteriaDesc: "Wait for parent to pick up CDS/CDNSKEYs and update the DS record(s)",
	MermaidPreCondDesc:  "",
	MermaidActionDesc:   "Remove CDS/CDNSKEYs from all signers",
	MermaidPostCondDesc: "Verify that all CDS/CDNSKEYs have been removed",
	Criteria:    	     LeaveParentDsSyncedCriteria,
	PreCondition:	     func(z *music.Zone) bool { return true },
	Action:		     LeaveParentDsSyncedAction,
	PostCondition:	     func(z *music.Zone) bool { return true },
}

func LeaveParentDsSyncedCriteria(z *music.Zone) bool {
	cdsmap := make(map[string]*dns.CDS)

	log.Printf("%s: Verifying that DSes in parent are up to date compared to signers CDSes", z.Name)

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeCDS)

		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way

		if err != nil {
			log.Printf("%s: Unable to fetch CDSes from %s: %s", z.Name, s.Name, err)
			return false
		}

		for _, a := range r.Answer {
			cds, ok := a.(*dns.CDS)
			if !ok {
				continue
			}

			cdsmap[fmt.Sprintf("%d %d %d %s", cds.KeyTag, cds.Algorithm, cds.DigestType, cds.Digest)] = cds
		}
	}

	// parentAddress := "13.48.238.90:53" // Issue #33: using static IP address for msat1.catch22.se for now

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeDS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, parentAddress)
	if err != nil {
		log.Printf("%s: Unable to fetch DSes from parent: %s", z.Name, err)
		return false
	}
	for _, a := range r.Answer {
		ds, ok := a.(*dns.DS)
		if !ok {
			continue
		}

		if _, ok := cdsmap[fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)]; !ok {
			log.Printf("%s: Parent DS found that is not in any signer: %d %d %d %s", z.Name, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
			return false
		}
	}

	log.Printf("%s: Parent is up-to-date with it's DS records", z.Name)
	return true
}

func LeaveParentDsSyncedAction(z *music.Zone) bool {
	log.Printf("%s: Removing CDS/CDNSKEY record sets", z.Name)

	cds := new(dns.CDS)
	cds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 0}

	ccds := new(dns.CDNSKEY)
	ccds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCDNSKEY, Class: dns.ClassINET, Ttl: 0}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.RemoveRRset(signer, z.Name, z.Name,
			[][]dns.RR{[]dns.RR{cds}, []dns.RR{ccds}}); err != nil {
			log.Printf("%s: Unable to remove CDS/CDNSKEY record sets from %s: %s", z.Name, signer.Name, err)
			return false
		}
		log.Printf("%s: Removed CDS/CDNSKEY record sets from %s successfully", z.Name, signer.Name)
	}

	// State transitions are managed from ZoneStepFsm()
	// z.StateTransition(FsmStateCDSAdded, FsmStateParentDsSynced)
	return true

	// TODO: remove state/metadata around leaving signer
	//       tables: zone_dnskeys, zone_nses
}

