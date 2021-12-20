package fsm

import (
	"fmt"
	"log"

	music "github.com/DNSSEC-Provisioning/music/common"
	"github.com/miekg/dns"
)

var FsmJoinParentNsSynced = music.FSMTransition{
	Description: "Wait for parent to pick up CSYNC and update it's NS records (criteria), then remove CSYNC from all signers and STOP (action)",

	MermaidPreCondDesc:  "Verify that parent has published updated NS RRset",
	MermaidActionDesc:   "Remove CSYNC RR from all signers",
	MermaidPostCondDesc: "Verify that CSYNC has been removed from all signers",

	PreCondition:  JoinParentNsSyncedPreCondition,
	Action:        JoinParentNsSyncedAction,
	PostCondition: func(z *music.Zone) bool { return true },
}

func JoinParentNsSyncedPreCondition(z *music.Zone) bool {
	nses := make(map[string][]*dns.NS)

	log.Printf("%s: Verifying that NSes are in sync in the parent", z.Name)

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeNS)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way
		if err != nil {
			stopreason := fmt.Sprintf("%s: Unable to fetch NSes from %s: %s", z.Name, s.Name, err)
			err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
			log.Printf("%s\n", stopreason)
			return false
		}

		nses[s.Name] = []*dns.NS{}

		for _, a := range r.Answer {
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

	// parentAddress := "13.48.238.90:53" // Issue #33: using static IP address for msat1.catch22.se for now

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, parentAddress)
	if err != nil {
		stopreason := fmt.Sprintf("%s: Unable to fetch NSes from parent: %s", z.Name, err)
		err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
		log.Printf("%s\n", stopreason)
		return false
	}

	for _, a := range r.Ns {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		delete(nsmap, ns.Ns)
	}

	if len(nsmap) > 0 {
		for ns, _ := range nsmap {
			stopreason := fmt.Sprintf("%s: Missing NS %s in parent", z.Name, ns)
			err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
			log.Printf("%s\n", stopreason)
		}
		return false
	}

	log.Printf("%s: Parent NSes are up-to-date", z.Name)
	return true
}

func JoinParentNsSyncedAction(z *music.Zone) bool {
	log.Printf("%s: Removing CSYNC record sets", z.Name)

	csync := new(dns.CSYNC)
	csync.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 0}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.RemoveRRset(signer, z.Name, z.Name,
			[][]dns.RR{[]dns.RR{csync}}); err != nil {
			stopreason := fmt.Sprintf("%s: Unable to remove CSYNC record sets from %s: %s", z.Name, signer.Name, err)
			err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
			log.Printf("%s\n", stopreason)
			return false
		}
		log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, signer.Name)
	}

	return true
}
