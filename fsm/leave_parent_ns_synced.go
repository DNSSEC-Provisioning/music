package fsm

import (
	// "fmt"
	"log"

	music "github.com/DNSSEC-Provisioning/music/common"
	"github.com/miekg/dns"
)

var FsmLeaveParentNsSynced = music.FSMTransition{
	Description: "Wait for parent to pick up CSYNC and update it's NS records (criteria), then remove CSYNC from all signers (action)",

	MermaidPreCondDesc:  "Wait for parent to pick up CSYNC and update the NS records",
	MermaidActionDesc:   "Remove CSYNC records from all signers",
	MermaidPostCondDesc: "Verify that all CSYNC records have been removed",

	PreCondition:  LeaveParentNsSyncedPreCondition,
	Action:        LeaveParentNsSyncedAction,
	PostCondition: func(z *music.Zone) bool { return true },
}

// Verify that NS records in parent are in synched.
func LeaveParentNsSyncedPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveParentNsSyncedPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	sg := z.SignerGroup()
	if sg == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}

	leavingSignerName := z.FSMSigner // Issue #34: Static leaving signer until metadata is in place
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name for zone %s unset.", z.Name)
	}

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	leavingSigner, err := z.MusicDB.GetSignerByName(leavingSignerName, false) // not apisafe
	if err != nil {
		log.Printf("%s: Unable to get leaving signer %s: %s", z.Name, leavingSignerName, err)
		return false
	}

	nses := make(map[string][]*dns.NS)

	log.Printf("%s: Verifying that NSes are in sync in the parent", z.Name)

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeNS)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)
		if err != nil {
			log.Printf("%s: Unable to fetch NSes from %s: %s", z.Name, s.Name, err)
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

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, leavingSigner.Address+":"+leavingSigner.Port)
	if err != nil {
		log.Printf("%s: Unable to fetch NSes from %s: %s", z.Name, leavingSigner.Name, err)
		return false
	}

	nses[leavingSigner.Name] = []*dns.NS{}

	for _, a := range r.Answer {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		nses[leavingSigner.Name] = append(nses[leavingSigner.Name], ns)
	}

	// Map all known NSes
	nsmap := make(map[string]*dns.NS)
	for _, rrs := range nses {
		for _, rr := range rrs {
			nsmap[rr.Ns] = rr
		}
	}

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false
	}

	m = new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c = new(dns.Client)
	r, _, err = c.Exchange(m, parentAddress)
	if err != nil {
		log.Printf("%s: Unable to fetch NSes from parent: %s", z.Name, err)
		return false
	}

	for _, a := range r.Ns {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		if _, ok := nsmap[ns.Ns]; !ok {
			log.Printf("%s: NS %s still exists in parent", z.Name, ns.Ns)
			return false
		}
	}

	log.Printf("%s: Parent NSes are up-to-date", z.Name)
	return true
}

func LeaveParentNsSyncedAction(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveParentNsSyncedAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	sg := z.SignerGroup()
	if sg == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}

	leavingSignerName := z.FSMSigner // Issue #34: Static leaving signer until metadata is in place
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name for zone %s unset.", z.Name)
	}

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	leavingSigner, err := z.MusicDB.GetSignerByName(leavingSignerName, false) // not apisafe
	if err != nil {
		log.Printf("%s: Unable to get leaving signer %s: %s", z.Name, leavingSignerName, err)
		return false
	}

	log.Printf("%s: Removing CSYNC record sets", z.Name)

	csync := new(dns.CSYNC)
	csync.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 0}

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.RemoveRRset(signer, z.Name, z.Name,
			[][]dns.RR{[]dns.RR{csync}}); err != nil {
			log.Printf("%s: Unable to remove CSYNC record sets from %s: %s",
				z.Name, signer.Name, err)
			return false
		}
		log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, signer.Name)
	}

	updater := music.GetUpdater(leavingSigner.Method)
	if err := updater.RemoveRRset(leavingSigner, z.Name, z.Name, [][]dns.RR{[]dns.RR{csync}}); err != nil {
		log.Printf("%s: Unable to remove CSYNC record sets from %s: %s", z.Name, leavingSigner.Name, err)
		return false
	}
	log.Printf("%s: Removed CSYNC record sets from %s successfully", z.Name, leavingSigner.Name)

	return true
}
