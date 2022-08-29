package fsm

import (
	"fmt"
	"log"

	music "github.com/DNSSEC-Provisioning/music/common"
	"github.com/miekg/dns"
)

var FsmLeaveAddCsync = music.FSMTransition{
	Description: "Once all NS are correct in all signers (criteria), build CSYNC record and push to all signers (action)",

	MermaidPreCondDesc:  "Wait for all NS RRsets to be in sync in all signers",
	MermaidActionDesc:   "Create and publish CSYNC record in all signers",
	MermaidPostCondDesc: "Verify that the CSYNC record has been removed everywhere",

	PreCondition:  LeaveAddCsyncPreCondition,
	Action:        LeaveAddCsyncAction,
	PostCondition: func(z *music.Zone) bool { return true },
}

func LeaveAddCsyncPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveAddCsyncPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	sg := z.SignerGroup()
	if sg == nil {
		log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}

	log.Printf("LeaveAddCsyncPreCondition: z: %v", z)

	leavingSignerName := z.FSMSigner // Issue #34: Static leaving signer until metadata is in place
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name for zone %s unset.", z.Name)
	}

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	leavingSigner, err := z.MusicDB.GetSignerByName(nil, leavingSignerName, false) // not apisafe
	if err != nil {
		z.SetStopReason(nil, fmt.Sprintf("Unable to get leaving signer %s: %s", leavingSignerName, err))
		return false
	}

	// https://github.com/DNSSEC-Provisioning/music/issues/130, testing to remove the leaving signer from the signermap. /rog
	// this may not be obvious to the casual observer
	log.Printf("leave_add_csync: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	nses := make(map[string]bool)

	stmt, err := z.MusicDB.Prepare("SELECT ns FROM zone_nses WHERE zone = ? AND signer = ?")
	if err != nil {
		log.Printf("%s: Statement prepare failed: %s", z.Name, err)
		return false
	}

	rows, err := stmt.Query(z.Name, leavingSigner.Name)
	if err != nil {
		log.Printf("%s: Statement execute failed: %s", z.Name, err)
		return false
	}

	var ns string
	for rows.Next() {
		if err = rows.Scan(&ns); err != nil {
			log.Printf("%s: Rows.Scan() failed: %s", z.Name, err)
			return false
		}

		nses[ns] = true
	}

	log.Printf("%s: Verifying that leaving signer %s NSes has been removed from all signers", z.Name, leavingSigner.Name)

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeNS)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":"+s.Port)
		if err != nil {
			z.SetStopReason(nil, fmt.Sprintf("Unable to fetch NSes from %s: %s", s.Name, err))
			return false
		}

		for _, a := range r.Answer {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}

			if _, ok := nses[ns.Ns]; ok {
				z.SetStopReason(nil, fmt.Sprintf("NS %s still exists in signer %s", ns.Ns, s.Name))
				return false
			}
		}
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, leavingSigner.Address+":"+leavingSigner.Port)
	if err != nil {
		z.SetStopReason(nil, fmt.Sprintf("Unable to fetch NSes from %s: %s", leavingSigner.Name, err))
		return false
	}

	for _, a := range r.Answer {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		if _, ok := nses[ns.Ns]; ok {
			z.SetStopReason(nil, fmt.Sprintf("NS %s still exists in signer %s",
				ns.Ns, leavingSigner.Name))
			return false
		}
	}

	log.Printf("%s: All NSes of leaving signer has been removed", z.Name)
	return true
}

// Semantics:
// 1. Lookup zone signergroup (can only be one)
// 2. Lookup FSMSigner for the zone (can only be one)
// 3. Go through the steps below.
// 4. Celebrate Christmas

func LeaveAddCsyncAction(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("LeaveAddCsyncAction: zone %s (DEBUG) is automatically ok", z.Name)
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
	leavingSigner, err := z.MusicDB.GetSignerByName(nil, leavingSignerName, false) // not apisafe
	if err != nil {
		z.SetStopReason(nil, fmt.Sprintf("Unable to get leaving signer %s: %s", leavingSignerName, err))
		return false
	}

	// https://github.com/DNSSEC-Provisioning/music/issues/130, testing to remove the leaving signer from the signermap. /rog
	// this may not be obvious to the casual observer
	log.Printf("leave_add_csync: %s SignerMap: %v\n", z.Name, z.SGroup.SignerMap)
	log.Printf("remove %v from SignerMap %v: for %v", leavingSignerName, sg.SignerMap, sg.Name)
	delete(z.SGroup.SignerMap, leavingSignerName)
	if _, member := z.SGroup.SignerMap[leavingSignerName]; member {
		log.Fatalf("Signer %s is still a member of group %s", leavingSignerName, z.SGroup.SignerMap)
	}

	// TODO: configurable TTL for created CSYNC records
	ttl := 300

	log.Printf("%s: Creating CSYNC record sets", z.Name)

	for _, signer := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeSOA)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, signer.Address+":"+signer.Port)
		if err != nil {
			z.SetStopReason(nil, fmt.Sprintf("Unable to fetch SOA from %s: %s", signer.Name, err))
			return false
		}

		for _, a := range r.Answer {
			soa, ok := a.(*dns.SOA)
			if !ok {
				continue
			}

			csync := new(dns.CSYNC)
			csync.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: uint32(ttl)}
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
			log.Printf("%s: Update %s successfully with CSYNC record sets", z.Name, signer.Name)
		}
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeSOA)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, leavingSigner.Address+":"+leavingSigner.Port)
	if err != nil {
		z.SetStopReason(nil, fmt.Sprintf("Unable to fetch SOA from %s: %s", leavingSigner.Name, err))
		return false
	}

	for _, a := range r.Answer {
		soa, ok := a.(*dns.SOA)
		if !ok {
			continue
		}

		csync := new(dns.CSYNC)
		csync.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: uint32(ttl)}
		csync.Serial = soa.Serial
		csync.Flags = 3
		csync.TypeBitMap = []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}

		updater := music.GetUpdater(leavingSigner.Method)
		if err := updater.Update(leavingSigner, z.Name, z.Name,
			&[][]dns.RR{[]dns.RR{csync}}, nil); err != nil {
			z.SetStopReason(nil, fmt.Sprintf("Unable to update %s with CSYNC record sets: %s",
				leavingSigner.Name, err))
			return false
		}
		log.Printf("%s: Update %s successfully with CSYNC record sets", z.Name, leavingSigner.Name)
	}

	return true
}
