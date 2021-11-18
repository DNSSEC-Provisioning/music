package music

import (
	// "fmt"
	"log"

	"github.com/miekg/dns"
)

func fsmLeaveSyncNsesCriteria(z *Zone) bool {
	return true
}

func fsmLeaveSyncNsesAction(z *Zone) bool {
	leavingSignerName := "ns1.msg2.catch22.se." // Issue #34: Static leaving signer until metadata is in place

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	leavingSigner, err := z.MusicDB.GetSignerByName(leavingSignerName)
	if err != nil {
		log.Printf("%s: Unable to get leaving signer %s: %s", z.Name, leavingSignerName, err)
		return false
	}

	log.Printf("%s: Removing NSes originating from leaving signer %s", z.Name, leavingSigner.Name)

	stmt, err := z.MusicDB.db.Prepare("SELECT ns FROM zone_nses WHERE zone = ? AND signer = ?")
	if err != nil {
		log.Printf("%s: Statement prepare failed: %s", z.Name, err)
		return false
	}

	rows, err := stmt.Query(z.Name, leavingSigner.Name)
	if err != nil {
		log.Printf("%s: Statement execute failed: %s", z.Name, err)
		return false
	}

	nsrem := []dns.RR{}

	var ns string
	for rows.Next() {
		if err = rows.Scan(&ns); err != nil {
			log.Printf("%s: Rows.Scan() failed: %s", z.Name, err)
			return false
		}

		rr := new(dns.NS)
		rr.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 0}
		rr.Ns = ns
		nsrem = append(nsrem, rr)
	}

	for _, signer := range z.sgroup.SignerMap {
		updater := GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name, nil, &[][]dns.RR{nsrem}); err != nil {
			log.Printf("%s: Unable to remove NSes from %s: %s", z.Name, signer.Name, err)
			return false
		}
		log.Printf("%s: Removed NSes from %s successfully", z.Name, signer.Name)
	}

	updater := GetUpdater(leavingSigner.Method)
	if err := updater.Update(leavingSigner, z.Name, z.Name, nil, &[][]dns.RR{nsrem}); err != nil {
		log.Printf("%s: Unable to remove NSes from %s: %s", z.Name, leavingSigner.Name, err)
		return false
	}
	log.Printf("%s: Removed NSes from %s successfully", z.Name, leavingSigner.Name)

	z.StateTransition(FsmStateSignerUnsynced, FsmStateNsesSynced)
	return true
}

var FsmLeaveSyncNses = FSMTransition{
	Description: "First step when leaving, this transistion has no critera and will remove NSes that originated from the leaving signer (Action)",
	Criteria:    fsmLeaveSyncNsesCriteria,
	Action:      fsmLeaveSyncNsesAction,
}
