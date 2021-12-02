package fsm

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
        music "github.com/DNSSEC-Provisioning/music/common"
)

func fsmLeaveSyncDnskeysCriteria(z *music.Zone) bool {
	return true
}

func fsmLeaveSyncDnskeysAction(z *music.Zone) bool {
	leavingSignerName := "ns1.msg2.catch22.se." // Issue #34: Static leaving signer until metadata is in place

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	leavingSigner, err := z.MusicDB.GetSignerByName(leavingSignerName)
	if err != nil {
		log.Printf("%s: Unable to get leaving signer %s: %s", z.Name, leavingSignerName, err)
		return false
	}

	log.Printf("%s: Removing DNSKEYs originating from leaving signer %s", z.Name, leavingSigner.Name)

	stmt, err := z.MusicDB.Prepare("SELECT dnskey FROM zone_dnskeys WHERE zone = ? AND signer = ?")
	if err != nil {
		log.Printf("%s: Statement prepare failed: %s", z.Name, err)
		return false
	}

	rows, err := stmt.Query(z.Name, leavingSigner.Name)
	if err != nil {
		log.Printf("%s: Statement execute failed: %s", z.Name, err)
		return false
	}

	dnskeys := make(map[string]bool)

	var dnskey string
	for rows.Next() {
		if err = rows.Scan(&dnskey); err != nil {
			log.Printf("%s: Rows.Scan() failed: %s", z.Name, err)
			return false
		}

		dnskeys[dnskey] = true
	}

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeDNSKEY)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way
		if err != nil {
			log.Printf("%s: Unable to fetch DNSKEYs from %s: %s", z.Name, s.Name, err)
			return false
		}

		rem := []dns.RR{}

		for _, a := range r.Answer {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if _, ok := dnskeys[fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey)]; ok {
				rem = append(rem, dnskey)
			}
		}

		if len(rem) > 0 {
			updater := music.GetUpdater(s.Method)
			if err := updater.Update(s, z.Name, z.Name, nil, &[][]dns.RR{rem}); err != nil {
				log.Printf("%s: Unable to remove DNSKEYs from %s: %s", z.Name, s.Name, err)
				return false
			}
			log.Printf("%s: Removed DNSKEYs from %s successfully", z.Name, s.Name)
		}
	}

	z.StateTransition(FsmStateNsPropagated, FsmStateDnskeysSynced)
	return true
}

var FsmLeaveSyncDnskeys = music.FSMTransition{
	Description: "Once NSes has been propagated (NO criteria), remove DNSKEYs that originated from the leaving signer (Action)",
	Criteria:    fsmLeaveSyncDnskeysCriteria,
	Action:      fsmLeaveSyncDnskeysAction,
}
