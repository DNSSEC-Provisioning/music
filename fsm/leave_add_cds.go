package fsm

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
        music "github.com/DNSSEC-Provisioning/music/common"
)

var FsmLeaveAddCDS = music.FSMTransition{
	Description: "Once all DNSKEYs are correct in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",

	MermaidPreCondDesc:  "TEXT",
	MermaidActionDesc:   "TEXT",
	MermaidPostCondDesc: "TEXT",

	PreCondition:    LeaveAddCDSPreCondition,
	Action:      	 LeaveAddCDSAction,
	PostCondition:	 func (z *music.Zone) bool { return true },
}

func LeaveAddCDSPreCondition(z *music.Zone) bool {
	sg := z.SignerGroup()
	if sg == nil {
	   log.Fatalf("Zone %s in process %s not attached to any signer group.", z.Name, z.FSM)
	}
	
	leavingSignerName := sg.PendingRemoval
	if leavingSignerName == "" {
		log.Fatalf("Leaving signer name in signer group %s unset.", sg.Name)
	}
	// leavingSignerName := "signer2.catch22.se." // Issue #34: Static leaving signer until metadata is in place

	// Need to get signer to remove records for it also, since it's not part of zone SignerMap anymore
	leavingSigner, err := z.MusicDB.GetSignerByName(leavingSignerName, false) // not apisafe
	if err != nil {
		log.Printf("%s: Unable to get leaving signer %s: %s", z.Name, leavingSignerName, err)
		return false
	}

	log.Printf("%s: Verifying that leaving signer %s DNSKEYs has been removed from all signers",
			z.Name, leavingSigner.Name)

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

		for _, a := range r.Answer {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if _, ok := dnskeys[fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey)]; ok {
				log.Printf("%s: DNSKEY %s still exists in signer %s", z.Name, dnskey.PublicKey, s.Name)
				return false
			}
		}
	}

	return true
}

func LeaveAddCDSAction(z *music.Zone) bool {
	log.Printf("%s: Creating CDS/CDNSKEY record sets", z.Name)

	cdses := []dns.RR{}
	cdnskeys := []dns.RR{}

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeDNSKEY)

		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way

		if err != nil {
			log.Printf("%s: Unable to fetch DNSKEYs from %s: %s", z.Name, s.Name, err)
			return false
		}

		for _, a := range r.Answer {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if f := dnskey.Flags & 0x101; f == 257 {
				cdses = append(cdses, dnskey.ToDS(dns.SHA256).ToCDS())
				cdnskeys = append(cdnskeys, dnskey.ToCDNSKEY())
			}
		}
	}

	// Create CDS/CDNSKEY records sets
	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name,
			&[][]dns.RR{cdses, cdnskeys}, nil); err != nil {
			log.Printf("%s: Unable to update %s with CDS/CDNSKEY record sets: %s",
				z.Name, signer.Name, err)
			return false
		}
		log.Printf("%s: Update %s successfully with CDS/CDNSKEY record sets", z.Name, signer.Name)
	}

	return true
}

