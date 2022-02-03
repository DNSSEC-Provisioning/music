package fsm

import (
	"fmt"
	"log"
	"time"

	music "github.com/DNSSEC-Provisioning/music/common"
	"github.com/miekg/dns"
)

var zoneWaitDs map[string]time.Time // Issue #34: using local store for now

func init() {
	zoneWaitDs = make(map[string]time.Time)
}

var FsmJoinWaitDs = music.FSMTransition{
	Description: "Wait enough time for parent DS records to propagate (criteria), then sync NS records between all signers (action)",

	MermaidPreCondDesc:  "Wait for DS to propagate",
	MermaidActionDesc:   "Sync NS RRsets between all signers",
	MermaidPostCondDesc: "Verify that NS RRsets are in sync",

	PreCondition: JoinWaitDsPreCondition,
	Action:       JoinWaitDsAction,
	PostCondition: func(z *music.Zone) bool {
		// verify that the NS RRset is in sync for all signers
		return true
	},
}

func JoinWaitDsPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
		log.Printf("JoinWaitDsPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	if until, ok := zoneWaitDs[z.Name]; ok {
		if time.Now().Before(until) {
			stopreason := fmt.Sprintf("%s: Waiting until %s (%s)", z.Name, until.String(), time.Until(until).String())
			err, _ := z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
			if err != nil {
				log.Printf("JoinWaitDsPreCondition: Could not update stop-reason \n")
			}
			log.Printf("%s\n", stopreason)
			return false
		}
		log.Printf("%s: Waited enough for DS, pre-condition fullfilled", z.Name)
		delete(zoneWaitDs, z.Name)
		return true
	}

	log.Printf("JoinWaitDsPreCondition: %s: Fetching DNSKEYs and DSes to calculate DS wait until", z.Name)

	var ttl uint32

	for _, signer := range z.SGroup.SignerMap {

		updater := music.GetUpdater(signer.Method)
		err, rrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("JoinWaitDsPreCondition: Error from updater.FetchRRset: %v\n", err)
		}

		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			if dnskey.Header().Ttl > ttl {
				ttl = dnskey.Header().Ttl
			}
		}
	}

	parentAddress, err := z.GetParentAddressOrStop()
	if err != nil {
		return false
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeDS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, parentAddress)
	if err != nil {
		stopreason := fmt.Sprintf("%s: Unable to fetch DSes from parent: %s", z.Name, err)
		err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
		log.Printf("%s\n", stopreason)
		return false
	}

	for _, a := range r.Answer {
		ds, ok := a.(*dns.DS)
		if !ok {
			continue
		}

		if ds.Header().Ttl > ttl {
			ttl = ds.Header().Ttl
		}
	}

	// until := time.Now().Add((time.Duration(ttl*2) * time.Second))
	// TODO: static wait time to enable faster testing
	until := time.Now().Add((time.Duration(5) * time.Second))

	stopreason := fmt.Sprintf("%s: Largest TTL found was %d, waiting until %s (%s)", z.Name, ttl,
		until.String(), time.Until(until).String())
	err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
	log.Printf("%s\n", stopreason)

	zoneWaitDs[z.Name] = until

	return false
}

func JoinWaitDsAction(z *music.Zone) bool {
	log.Printf("JoinWaitDsAction: %s: Fetch all NS records from all signers", z.Name)

	if z.ZoneType == "debug" {
		log.Printf("JoinWaitDsAction: zone %s (DEBUG) is automatically ok", z.Name)
		return true
	}

	nses := make(map[string][]*dns.NS)

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		log.Printf("JoinWaitDsAction: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(signer, z.Name, z.Name, dns.TypeNS)
		if err != nil {
			stopreason := fmt.Sprintf("Error from updater.FetchRRset: %v\n", err)
			err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
			log.Printf("%s\n", stopreason)
		}

		nses[signer.Name] = []*dns.NS{}

		for _, a := range rrs {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}

			nses[signer.Name] = append(nses[signer.Name], ns)

			stmt, err := z.MusicDB.Prepare("INSERT OR IGNORE INTO zone_nses (zone, ns, signer) VALUES (?, ?, ?)")
			if err != nil {
				log.Printf("%s: Statement prepare failed: %s", z.Name, err)
				return false
			}

			res, err := stmt.Exec(z.Name, ns.Ns, signer.Name)
			if err != nil {
				log.Printf("%s: Statement execute failed: %s", z.Name, err)
				return false
			}
			rows, _ := res.RowsAffected()
			if rows > 0 {
				log.Printf("%s: Origin for %s set to %s", z.Name, ns.Ns, signer.Name)
			}
		}
	}

	log.Printf("%s: Creating NS record sets", z.Name)

	// Map all known NSes
	nsmap := make(map[string]*dns.NS)
	for _, rrs := range nses {
		for _, rr := range rrs {
			nsmap[rr.Ns] = rr
		}
	}
	// Create RRset for insert
	nsset := []dns.RR{}
	for _, rr := range nsmap {
		nsset = append(nsset, rr)
	}

	// TODO: is this needed here also?
	//       Old code made sure the configured NS for each signer was added
	// for _, signer := range signers {
	//     ns := Config.Get("signer-ns:"+signer, "")
	//     if ns == "" {
	//         continue
	//     }
	//     if _, ok := nsmap[ns]; !ok {
	//         rr := new(dns.NS)
	//         rr.Hdr = dns.RR_Header{Name: args[0], Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(ttl)}
	//         rr.Ns = ns
	//         nsset = append(nsset, rr)
	//     }
	// }

	for _, signer := range z.SGroup.SignerMap {
		updater := music.GetUpdater(signer.Method)
		if err := updater.Update(signer, z.Name, z.Name, &[][]dns.RR{nsset}, nil); err != nil {
			stopreason := fmt.Sprintf("%s: Unable to update %s with NS record sets: %s", z.Name, signer.Name, err)
			err, _ = z.MusicDB.ZoneSetMeta(z, "stop-reason", stopreason)
			log.Printf("%s\n", stopreason)
			return false
		}
		log.Printf("%s: Update %s successfully with NS record sets", z.Name, signer.Name)
	}

	// XXX: What should we do here? If we don't do the state transition
	//      then the delete is wrong.
	// z.StateTransition(FsmStateParentDsSynced, FsmStateDsPropagated)
	// The delete has moved to the true-branch of the PreCondition.
	// delete(zoneWaitDs, z.Name)
	return true
}
