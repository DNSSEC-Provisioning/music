package fsm

import (
	// "fmt"
	"log"
	"time"

	"github.com/miekg/dns"
        music "github.com/DNSSEC-Provisioning/music/common"
)

var zoneWaitNs map[string]time.Time // Issue #34: using local store for now

func init() {
	zoneWaitNs = make(map[string]time.Time)
}

var FsmLeaveWaitNs = music.FSMTransition{
	Description: "Wait enough time for parent NS records to propagate (criteria), then continue (NO action)",

	MermaidPreCondDesc:  "Wait long enough for parent NS records to propagate",
	MermaidActionDesc:   "Continue after waiting (no action)",
	MermaidPostCondDesc: "None",
	
	PreCondition:   LeaveWaitNsPreCondition,
	Action:      	LeaveWaitNsAction,
	PostCondition:	func (z *music.Zone) bool { return true },
}

func LeaveWaitNsPreCondition(z *music.Zone) bool {
	if z.ZoneType == "debug" {
	   log.Printf("LeaveWaitNsPreCondition: zone %s (DEBUG) is automatically ok", z.Name)
	   return true
	}

	if until, ok := zoneWaitNs[z.Name]; ok {
		if time.Now().Before(until) {
			log.Printf("%s: Waiting until %s (%s)", z.Name, until.String(), time.Until(until).String())
			return false
		}
		log.Printf("%s: Waited enough for NS, critera fullfilled", z.Name)
		delete(zoneWaitNs, z.Name)
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

	var ttl uint32

	log.Printf("%s: Fetching NSes to calculate NS wait until", z.Name)

	for _, s := range z.SGroup.SignerMap {
		m := new(dns.Msg)
		m.SetQuestion(z.Name, dns.TypeNS)
		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.Address+":53") // TODO: add DnsAddress or solve this in a better way
		if err != nil {
			log.Printf("%s: Unable to fetch NSes from %s: %s", z.Name, s.Name, err)
			return false
		}

		for _, a := range r.Answer {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}

			if ns.Header().Ttl > ttl {
				ttl = ns.Header().Ttl
			}
		}
	}

	m := new(dns.Msg)
	m.SetQuestion(z.Name, dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, leavingSigner.Address+":53") // TODO: add DnsAddress or solve this in a better way
	if err != nil {
		log.Printf("%s: Unable to fetch NSes from %s: %s", z.Name, leavingSigner.Name, err)
		return false
	}

	for _, a := range r.Answer {
		ns, ok := a.(*dns.NS)
		if !ok {
			continue
		}

		if ns.Header().Ttl > ttl {
			ttl = ns.Header().Ttl
		}
	}

	// parentAddress := "13.48.238.90:53" // Issue #33: using static IP address for msat1.catch22.se for now

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

		if ns.Header().Ttl > ttl {
			ttl = ns.Header().Ttl
		}
	}

	// until := time.Now().Add((time.Duration(ttl*2) * time.Second))
	// TODO: static wait time to enable faster testing
	until := time.Now().Add((time.Duration(5) * time.Second))

	log.Printf("%s: Largest TTL found was %d, waiting until %s (%s)", z.Name, ttl, until.String(), time.Until(until).String())

	zoneWaitNs[z.Name] = until
	return false
}

func LeaveWaitNsAction(z *music.Zone) bool {
     	// XXX: What should we do about the delete() after the state transition?
	// z.StateTransition(FsmStateParentNsSynced, FsmStateNsPropagated)
	// The delete action has moved to the true-branch of the PreCondition
	// delete(zoneWaitNs, z.Name)
	return true
}

