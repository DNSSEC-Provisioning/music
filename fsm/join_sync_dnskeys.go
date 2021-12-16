package fsm

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
        music "github.com/DNSSEC-Provisioning/music/common"
)

// Transition SIGNERS-UNSYNCHED --> DNSKEYS-SYNCHED:

// PRE-CONDITION (aka CRITERIA): None
// ACTION: get all ZSKs for all signers included in the DNSKEY RRset on all signers
// POST-CONDITION: verify that all ZSKs are included in all DNSKEY RRsets on all signers

var FsmJoinSyncDnskeys = music.FSMTransition{
	Description:         "First step when joining, this transistion has no criteria and will sync DNSKEYs between all signers (action)",
	MermaidCriteriaDesc: "",
	MermaidPreCondDesc:  "",
	MermaidActionDesc:   "Update all signer DNSKEY RRsets with all ZSKs",
	MermaidPostCondDesc: "Verify that all ZSKs are published in signer DNSKEY RRsets",
	Criteria:            func(z *music.Zone) bool { return true },
	PreCondition:        func(z *music.Zone) bool { return true },
	Action:              JoinSyncDnskeys,
	PostCondition:       VerifyDnskeysSynched,
}

// XXX: Is it always true that the PostCondition for one action is equal to the PreCondition
//      for the next action? I think so. I.e. this implementation (VerifyDnskeysSynched) is
//      extremely similar to the JoinAddCdsCriteria function that is the PreCondition for
//      the next step (adding CDS/CDNSKEYs).
func VerifyDnskeysSynched(z *music.Zone) bool {
	// 1: for each signer:
	// 1.a. get DNSKEY RRset, extract all ZSKs,
	// 1.b. store all zsks in a map[keyid]key per signer
	// 1.c. store all zsks in a map[keyid]key for all signers
	// 1.d. end
	// 2: for each signer:
	// 2.a. if len(pool) > len(zsks for this signer) ==> failure
	// 2.b. if keyid(zsk) in pool not among keyid(zsks) for signer ==> failure
	// 2.c. if pubkey(zsk) in pool not among pubkey(zsks) for signer ==> failure
	// 2. end
	// return success

	signerzsks := make(map[string]map[uint16]*dns.DNSKEY)
	allzsks := make(map[uint16]*dns.DNSKEY)

	log.Printf("VerifyDnskeysSynched: Fetching all ZSKs for %s.\n", z.Name)

	for _, s := range z.SGroup.SignerMap {

		updater := music.GetUpdater(s.Method)
		log.Printf("VerifyDnskeysSynched: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		signerzsks[s.Name] = map[uint16]*dns.DNSKEY{}
		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			log.Printf("Rececived key from %s: keyid=%d flags=%d\n", s.Name, dnskey.KeyTag(), dnskey.Flags)
			// only store ZSKs in DB
			if f := dnskey.Flags & 0x101; f == 256 {
				signerzsks[s.Name][dnskey.KeyTag()] = dnskey
				allzsks[dnskey.KeyTag()] = dnskey
				stmt, err := z.MusicDB.Prepare("INSERT OR IGNORE INTO zone_dnskeys (zone, dnskey, signer) VALUES (?, ?, ?)")
				if err != nil {
					log.Printf("%s: Statement prepare failed: %s", z.Name, err)
					return false
				}

				res, err := stmt.Exec(z.Name, fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey), s.Name)
				if err != nil {
					log.Printf("%s: Statement execute failed: %s", z.Name, err)
					return false
				}
				rows, _ := res.RowsAffected()
				if rows > 0 {
					log.Printf("%s: Origin for %s set to %s", z.Name, dnskey.PublicKey, s.Name)
				}
			}
		}
	}

	log.Printf("VerifyDnskeysSynched: Comparing ZSK RRs for %s... ", z.Name)
	for _, s := range z.SGroup.SignerMap {
		if len(allzsks) != len(signerzsks[s.Name]) {
			log.Printf("%s: Signer %s has %d ZSKs (should be %d)\n",
				z.Name, s.Name, len(signerzsks[s.Name]), len(allzsks))
			return false
		}
		for id, dnskey := range allzsks {
			var k *dns.DNSKEY
			var exist bool
			if k, exist = signerzsks[s.Name][id]; !exist {
				log.Printf("%s: ZSK with keyid=%d does not exist in signer %s\n",
					z.Name, id, s.Name)
				return false
			}
			if k.PublicKey != dnskey.PublicKey {
				log.Printf("%s: ZSK with keyid=%d in signer %s has inconsistent key material\n",
					z.Name, id, s.Name)
				return false
			}

		}
	}
	fmt.Printf("All good.\n")
	return true
}

func JoinSyncDnskeys(z *music.Zone) bool {
	dnskeys := make(map[string][]*dns.DNSKEY)

	log.Printf("%s: Syncing DNSKEYs in group %s", z.Name, z.SGroup.Name)

	for _, s := range z.SGroup.SignerMap {

		updater := music.GetUpdater(s.Method)
		log.Printf("JoinSyncDnskeys: Using FetchRRset interface:\n")
		err, rrs := updater.FetchRRset(s, z.Name, z.Name, dns.TypeDNSKEY)
		if err != nil {
			log.Printf("Error from updater.FetchRRset: %v\n", err)
		}

		// signerzsks[s.Name] = map[uint16]*dns.DNSKEY{}

		dnskeys[s.Name] = []*dns.DNSKEY{}
		for _, a := range rrs {
			dnskey, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}

			dnskeys[s.Name] = append(dnskeys[s.Name], dnskey)

			if f := dnskey.Flags & 0x101; f == 256 {
				stmt, err := z.MusicDB.Prepare("INSERT OR IGNORE INTO zone_dnskeys (zone, dnskey, signer) VALUES (?, ?, ?)")
				if err != nil {
					log.Printf("%s: Statement prepare failed: %s", z.Name, err)
					return false
				}

				res, err := stmt.Exec(z.Name, fmt.Sprintf("%d-%d-%s", dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey), s.Name)
				if err != nil {
					log.Printf("%s: Statement execute failed: %s", z.Name, err)
					return false
				}
				rows, _ := res.RowsAffected()
				if rows > 0 {
					log.Printf("%s: Origin for %s set to %s", z.Name, dnskey.PublicKey, s.Name)
				}
			}
		}

		if len(dnskeys[s.Name]) > 0 {
			log.Printf("%s: Fetched DNSKEYs from %s:", z.Name, s.Name)
			for _, k := range dnskeys[s.Name] {
				if f := k.Flags & 0x101; f == 256 {
					log.Printf("%s: - %d (ZSK) %s...", z.Name, int(k.KeyTag()), k.PublicKey[:20])
				} else {
					log.Printf("%s: - %d (KSK) %s...", z.Name, int(k.KeyTag()), k.PublicKey[:20])
				}
			}
		} else {
			log.Printf("%s: No DNSKEYs found in %s", z.Name, s.Name)
		}
	}

	// for each signer, check every other_signer if it's missing signer's DNSKEYs
	for signer, keys := range dnskeys {
		for _, key := range keys {
			if f := key.Flags & 0x101; f == 256 { // only process ZSK's
				for other_signer, other_keys := range dnskeys {
					if other_signer == signer {
						continue
					}

					found := false
					for _, other_key := range other_keys {
						if other_key.PublicKey == key.PublicKey {
							// if other_key.Protocol != key.Protocol {
							//     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but missmatch Protocol: %s", other_signer, key.PublicKey))
							//     break
							// }
							// if other_key.Algorithm != key.Algorithm {
							//     *output = append(*output, fmt.Sprintf("Found DNSKEY in %s but missmatch Protocol: %s", other_signer, key.PublicKey))
							//     break
							// }
							found = true
							break
						}
					}

					if !found {
						// add a DNSKEY that we had but other signer did not
						s := z.SGroup.SignerMap[other_signer]
						updater := music.GetUpdater(s.Method)
						if err := updater.Update(s, z.Name, z.Name,
							&[][]dns.RR{[]dns.RR{key}}, nil); err != nil {
							log.Printf("%s: Unable to update %s with new DNSKEY %s: %s", z.Name, other_signer, key.PublicKey, err)
							return false
						}
						log.Printf("%s: Added %s's DNSKEY %s to %s", z.Name, signer, key.PublicKey, other_signer)
					} else {
						log.Printf("%s: %s's DNSKEY %s already exists in %s", z.Name, signer, key.PublicKey, other_signer)
					}
				}
			}
		}
	}

	return true
}
