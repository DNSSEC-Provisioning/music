package main

import (
	"fmt"
	"log"
	"os"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/DNSSEC-Provisioning/music/common"
)

func RunScannerNG(conf *Config, zonesng map[string]ZoneNG) {
	if len(zonesng) == 0 {
		log.Printf("RunScannerNG: no zones to scan.")
		os.Exit(1)
	}

	if !viper.GetBool("scanner.run-new") {
		fmt.Printf("Not using the new scanner\n")
		return
	}

	// This is just for printing out zone names.
	zs := ""
	for k, _ := range zonesng {
		zs += ", " + k
	}
	log.Printf("RunScanner: scanning %d zones: %s", len(zonesng), zs[2:])

	// Locate zone nameservers and current DS from the parent
	// var zone_nses []string
	for zone, z := range zonesng {
		var signer music.Signer
		var known bool

		z.DelegationNS = make(map[string]*ZoneNS)
		log.Printf("Working with zone %s (fetching DS + all NSes from parent)", zone)
		parent := conf.ParentMap[z.PName]
		if signer, known = conf.SignerMap[parent.Signer]; !known {
			log.Fatalf("Zone %s with parent %s depends on unknown signer '%s'",
				zone, z.PName, parent.Signer)
		}

		// Get DS records for zone from Parent

		z.CurrentDS = GetDS(zone, z.PName, signer.Address+":"+signer.Port)
		for _, ds := range z.CurrentDS {
			log.Printf("%s", ds)
		}
		log.Printf("*** Scanner: GetDS done ***")

		// get zone NSes from parent and create ZoneNS struct
		// zone_nses = GetNS(zone, z.PName, parent.Address)
//		updater_old := GetUpdaterNG("parent")
		updater := music.GetUpdater(signer.Method)
		err, ns_rrs := updater.FetchRRset(&signer, z.PName, zone, dns.TypeNS)
		if err != nil {
			log.Printf("Error from FetchRRset (%s, NS): %v", zone, err)
		}

		//		log.Printf("Old NS Fetcher:")
		//		for _, ns := range zone_nses {
		//			log.Printf("Zone %s: Got NS: %s", zone, ns)
		//			ip := GetIP(ns, parent.Address)
		//			zns := &ZoneNS{
		//				NSName:		ns,
		//				Address:	ip+":53",
		//			}
		//			z.DelegationNS[ns] = zns
		//			log.Printf("Zone %s: NS %s has address %s (old)", zone,
		//					 zns.NSName, zns.Address)
		//
		//		}

		//		log.Printf("New NS Fetcher:")
		for _, rr := range ns_rrs {
			nsrr := rr.(*dns.NS)
			log.Printf("%s", rr.String())
			log.Printf("Zone %s: Got NS: %s", zone, nsrr.Ns)
			ip := GetIP(nsrr.Ns, parent.Address) // wrong. parent may not be auth
			zns := &ZoneNS{
				NSName:  nsrr.Ns,
				Address: ip + ":53",
			}
			z.DelegationNS[nsrr.Ns] = zns
			log.Printf("Zone %s: NS %s has address %s (new)", zone,
				zns.NSName, zns.Address)
		}

		zonesng[zone] = z
		log.Printf("*** Scanner: GetNS done ***")
		
		//	}

		// Get zone data from each zone NS information
		//	for zone, z := range zonesng {
		log.Printf("Working with zone %s (checking data from %d NSes)",
			zone, len(z.DelegationNS))
		for _, zns := range z.DelegationNS {
			log.Printf("Working with zone %s NS: %s (fetch CDS+CSYNC)",
				zone, zns.NSName)
			zns.NSes = make(map[string]string)

			// Get CDS From zone nameserver
			zns.CDS = GetCDS(zone, zns.NSName, zns.Address)
			for _, cds := range zns.CDS {
				log.Printf("%s", cds)
			}
			// Get CSYNC From Child nameserver
			zns.CSYNC = GetCsyncNG(zone, zns.NSName, zns.Address)
			log.Printf("CSYNC from zone NS: %s", zns.CSYNC)

			// Get NSes from Child nameserver
			nses := GetNS(zone, zns.NSName, zns.Address)
			for _, ns := range nses {
				ip := GetIP(ns, zns.Address)
				log.Printf("IP from zns: %s", ip)
				zns.NSes[ns] = ""
			}
			log.Printf("NS from child: %v", nses)
		}
		log.Printf("*** Scanner: GetCDS+GetCSYNC done ***")
		
		//	}

		// Update DS information
		// for zone, parent := range zonesng {
		//	for zone, z := range zonesng {
		log.Printf("Zone %s: \n", zone)
		dsadd, dsremove := CreateDsUpdateNG(z)
		for _, rr := range dsadd {
			rr.Hdr.Rrtype = 43
		}

		adds := []dns.RR{}
		for _, value := range dsadd {
			adds = append(adds, &value.DS)
		}

		removes := []dns.RR{}
		for _, value := range dsremove {
			removes = append(removes, value)
		}
		log.Printf("value is a %T with value of %v", removes, removes)

		// trying to get ddns to work with nsupdater_updater.go

		output := []string{}
		if len(adds) != 0 || len(removes) != -0 {
//			err = updater_old.Update(z.PName, parent, &[][]dns.RR{adds}, &[][]dns.RR{removes}, &output)
//			if err != nil {
//				fmt.Printf("bob Got an err %v\n", err)
//			}
//			fmt.Println(output)

			err = updater.Update(&signer, z.PName, zone, &[][]dns.RR{adds},
				&[][]dns.RR{removes})
			if err != nil {
				log.Printf("Error: updater.Update(zone: %s, rr: %s DS): %v",
						   z.PName, zone, err)
			}
			fmt.Println(output)
		} else {
			log.Printf("Zone %s: Updating parent DS RRset: no change", zone)
		}
		log.Printf("*** Scanner: UpdateDS done ***")

		//	}

		// Update NS in parent
		updateNsFlag := 0

		//	for zone, z := range zonesng {
		output = []string{}
		log.Printf("Zone: %s", zone)
		flagCount := len(z.DelegationNS)
		for _, zns := range z.DelegationNS {
			if zns.CSYNC == "" {
				log.Printf("Zone %s: No CSYNC at %s, not updating %s NS in %s",
					zone, zone, z.PName)
			} else {
				updateNsFlag++
			}
		}
		if updateNsFlag == flagCount {
			log.Printf("CSYNC count even, updating parent with NSes")
			adds, removes, err := CreateNsUpdateNG(zone, z)
			if err != nil {
				fmt.Printf("CSYNC Update got err %v\n", err)
			}
//			parent := conf.ParentMap[z.PName]
//			err = updater_old.Update(z.PName, parent, &[][]dns.RR{adds},
//				&[][]dns.RR{removes}, &output)
//			if err != nil {
//				fmt.Printf("bob Got an err %v\n", err)
//			}
//			fmt.Println(output)

			err = updater.Update(&signer, z.PName, zone, &[][]dns.RR{adds},
				&[][]dns.RR{removes})
			if err != nil {
				log.Printf("Error: updater.Update(zone %s, RR: %s NS): %v",
						   z.PName, zone, err)
			}

		} else {
			log.Printf("CSYNC count uneven, no updating Parent with NSes")

		}
		log.Printf("*** Scanner: UpdateNS done ***")
		
	}
}

// if CDS's from children match
// - Update Parent if neccessary ( need to figure out the ttl bit )
// else
// - log error

// Get Csync from children
// if Csync from children match
//  - check intent update parent as necessary
// else
//  - log error

// Ignore CDNSKEY for now
