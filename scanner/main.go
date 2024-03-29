package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/DNSSEC-Provisioning/music/music"
)

func main() {
	var conf Config
	viper.SetConfigFile(DefaultCfgFile)
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("viper: Could not load config (%s)", err)
	}

	ValidateConfig(nil, DefaultCfgFile) // will terminate on error

	conf.MusicDB, err = music.NewDB(viper.GetString("scanner.db"), "", false)
	if err != nil {
		log.Fatalf("Error from NewDB(%s): %v", viper.GetString("scanner.db"), err)
	}

	// zones is the list of zones the scanner will be monitoring
	zones := ReadConf(viper.GetString("scanner.zones"))

	err = ReadConfNG(&conf)
	if err != nil {
		log.Fatalf("This cannot happen (ReadConfNG returning an error)")
	}
	fmt.Printf("Zones NG: %v\n", conf.ZoneMap)

	interval := viper.GetInt("scanner.interval")
	if interval < 10 || interval > 900 {
		interval = 60
	}
	log.Printf("Scanner: will run once every %d seconds\n", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	runcount := 1
	RunScanner(zones)
	RunScannerNG(&conf, conf.ZoneMap)
	log.Printf("***** Run %d complete *****", runcount)

	for {
		select {
		case <-ticker.C:
			runcount++
			log.Printf("***** Starting run %d ****", runcount)
			RunScanner(zones)
			RunScannerNG(&conf, conf.ZoneMap)
			log.Printf("***** Run %d complete ****", runcount)

			// no default case
		}
	}
}

func RunScanner(zones map[string]*Parent) {
	zs := ""
	if len(zones) == 0 {
		log.Printf("RunScanner: no zones to scan.")
		os.Exit(1)
	}

	if !viper.GetBool("scanner.run-old") {
		fmt.Printf("Not using the old scanner\n")
		return
	}

	for k, _ := range zones {
		zs += ", " + k
	}
	log.Printf("RunScanner: scanning %d zones: %s", len(zones), zs[2:])
	var child_nses []string

	for zone, parent := range zones {
		parent.child_ns = make(map[string]*Child)
		log.Printf("Working with zone: %s ", zone)

		// Get DS records for zone from Parent
		parent.ds = GetDS(zone, parent.hostname, parent.ip+":"+parent.port)
		for _, ds := range parent.ds {
			log.Printf("%s", ds)
		}

		// get child NSes from Parent and create Child struct
		child_nses = GetNS(zone, parent.hostname, parent.ip+":"+parent.port)
		for _, ns := range child_nses {
			log.Printf("Got NS: %s", ns)
			ip := GetIP(ns, parent.ip+":"+parent.port)
			child := &Child{
				hostname: ns,
				ip:       ip,
				port:     "53",
			}
			parent.child_ns[ns] = child
			log.Printf("%s has ip %s", child.hostname, child.ip)

		}
	}

	// Get Child information
	for zone, parent := range zones {
		log.Printf("Working with Zone: %s", zone)
		for _, child := range parent.child_ns {
			log.Printf("Working with Child NS: %s", child.hostname)
			child.nses = make(map[string]string)

			// Get CDS From Child
			child.cds = GetCDS(zone, child.hostname, child.ip+":"+child.port)
			for _, cds := range child.cds {
				log.Printf("%s", cds)
			}
			// Get CSYNC From Child
			child.csync = GetCsync(zone, child.hostname, child.ip, child.port)
			log.Printf("CSYNC from child: %s", child.csync)

			// Get NSes from Child
			nses := GetNS(zone, child.hostname, child.ip+":"+child.port)
			for _, ns := range nses {
				ip := GetIP(ns, child.ip+":"+child.port)
				log.Printf("IP from child: %s", ip)
				child.nses[ns] = ""
			}
			log.Printf("NS from child: %v", nses)
		}
	}

	// Update DS information
	for zone, parent := range zones {
		log.Printf("Zone %s\n", zone)
		dsadd, dsremove := CreateDsUpdate(zone, parent)
		for _, value := range dsadd {
			value.Hdr.Rrtype = 43
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
		updater := GetUpdater("nsupdate")
		err := updater.Update(parent.pzone, parent, &[][]dns.RR{adds}, &[][]dns.RR{removes}, &output)
		if err != nil {
			fmt.Printf("bob Got an err %v\n", err)
		}
		fmt.Println(output)
	}

	// Update NS in parent
	updateNsFlag := 0

	for zone, parent := range zones {
		output := []string{}
		log.Printf("Zone: %s", zone)
		flagCount := len(parent.child_ns)
		for _, child := range parent.child_ns {
			if child.csync == "" {
				log.Printf("No Csync, not updating Parent with NSes")
			} else {
				updateNsFlag++
			}
		}
		if updateNsFlag == flagCount {
			log.Printf("Csync count even, updating Parent with NSes")
			adds, removes, err := CreateNsUpdate(zone, parent)
			if err != nil {
				fmt.Printf("Csync Update got err %v\n", err)
			}
			updater := GetUpdater("nsupdate")
			err = updater.Update(parent.pzone, parent, &[][]dns.RR{adds}, &[][]dns.RR{removes}, &output)
			if err != nil {
				fmt.Printf("bob Got an err %v\n", err)
			}

		} else {
			log.Printf("Csync count uneven, no updating Parent with NSes")

		}
		fmt.Println(output)
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
