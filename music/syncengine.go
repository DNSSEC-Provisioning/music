//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//

package music

import (
	"log"
	"time"

	//	"github.com/DNSSEC-Provisioning/music/music"
	tdns "github.com/johanix/tdns/tdns"
	"github.com/spf13/viper"
)

type Sidecar struct {
	Name       string
	Addresses  []string
	Port       uint16
	LastHB     time.Time
	LastFullHB time.Time
	HBCount    int
	Zones      []string
}

func MusicSyncEngine(mconf *Config, stopch chan struct{}) {
	// mdb := mconf.Internal.MusicDB
	// var err error

	var sidecars map[string]Sidecar
	var missing []string
	var zonename string
	var syncitem tdns.MultiSignerSyncRequest
	syncQ := mconf.Internal.MultiSignerSyncQ

	if !viper.GetBool("syncengine.active") {
		log.Printf("MusicSyncEngine is NOT active. No detection of of communication with other music-sidecars will be done.")
		for {
			select {
			case <-syncQ: // ensure that we keep reading to keep the
				log.Printf("MusicSyncEngine: NOT active, butreceived a sync request: %+v", syncitem)
				continue // channel open (otherwise other parts of MUSIC
			} // may block)
		}
	}

	hbinterval := viper.GetInt("syncengine.intervals.heartbeat")
	if hbinterval > 1800 {
		hbinterval = 1800
	}
	if hbinterval < 15 {
		hbinterval = 15
	}
	viper.Set("syncengine.intervals.heartbeat", 15)

	fullhbinterval := viper.GetInt("syncengine.intervals.fullheartbeat")
	if fullhbinterval > 3600 {
		fullhbinterval = 3600
	}
	if fullhbinterval < 60 {
		fullhbinterval = 60
	}
	viper.Set("syncengine.intervals.fullheartbeat", fullhbinterval)

	log.Printf("Starting MusicSyncEngine (heartbeat will run once every %d seconds)", hbinterval)

	HBticker := time.NewTicker(time.Duration(hbinterval) * time.Second)
	fullHBticker := time.NewTicker(time.Duration(fullhbinterval) * time.Second)

	ReportProgress := func() {
		allok := true
		if allok {
			log.Printf("MusicSyncEngine: received heartbeats from these sidecars: %v (the expected result)", sidecars)
		} else {
			log.Printf("MusicSyncEngine: received heartbeats from these sidecars: %v (missing some sidecars: %v)",
				sidecars, missing)
		}
	}

	for {
		select {
		case syncitem = <-syncQ:
			cmd := syncitem.Command
			zonename = syncitem.ZoneName
			switch cmd {
			case "RESET-MSIGNER-GROUP":
				log.Printf("MusicSyncEngine: Zone %s MSIGNER RRset has changed. Resetting MSIGNER group.", zonename)

			case "SYNC-DNSKEY-RRSET":
				log.Printf("MusicSyncEngine: Zone %s DNSKEY RRset has changed. Should send NOTIFY(DNSKEY) to other sidecars.", zonename)

			default:
				log.Printf("MusicSyncEngine: Unknown command: %s in request: %+v", cmd, syncitem)
			}
			ReportProgress()

		case <-HBticker.C:
			log.Printf("MusicSyncEngine: Heartbeat ticker. Contacting other known music-sidecars.")
			ReportProgress()

		case <-fullHBticker.C:
			log.Printf("MusicSyncEngine: Full Heartbeat ticker. Contacting other known music-sidecars with complete zone lists.")
			ReportProgress()

		case <-stopch:
			HBticker.Stop()
			fullHBticker.Stop()
			log.Println("MusicSyncEngine: stop signal received.")
			return
		}
	}
}
