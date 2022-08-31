//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//

package main

import (
	"log"
	"time"

	"github.com/DNSSEC-Provisioning/music/common"
	"github.com/spf13/viper"
)

func NewInterval(current, target, mininterval, maxinterval, count int) int {
	if count == 0 {
		if current < maxinterval {
			current = current * 2
		}
		if current > maxinterval {
			current = maxinterval
		}
		return current
	}
	current = target
	if current < mininterval {
		current = mininterval
	}
	return current
}

func FSMEngine(conf *Config, stopch chan struct{}) {
	mdb := conf.Internal.MusicDB
	var err error
	var count int
	var zones []music.Zone
	var foo music.EngineCheck
	var z string
	var emptymap = map[string]bool{}
	checkch := conf.Internal.EngineCheck

	if !viper.GetBool("fsmengine.active") {
		log.Printf("FSM Engine is NOT active. All state transitions must be managed manually.")
		for {
			select {
			case <-checkch: // ensure that we keep reading to keep the
				continue // channel open (otherwise other parts of MUSIC
			} // may block)
		}
	}

	mininterval := viper.GetInt("fsmengine.intervals.minimum")
	if mininterval < 15 {
		mininterval = 15
		viper.Set("fsmengine.mininterval", 15)
	}
	maxinterval := viper.GetInt("fsmengine.intervals.maximum")
	if maxinterval > 3600 {
		maxinterval = 3600
		viper.Set("fsmengine.maxinterval", 3600)
	}

	target := viper.GetInt("fsmengine.intervals.target")
	if target < mininterval || target > maxinterval {
		target = mininterval
	}
	current := target

	completeinterval := viper.GetInt("fsmengine.intervals.complete")
	if completeinterval < 3600 || completeinterval > 24*3600 {
		completeinterval = 7200
	}

	log.Printf("Starting FSM Engine (will run once every %d seconds)", current)

	ticker := time.NewTicker(time.Duration(current) * time.Second)
	completeticker := time.NewTicker(time.Duration(completeinterval) * time.Second)

	_, err = mdb.PushZones(nil, emptymap, true) // check ALL zones
	if err != nil {
		log.Printf("FSMEngine: Error from PushZones: %v", err)
	}

	UpdateTicker := func() {
		ni := NewInterval(current, target, mininterval, maxinterval, count)
		if ni != current {
			ticker.Stop()
			log.Printf("FSM Engine: changing run interval from %d to %d seconds", current, ni)
			current = ni
			ticker = time.NewTicker(time.Duration(current) * time.Second)
		}
	}

	ReportProgress := func() {
		count = len(zones)
		if count > 0 {
			log.Printf("FSM Engine: tried to move these zones forward: %v (will run every %d seconds)",
				zones, current)
		} else {
			log.Printf("FSM Engine: All zones are currently blocked (will run every %d seconds)",
				current)
		}
	}

	for {
		select {
		case foo = <-checkch:
			z = foo.Zone
			if z != "" {
				log.Printf("FSM Engine: Someone wants me to check the zone '%s', so I'll do that.",
					z)
				zones, err = mdb.PushZones(nil, map[string]bool{z: true}, false)
			} else {
				log.Print("FSM Engine: Someone wants me to do a run now, so I'll do that.")
				zones, err = mdb.PushZones(nil, emptymap, false)
			}
			if err != nil {
				log.Printf("FSMEngine: Error from PushZones: %v", err)
			}
			ReportProgress()
			UpdateTicker()

		case <-ticker.C:
			zones, err = mdb.PushZones(nil, emptymap, false) // check non-blocked zones only
			if err != nil {
				log.Printf("FSMEngine: Error from PushZones: %v", err)
			}
			ReportProgress()
			UpdateTicker()

		case <-completeticker.C:
			zones, err = mdb.PushZones(nil, emptymap, true) // check ALL zones
			if err != nil {
				log.Printf("FSMEngine: Error from PushZones: %v", err)
			}
			ReportProgress()
			UpdateTicker()

		case <-stopch:
			ticker.Stop()
			log.Println("FSM Engine: stop signal received.")
			return
		}
	}
}

