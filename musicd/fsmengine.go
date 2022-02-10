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

func FSMEngine(conf *Config, stopch chan struct{}) {
	var err error

	runinterval := viper.GetInt("fsmengine.interval")
	if runinterval < 10 || runinterval > 3600 {
		runinterval = 60
	}

	ticker := time.NewTicker(time.Duration(runinterval) * time.Second)

	for {
		select {
		case <-ticker.C:
			err = PushZones(conf)
			if err != nil {
				log.Printf("FSMEngine: Error from PushZones: %v", err)
			}

		case <-stopch:
			ticker.Stop()
			log.Println("FSM Engine: stop signal received.")
			return
		}
	}
}

const (
      AutoZones = `
SELECT name, zonetype, fsm, fsmsigner, fsmstate
FROM zones WHERE fsmmode='auto' AND fsm != '' AND fsmstate != 'stop'`
)

// PushZones: Try to move all "auto" zones forward through their respective processes until they
//            hit a stop.
//
// Note that we also need to add management for:
// (a) trying stopped zones, but less frequently, as they may have become unwedged
// (b) 

func PushZones(conf *Config) error {
     mdb := conf.Internal.MusicDB
     var zones []string
     stmt, err := mdb.Prepare(AutoZones)
     if err != nil {
     	log.Fatalf("PushZones: Error from mdb.Prepare(%s): %v", AutoZones, err)
     }

     tx, err := mdb.Begin()
     if err != nil {
     	log.Fatalf("PushZones: Error from mdb.Begin(): %v", err)
     }

     	rows, err := stmt.Query()
	if err != nil {
		log.Printf("PushZones: Error from stmt query(%s): %v", AutoZones, err)
	}
	defer rows.Close()

	if music.CheckSQLError("PushZones", AutoZones, err, false) {
		return err
	} else {
	  var name, zonetype, fsm, fsmsigner, fsmstate string
	  for rows.Next() {
	      err := rows.Scan(&name, &zonetype, &fsm, &fsmsigner, &fsmstate)
	      if err != nil {
	      	 log.Fatalf("PushZones: Error from rows.Scan: %v", err)
	      }

	      zones = append(zones, name)

	  }
	}
	tx.Commit()
	
	log.Printf("PushZones: will push on these zones: %v", zones)
	return nil
}