//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//

package music

import (
        "database/sql"
	"log"
)

const (
	AutoZones = `
SELECT name, zonetype, fsm, fsmsigner, fsmstatus
FROM zones WHERE fsmmode='auto' AND fsm != '' AND fsmstatus != 'blocked'`
	AllAutoZones = `
SELECT name, zonetype, fsm, fsmsigner, fsmstatus
FROM zones WHERE fsmmode='auto' AND fsm != ''` 
)

// PushZones: Try to move all "auto" zones forward through their respective processes until they
//            hit a stop.
//
// Note that we also need to add management for:
// (a) trying stopped zones, but less frequently, as they may have become unwedged
// (b)

func (mdb *MusicDB) PushZones(tx *sql.Tx, checkzones map[string]bool, checkall bool) ([]Zone, error) {
	var zones []Zone
	var stmt *sql.Stmt
	var err error

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return zones, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	if checkall {
	   stmt, err = mdb.Prepare(AllAutoZones)
	} else {
	   stmt, err = mdb.Prepare(AutoZones)
	}
	if err != nil {
		log.Fatalf("PushZones: Error from mdb.Prepare(%s): %v", AutoZones, err)
	}

	// tx, err := mdb.Begin()
//	if err != nil {
//		log.Fatalf("PushZones: Error from mdb.Begin(): %v", err)
//	}

	rows, err := stmt.Query()
	if err != nil {
		log.Printf("PushZones: Error from stmt query(%s): %v", AutoZones, err)
	}
	defer rows.Close()

	if CheckSQLError("PushZones", AutoZones, err, false) {
		return zones, err
	} else {
		var name, zonetype, fsm, fsmsigner, fsmstatus string
		for rows.Next() {
			err := rows.Scan(&name, &zonetype, &fsm, &fsmsigner, &fsmstatus)
			if err != nil {
				log.Fatalf("PushZones: Error from rows.Scan: %v", err)
			}

			z := Zone{ Name: name, FSMStatus: fsmstatus }

			if len(checkzones) == 0 {
			   zones = append(zones, z)
			} else {
			   if checkzones[name] {
			      zones = append(zones, z)
			   }
			}
		}
	}
	// tx.Commit()

	if len(zones) > 0 {
		log.Printf("PushZones: will push on these zones: %v", zones)
		for _, z := range zones {
		        if z.FSMStatus == "delayed" {
			   log.Printf("PushZones: zone %s is delayed until %v. Leaving for now.",
			   			  z.Name, "Kokko")
			} else {
			  mdb.PushZone(tx, z)
			}
		}
	} 
	return zones, nil
}

func (mdb *MusicDB) PushZone(tx *sql.Tx, z Zone) error {
	dbzone, _ := mdb.GetZone(tx, z.Name)
	success, _, _ := mdb.ZoneStepFsm(tx, dbzone, "")
	oldstate := dbzone.State
	if success {
		dbzone, _ := mdb.GetZone(tx, z.Name)
		log.Printf("PushZone: successfully transitioned zone '%s' from '%s' to '%s'",
			z, oldstate, dbzone.State)
	} else {
		log.Printf("PushZone: failed to transition zone '%s' from state '%s'",
			z, oldstate)
	}
	return nil
}
