/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

func (z *Zone) SignerGroup() *SignerGroup {
	return z.SGroup
}

func (mdb *MusicDB) AddZone(z *Zone, group string, enginecheck chan EngineCheck) (string, error) {

        var tx *sql.Tx
	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return "fail", err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	fqdn := dns.Fqdn(z.Name)
	dbzone, _, err := mdb.GetZone(tx, fqdn)
	if err != nil {
	   return "", err
	}
	if dbzone.Exists {
		return "", fmt.Errorf("Zone %s already present in MuSiC system.", fqdn)
	}

	const AZsql = `
INSERT INTO zones(name, zonetype, state, statestamp, fsm, fsmmode)
VALUES (?, ?, ?, datetime('now'), ?, ?)`

	stmt, err := mdb.Prepare(AZsql)
	if err != nil {
		log.Printf("Error in SQL prepare(%s): %v", AZsql, err)
		return fmt.Sprintf("Error in SQL prepare(%s): %v", AZsql, err), err
	}

	_, err = stmt.Exec(fqdn, z.ZoneType, "", "", z.FSMMode)
	if CheckSQLError("AddZone", AZsql, err, false) {
		return "", err
	}

	if group != "" {
		fmt.Printf("AddGroup: the zone %s has the signergroup %s specified so we set that too\n", z.Name, group)
		dbzone, _, err := mdb.GetZone(tx, z.Name)
		if err != nil {
		   return "", err
		}
		_, err = mdb.ZoneJoinGroup(tx, dbzone, group, enginecheck) // we know that the zone exist
		if err != nil {
			return fmt.Sprintf(
				"Zone %s was added, but failed to attach to signer group %s.", fqdn, group), err
		} else {
			return fmt.Sprintf(
				"Zone %s was added and immediately attached to signer group %s.", fqdn, group), err
		}
	}
	return fmt.Sprintf("Zone %s was added but is not yet attached to any signer group.",
		fqdn), nil
}

const (
	UZsql = "UPDATE zones SET zonetype=?, fsmmode=? WHERE name=?"
)

func (mdb *MusicDB) UpdateZone(dbzone, uz *Zone, enginecheck chan EngineCheck) (error, string) {
	log.Printf("UpdateZone: zone: %v", uz)

	var tx *sql.Tx
	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("UpdateZone: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	stmt, err := mdb.Prepare(UZsql)
	if err != nil {
		fmt.Printf("Error in SQL prepare(%s): %v", UZsql, err)
	}

	if uz.ZoneType != "" {
		dbzone.ZoneType = uz.ZoneType
	}

	if uz.FSMMode != "" {
		dbzone.FSMMode = uz.FSMMode
	}

	_, err = stmt.Exec(dbzone.ZoneType, dbzone.FSMMode, dbzone.Name)
	if CheckSQLError("UpdateZone", UZsql, err, false) {
		return err, ""
	}

	if uz.FSMMode == "auto" {
	   enginecheck <- EngineCheck{ Zone: dbzone.Name }
	}

	return nil, fmt.Sprintf("Zone %s updated.", dbzone.Name)
}

func (mdb *MusicDB) DeleteZone(z *Zone) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	var tx *sql.Tx
	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("DeleteZone: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	sg := z.SignerGroup()
	if sg != nil {
		err, _ := mdb.ZoneLeaveGroup(z, sg.Name)
		if err != nil {
			log.Printf("DeleteZone: Error from ZoneLeaveGroup(%s, %s): %v", z.Name, sg.Name, err)
		}
	}

	if err != nil {
		log.Printf("DeleteZone: Error from mdb.Begin(): %v", err)
	}

	stmt, err := mdb.Prepare("DELETE FROM zones WHERE name=?")
	if err != nil {
		fmt.Printf("DeleteZone: Error from db.Prepare: %v\n", err)
	}
	_, err = stmt.Exec(z.Name)
	if err != nil {
		fmt.Printf("DeleteZone: Error from stmt.Exec: %v\n", err)
	}
	stmt, err = mdb.Prepare("DELETE FROM records WHERE zone=?")
	_, err = stmt.Exec(z.Name)
	stmt, err = mdb.Prepare("DELETE FROM metadata WHERE zone=?")
	_, err = stmt.Exec(z.Name)

	if CheckSQLError("DeleteZone", "DELETE FROM ... WHERE zone=...", err, false) {
		return err, ""
	}

	deletemsg := fmt.Sprintf("Zone %s deleted.", z.Name)
	processcomplete, msg, err := mdb.CheckIfProcessComplete(tx, sg)
	if err != nil {
	   return err, fmt.Sprintf("Error from CheckIfProcessComplete(): %v", err)
	}
	if processcomplete {
		return nil, deletemsg + "\n" + msg
	}
	return nil, deletemsg
}

func (z *Zone) SetStopReason(tx *sql.Tx, value string) (error, string) {
	mdb := z.MusicDB

//	localtx, tx, err := mdb.StartTransaction(tx)
//	if err != nil {
//		log.Printf("SetStopReason: Error from mdb.StartTransaction(): %v\n", err)
//		return err, "fail"
//	}
//	defer mdb.CloseTransaction(localtx, tx, err)

//	err, msg := mdb.ZoneSetMeta(tx, z, "stop-reason", value)
//	if err != nil {
//		return err, msg
//	}

//	const DSsql = "UPDATE zones SET fsmstatus='blocked' WHERE name=?"
//	stmt, err1 := mdb.Prepare(DSsql)
//	if err1 != nil {
//		log.Fatalf("DocumentStop: Error from mdb.Prepare(%s): %v", DSsql, err)
//	}
//
//	_, err1 = stmt.Exec(z.Name)
//	if err1 != nil {
//		log.Fatalf("DocumentStop: Error from mdb.Exec(%s): %v", DSsql, err)
//	}

	mdb.UpdateC <- DBUpdate{
		        Type:	"STOPREASON",
			Zone:	z.Name,
			Key:	"stop-reason",
			Value:	value,
		       }

	log.Printf("%s: %s\n", z.Name, value)
//	return err, msg
	return nil, fmt.Sprintf("Zone %s stop-reason documented as '%s'", z.Name, value)
}

// XXX: SetDelayReason is not yet in use, but is needed for the wait-for-parent-ds stuff
func (z *Zone) SetDelayReason(tx *sql.Tx, value string, delay time.Duration) (error, string) {
	mdb := z.MusicDB

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("SetDelayReason: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	err, msg := mdb.ZoneSetMeta(tx, z, "delay-reason", value)
	if err != nil {
		return err, msg
	}

	const DSsql = "UPDATE zones SET fsmstatus='delayed' WHERE name=?"
	stmt, err1 := mdb.Prepare(DSsql)
	if err1 != nil {
		log.Fatalf("DocumentStop: Error from mdb.Prepare(%s): %v", DSsql, err)
	}

	_, err1 = stmt.Exec(z.Name)
	if err1 != nil {
		log.Fatalf("DocumentStop: Error from mdb.Exec(%s): %v", DSsql, err)
	}
	log.Printf("%s\n", value)
	return err, msg
}

const (
	ZSMsql = "INSERT OR REPLACE INTO metadata (zone, key, time, value) VALUES (?, ?, datetime('now'), ?)"
)

func (mdb *MusicDB) ZoneSetMeta(tx *sql.Tx, z *Zone, key, value string) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneSetMeta: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	mstmt, err := mdb.Prepare(ZSMsql)
	if err != nil {
		fmt.Printf("ZoneSetMeta: Error from db.Prepare(%s) 1: %v\n", ZSMsql, err)
	}
	zstmt, err := mdb.Prepare("UPDATE zones SET zonetype=? WHERE name=?")
	if err != nil {
		fmt.Printf("ZoneSetMeta: Error from db.Prepare 2: %v\n", err)
	}

	_, err = mstmt.Exec(z.Name, key, value)
	if CheckSQLError("ZoneSetMeta", "INSERT OR REPLACE INTO", err, false) {
		return err, ""
	}
	_, err = zstmt.Exec(z.ZoneType, z.Name)
	if CheckSQLError("ZoneSetMeta", "UPDATE zones SET zonetype", err, false) {
		return err, ""
	}

	return nil, fmt.Sprintf("Zone %s metadata '%s' updated to be '%s'",
		z.Name, key, value)
}

const (
	ZGMsql = "SELECT value FROM metadata WHERE zone=? AND key=?"
)

func (mdb *MusicDB) ZoneGetMeta(tx *sql.Tx, z *Zone, key string) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneGetMeta: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	stmt, err := mdb.Prepare(ZGMsql)
	if err != nil {
		fmt.Printf("ZoneSetMeta: Error from db.Prepare(%s): %v\n", ZGMsql, err)
	}

	row := stmt.QueryRow(z.Name, key)
	if CheckSQLError("ZoneGetMeta", ZGMsql, err, false) {
		return err, ""
	}

	var value string
	switch err = row.Scan(&value); err {
	case sql.ErrNoRows:
		return err, ""
	case nil:
		return nil, value
	}
	return nil, ""
}

func (z *Zone) StateTransition(tx *sql.Tx, from, to string) error {
	mdb := z.MusicDB
	fsm := z.FSM

	fmt.Printf("This is %sStateTransition(%s-->%s) in process %s\n", z.Name, from, to, fsm)
	if fsm == "" {
		return errors.New(fmt.Sprintf("Zone %s is not currently in any ongoing process.",
			z.Name))
	}

	if z.State != from {
		return errors.New(fmt.Sprintf("StateTransition: Error: zone %s is in state '%s'. Should be '%s'.\n", z.State, from))
	}

	if from == FsmStateStop && to == FsmStateStop {
		fmt.Printf("StateTransition: terminal state reached. Exiting process.\n")
		to = "---"
		fsm = "---"
	}

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("StateTransition: Error from mdb.StartTransaction(): %v\n", err)
		return err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	sqlq := "UPDATE zones SET state=?, fsm=?, fsmstatus=? WHERE name=?"
	stmt, err := mdb.Prepare(sqlq)
	if err != nil {
		fmt.Printf("Error from db.Prepare: %v\n", err)
	}

	_, err = stmt.Exec(to, fsm, "", z.Name)			// remove fsmstatus="blocked" if there
	if CheckSQLError("StateTransition", sqlq, err, false) {
		return err
	}
	err, _ = mdb.ZoneSetMeta(tx, z, "stop-reason", "")		// remove old stop-reason if there
	if err != nil {
		log.Printf("StateTransition: Error from ZoneSetMeta: %v\n", err)
	}
	log.Printf("Zone %s transitioned from %s to %s in process %s", z.Name, from, to, fsm)

	return nil
}

func (mdb *MusicDB) ApiGetZone(zonename string) (*Zone, bool, error) {
	zone, exists, err := mdb.GetZone(nil, zonename)
	if err != nil {
	   return nil, false, err
	}
	zone.MusicDB = nil
	zone.SGroup = nil // another one
	return zone, exists, nil
}

const (
	GZsql = `
SELECT name, zonetype, state, fsmmode, COALESCE(statestamp, datetime('now')) AS timestamp,
       fsm, fsmsigner, COALESCE(sgroup, '') AS signergroup
FROM zones WHERE name=?`
)

func (mdb *MusicDB) GetZone(tx *sql.Tx, zonename string) (*Zone, bool, error) {

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("GetZone: Error from mdb.StartTransaction(): %v\n", err)
		// return err, "fail"
		return nil, false, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	stmt, err := mdb.Prepare(GZsql)
	if err != nil {
		log.Printf("GetZone: Error from db.Prepare(%s): %v\n", GZsql, err)
		return nil, false, err
	}
	row := stmt.QueryRow(zonename)

	var name, zonetype, state, fsmmode, timestamp, fsm, fsmsigner, signergroup string
	switch err = row.Scan(&name, &zonetype, &state, &fsmmode, &timestamp,
		&fsm, &fsmsigner, &signergroup); err {
	case sql.ErrNoRows:
		// fmt.Printf("GetZone: Zone \"%s\" does not exist\n", zonename)
		return &Zone{
			Name:   zonename,
			Exists: false,
		}, false, nil		// not an error

	case nil:
		t, err := time.Parse(layout, timestamp)
		if err != nil {
			log.Fatal("GetZone: Error from time.Parse():", err)
			return nil, false, err
		}

		sg, err := mdb.GetSignerGroup(tx, signergroup, false) // not apisafe
		if err != nil {
		      return nil, false, err
		}
		
		nexttransitions := mdb.FSMlist[fsm].States[state].Next
		next := map[string]bool{}
		for k, _ := range nexttransitions {
			next[k] = true
		}

		return &Zone{
			Name:       name,
			Exists:     true,
			ZoneType:   zonetype,
			State:      state,
			FSMMode:    fsmmode,
			Statestamp: t,
			NextState:  next,
			FSM:        fsm,
			FSMSigner:  fsmsigner,	// is this still used for anything?
			SGroup:     sg,
			SGname:     sg.Name,
			MusicDB:    mdb, // can not be json encoded, i.e. not used in API
		}, true, nil

	default:
		log.Fatalf("GetZone: error from row.Scan(): name=%s, err=%v", zonename, err)
	}
	return &Zone{
		Name:   zonename,
		Exists: false,
	}, false, nil
}

func (mdb *MusicDB) GetSignerGroupZones(tx *sql.Tx, sg *SignerGroup) ([]*Zone, error) {
	var zones = []*Zone{}

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("GetSignerGroup: Error from mdb.StartTransaction(): %v\n", err)
		return zones, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	sqlq := "SELECT name, state, COALESCE(statestamp, datetime('now')) AS timestamp, fsm FROM zones WHERE sgroup=?"
	stmt, err := mdb.Prepare(sqlq)
	if err != nil {
		log.Printf("GetSignerGroupZones: Error from db.Prepare(%s): %v\n", sqlq, err)
	}
	rows, err := stmt.Query(sg.Name)
	defer rows.Close()

	if CheckSQLError("GetSignerGroupZones", sqlq, err, false) {
		log.Printf("GetSignerGroupZones: Error from SQL query: %v", err)
		return zones, err
	} else {
		rowcounter := 0
		var name, state, fsm, timestamp string
		for rows.Next() {
			err := rows.Scan(&name, &state, &timestamp, &fsm)
			if err != nil {
				log.Fatal("GetSignerGroupZones: Error from rows.Next():", err)
			}

			t, err := time.Parse(layout, timestamp)
			if err != nil {
				log.Fatal("GetSignerGroupZones: Error from time.Parse():", err)
			}

			zones = append(zones, &Zone{
				Name:       name,
				Exists:     true,
				State:      state,
				Statestamp: t,
				FSM:        fsm,
				SGroup:     sg,
				MusicDB:    mdb,
			})
			rowcounter++
		}
	}
	return zones, nil
}

// When a zone joins a signer group it could be that the signer group
// is in a state of transition (incoming or departing signer). In that
// case, shouldn't the new zone immediately also enter that process?

// Or, perhaps the new zone should enter the "add-signer" process
// regardless of the state of the signer group? I.e. from the POV of the
// zone, "joining" the signer group (that has signers) by definition
// causes signers to be added (for that zone).

// Current thinking: it should not be possible to enter (or leave) a
// signer group that is in an add-signer or remove-signer process. The
// problem with that is that // if a zone joining then automatically
// enters the add-signer process, then we "lock" the signer group until
// the new zone is in sync. That seems... bad.

// So perhaps the new zone going through "add-signer" is different
// from the entire signer group going through "add-signer"? In that case,
// perhaps the right thing is to "lock" the signer group when the entire
// group enters a proceess (and unlock when all zones are done)

func (mdb *MusicDB) ZoneJoinGroup(tx *sql.Tx, dbzone *Zone, g string,
     	  	    		     enginecheck chan EngineCheck) (string, error) {
	var group *SignerGroup
	var err error

	if !dbzone.Exists {
		return "", fmt.Errorf("Zone %s unknown", dbzone.Name)
	}

	if group, err = mdb.GetSignerGroup(tx, g, false); err != nil { // not apisafe
		return "", err
	}

	sg := dbzone.SignerGroup()

	// must test for existence of sg, as after AddZone() it is still nil
	if sg != nil && sg.Name != "" {
		return "", fmt.Errorf("Zone %s already assigned to signer group %s\n",
			dbzone.Name, sg.Name)
	}

	// Is the signer group locked (because of being in a process
	// that precludes zones joining or leaving)?
	if group.Locked {
		return "", fmt.Errorf("Signer group %s locked from zones joining or leaving due to ongoing '%s' process.",
			group.Name, group.CurrentProcess)

	}

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return "fail", err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	sqlq := "UPDATE zones SET sgroup=? WHERE name=?"
	stmt, err := mdb.Prepare(sqlq)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from db.Prepare: %v\n", err)
	}

	_, err = stmt.Exec(g, dbzone.Name)
	if CheckSQLError("JoinGroup", sqlq, err, false) {
		return fmt.Sprintf("Error from stmt.Exec(%s): %v", sqlq, err), err
	}

	dbzone, _, err = mdb.GetZone(tx, dbzone.Name)
	if err != nil {
	   return fmt.Sprintf("Error from mdb.GetZone(%s): %v", dbzone.Name, err), err
	}

	// If the new zone is not already in a process then we put it in the
	// VerifyZoneInSyncProcess as a method of ensuring that it is in sync.
	// This process is currently a no-op, but doesn't have to be.
	if dbzone.FSM == "" || dbzone.FSM == "---" {
		err, msg := mdb.ZoneAttachFsm(tx, dbzone, SignerJoinGroupProcess,
			"all", false) // false=no preempting
		if err != nil {
			return msg, err
		}

	        enginecheck <- EngineCheck{ Zone: dbzone.Name }
		return fmt.Sprintf(
			"Zone %s has joined signer group %s and started the process '%s'.",
			dbzone.Name, g, SignerJoinGroupProcess), nil
	}

        enginecheck <- EngineCheck{ Zone: dbzone.Name }
	return fmt.Sprintf(
		`Zone %s has joined signer group %s but could not start the process '%s'
as the zone is already in process '%s'. Problematic.`, dbzone.Name,
   g, SignerJoinGroupProcess, dbzone.FSM), nil
}

// Leaving a signer group is different from joining in the sense that
// if the group is locked (due to ongoing process) a zone cannot join at
// all, but it is always possible to leave. Apart from being a basic
// observation of the zone owners right to always decide what it wants to
// do it is also a "safe" mechanism, as part of the point with MUSIC and
// the multi-signer mechanism in general is that every single state in every
// process is a stable and fully functioning state. I.e regarless of where
// a zone may decide to jump ship it will not be dangrous to eith the child,
// nor the signer group if this occurs.

func (mdb *MusicDB) ZoneLeaveGroup(dbzone *Zone, g string) (error, string) {
	if !dbzone.Exists {
		return fmt.Errorf("Zone %s unknown", dbzone.Name), ""
	}

	var tx *sql.Tx
	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	if _, err := mdb.GetSignerGroup(tx, g, false); err != nil { // not apisafe
		return err, ""
	}

	sg := dbzone.SignerGroup()

	if sg.Name != g {
		return fmt.Errorf("Zone %s is not assigned to signer group %s",
			dbzone.Name, g), ""
	}

	sqlq := "UPDATE zones SET sgroup='' WHERE name=?"
	stmt, err := mdb.Prepare(sqlq)
	if err != nil {
		fmt.Printf("ZoneLeaveGroup: Error from db.Prepare(%s): %v\n", sqlq, err)
	}

	_, err = stmt.Exec(dbzone.Name)
	if CheckSQLError("ZoneLeaveGroup", sqlq, err, false) {
		return err, ""
	}

	return nil, fmt.Sprintf("Zone %s has left the signer group %s.",
		dbzone.Name, sg.Name)
}

const (
	layout = "2006-01-02 15:04:05"
	LZsqlq = `
SELECT name, zonetype, state, fsm, fsmmode, fsmstatus,
  COALESCE(statestamp, datetime('now')) AS timestamp,
  COALESCE(sgroup, '') AS signergroup
FROM zones`
)

func (mdb *MusicDB) ListZones() (map[string]Zone, error) {
	var zl = make(map[string]Zone, 10)

	var tx *sql.Tx
	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return zl, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	stmt, err := mdb.Prepare(LZsqlq)
	if err != nil {
		fmt.Printf("ListZones: Error from db.Prepare: %v", err)
	}

	rows, err := stmt.Query()
	if err != nil {
		log.Printf("ListZones: Error from db query: %v", err)
	}
	defer rows.Close()

	if CheckSQLError("ListZones", LZsqlq, err, false) {
		return zl, err
	} else {
		rowcounter := 0
		var name, zonetype, state, fsm, fsmmode, fsmstatus string
		var timestamp string
		var signergroup, stopreason string
		for rows.Next() {
			err := rows.Scan(&name, &zonetype, &state, &fsm, &fsmmode,
				&fsmstatus, &timestamp, &signergroup)
			if err != nil {
				log.Fatal("ListZones: Error from rows.Next():", err)
			}
			t, err := time.Parse(layout, timestamp)
			if err != nil {
				log.Fatal("ListZones: Error from time.Parse():", err)
			}

			sg, err := mdb.GetSignerGroup(tx, signergroup, true) // apisafe
			if err != nil {
			   return zl, err
			}

			nexttransitions := mdb.FSMlist[fsm].States[state].Next
			next := map[string]bool{}
			for k, _ := range nexttransitions {
				next[k] = true
			}

			tz := Zone{
				Name:       name,
				Exists:     true,
				ZoneType:   zonetype,
				State:      state,
				FSMMode:    fsmmode,
				FSMStatus:  fsmstatus,
				Statestamp: t,
				NextState:  next,
				FSM:        fsm,
				SGroup:     sg,
				SGname:     sg.Name,
			}

			if fsmstatus == "blocked" {
				_, stopreason = mdb.ZoneGetMeta(tx, &tz, "stop-reason")
				log.Printf("ListZones: zone %s is blocked. reason: '%s'", name, stopreason)
				tz.StopReason = stopreason
			}
			zl[name] = tz

			rowcounter++
		}
		// fmt.Printf("ListZones: rowcounter: %d zonemap: %v\n", rowcounter, zl)
	}

	return zl, nil
}
