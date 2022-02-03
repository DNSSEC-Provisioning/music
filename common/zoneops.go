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

const AZsql = `
    INSERT INTO zones(name, zonetype, state, statestamp, fsm) VALUES (?, ?, ?, datetime('now'), ?)`


func (mdb *MusicDB) AddZone(z *Zone, group string) (error, string) {
	log.Printf("AddZone: zone: %v", z)
	fqdn := dns.Fqdn(z.Name)
	dbzone, _ := mdb.GetZone(fqdn)
	if dbzone.Exists {
		return fmt.Errorf("Zone %s already present in MuSiC system.", fqdn), ""
	}

	stmt, err := mdb.Prepare(AZsql)
	if err != nil {
		fmt.Printf("Error in SQL prepare(%s): %v", AZsql, err)
	}

	mdb.mu.Lock()
	_, err = stmt.Exec(fqdn, z.ZoneType, "", "")
	if CheckSQLError("AddZone", AZsql, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()

	if group != "" {
		fmt.Printf("AddGroup: notice that the zone %s has the signergroup %s specified so we set that too\n", z.Name, group)
		dbzone, _ := mdb.GetZone(z.Name)
		err, _ := mdb.ZoneJoinGroup(dbzone, group) // we know that the zone exist
		if err != nil {
		   return err, fmt.Sprintf(
			"Zone %s was added, but failed to attach to signer group %s.", fqdn, group)
		} else {
		  return nil, fmt.Sprintf(
			"Zone %s was added and immediately attached to signer group %s.", fqdn, group)
		}
	}
	return nil, fmt.Sprintf("Zone %s was added but is not yet attached to any signer group.",
	       	    		      fqdn)
}

const (
      UZsql = "UPDATE zones SET zonetype=? WHERE name=?"
)

func (mdb *MusicDB) UpdateZone(dbzone, uz *Zone) (error, string) {
	log.Printf("UpdateZone: zone: %v", uz)

	stmt, err := mdb.Prepare(UZsql)
	if err != nil {
		fmt.Printf("Error in SQL prepare(%s): %v", UZsql, err)
	}

	if uz.ZoneType != "" {
	   dbzone.ZoneType = uz.ZoneType
	}

	mdb.mu.Lock()
	_, err = stmt.Exec(dbzone.ZoneType, dbzone.Name)
	if CheckSQLError("UpdateZone", UZsql, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()

	return nil, fmt.Sprintf("Zone %s updated.", dbzone.Name)
}

func (mdb *MusicDB) DeleteZone(z *Zone) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	sg := z.SignerGroup()
	if sg != nil {
		err, _ := mdb.ZoneLeaveGroup(z, sg.Name)
		if err != nil {
			log.Printf("DeleteZone: Error from ZoneLeaveGroup(%s, %s): %v", z.Name, sg.Name, err)
		}
	}

	mdb.mu.Lock()
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
		mdb.mu.Unlock()
		return err, ""
	}

	mdb.mu.Unlock()
	deletemsg := fmt.Sprintf("Zone %s deleted.", z.Name)
	processcomplete, msg  := mdb.CheckIfProcessComplete(sg)
	if processcomplete {
	   return nil, deletemsg + "\n" + msg
	}
	return nil, deletemsg
}

func (mdb *MusicDB) ZoneSetMeta(z *Zone, key, value string) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	mstmt, err := mdb.Prepare("INSERT OR REPLACE INTO metadata (zone, key, time, value) VALUES (?, ?, datetime('now'), ?)")
	if err != nil {
		fmt.Printf("ZoneSetMeta: Error from db.Prepare 1: %v\n", err)
	}
	zstmt, err := mdb.Prepare("UPDATE zones SET zonetype=? WHERE name=?")
	if err != nil {
		fmt.Printf("ZoneSetMeta: Error from db.Prepare 2: %v\n", err)
	}

	mdb.mu.Lock()

	_, err = mstmt.Exec(z.Name, key, value)
	if CheckSQLError("ZoneSetMeta", "INSERT OR REPLACE INTO", err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	_, err = zstmt.Exec(z.ZoneType, z.Name)
	if CheckSQLError("ZoneSetMeta", "UPDATE zones SET zonetype", err, false) {
		mdb.mu.Unlock()
		return err, ""
	}

	mdb.mu.Unlock()
	return nil, fmt.Sprintf("Zone %s metadata '%s' updated to be '%s'",
		z.Name, key, value)
}

func (mdb *MusicDB) ZoneGetMeta(z *Zone, key string) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	mdb.mu.Lock()
	stmt, err := mdb.Prepare("SELECT value FROM metadata WHERE zone=? AND key=?")
	if err != nil {
		fmt.Printf("ZoneSetMeta: Error from db.Prepare: %v\n", err)
	}

	row := stmt.QueryRow(z.Name, key)
	if CheckSQLError("ZoneGetMeta", "SELECT value FROM metadata", err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()

	var value string
	switch err = row.Scan(&value); err {
	case sql.ErrNoRows:
		return err, ""
	case nil:
		return nil, value
	}
	return nil, ""
}

func (z *Zone) StateTransition(from, to string) error {
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

	sqlq := "UPDATE zones SET state=?, fsm=? WHERE name=?"
	stmt, err := mdb.Prepare(sqlq)
	if err != nil {
		fmt.Printf("Error from db.Prepare: %v\n", err)
	}

	mdb.mu.Lock()
	_, err = stmt.Exec(to, fsm, z.Name)
	if CheckSQLError("StateTransition", sqlq, err, false) {
		mdb.mu.Unlock()
		return err
	}
	mdb.mu.Unlock()
	err, _ = mdb.ZoneSetMeta(z, "stop-reason", "")
	if err != nil {
		log.Printf("StateTransition: Error from ZoneSetMeta: %v\n", err)
	}
	log.Printf("Zone %s transitioned from %s to %s in process %s", z.Name, from, to, fsm)

	return nil
}

func (mdb *MusicDB) ApiGetZone(zonename string) (*Zone, bool) {
	zone, exists := mdb.GetZone(zonename)
	zone.MusicDB = nil
	zone.SGroup = nil // another one
	return zone, exists
}

const (
      GZsql = `
SELECT name, zonetype, state, COALESCE(statestamp, datetime('now')) AS timestamp,
       fsm, fsmsigner, COALESCE(sgroup, '') AS signergroup
FROM zones WHERE name=?`
)

func (mdb *MusicDB) GetZone(zonename string) (*Zone, bool) {
	stmt, err := mdb.Prepare(GZsql)
	if err != nil {
		log.Printf("GetZone: Error from db.Prepare(%s): %v\n", GZsql, err)
	}
	row := stmt.QueryRow(zonename)

	var name, zonetype, state, timestamp, fsm, fsmsigner, signergroup string
	switch err = row.Scan(&name, &zonetype, &state, &timestamp, &fsm, &fsmsigner, &signergroup); err {
	case sql.ErrNoRows:
		// fmt.Printf("GetZone: Zone \"%s\" does not exist\n", zonename)
		return &Zone{
			Name:   zonename,
			Exists: false,
		}, false

	case nil:
		t, err := time.Parse(layout, timestamp)
		if err != nil {
			log.Fatal("GetZone: Error from time.Parse():", err)
		}

		sg, _ := mdb.GetSignerGroup(signergroup, false) // not apisafe
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
			Statestamp: t,
			NextState:  next,
			FSM:        fsm,
			FSMSigner:  fsmsigner,
			SGroup:     sg,
			SGname:     sg.Name,
			MusicDB:    mdb, // can not be json encoded, i.e. not used in API
		}, true

	default:
		log.Fatalf("GetZone: error from row.Scan(): name=%s, err=%v", zonename, err)
	}
	return &Zone{
		Name:   zonename,
		Exists: false,
	}, false
}

func (mdb *MusicDB) GetSignerGroupZones(sg *SignerGroup) ([]*Zone, error) {
	var zones = []*Zone{}

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
				Exists:	    true,
				State:      state,
				Statestamp: t,
				FSM:        fsm,
				SGroup:     sg,
				MusicDB:    mdb,
			})
			rowcounter++
		}
		// log.Printf("GetSignerGroupZones: found %d zones attached to signer group %s\n",
		// 	rowcounter, sg.Name)
	}
	// log.Printf("GetSignerGroupZones: there are %d zones:\n %v", len(zones), zones)
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

func (mdb *MusicDB) ZoneJoinGroup(dbzone *Zone, g string) (error, string) {
	var group *SignerGroup
	var err error

	if !dbzone.Exists {
		return fmt.Errorf("Zone %s unknown", dbzone.Name), ""
	}

	if group, err = mdb.GetSignerGroup(g, false); err != nil { // not apisafe
		return err, ""
	}

	sg := dbzone.SignerGroup()
	// fmt.Printf("ZoneJoinGroup: dbzone: %v sg: %v\n", dbzone, sg)

	// must test for existence of sg, as after AddZone() it is still nil
	if sg != nil && sg.Name != "" {
		return errors.New(fmt.Sprintf("Zone %s already assigned to signer group %s\n",
			dbzone.Name, sg.Name)), ""
	}

	// Is the signer group locked (because of being in a process
	// that precludes zones joining or leaving)?
	if group.Locked {
		return errors.New(fmt.Sprintf("Signer group %s locked from zones joining or leaving due to ongoing '%s' process.",
			group.Name, group.CurrentProcess)), ""

	}

	mdb.mu.Lock()
	sqlq := "UPDATE zones SET sgroup=? WHERE name=?"
	stmt, err := mdb.Prepare(sqlq)
	if err != nil {
		fmt.Printf("ZoneJoinGroup: Error from db.Prepare: %v\n", err)
	}

	_, err = stmt.Exec(g, dbzone.Name)
	if CheckSQLError("JoinGroup", sqlq, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()

	dbzone, _ = mdb.GetZone(dbzone.Name)

	// If the new zone is not already in a process then we put it in the
	// VerifyZoneInSyncProcess as a method of ensuring that it is in sync.
	// This process is currently a no-op, but doesn't have to be.
	if dbzone.FSM == "" || dbzone.FSM == "---" {
		err, msg := mdb.ZoneAttachFsm(dbzone, SignerJoinGroupProcess,
		     	    			      "all", false) // false=no preempting
		if err != nil {
			return err, msg
		}

		return nil, fmt.Sprintf(
			"Zone %s has joined signer group %s and started the process '%s'.", dbzone.Name, g, VerifyZoneInSyncProcess)
	}
	return nil, fmt.Sprintf(
		`Zone %s has joined signer group %s but could not start the process '%s'
as the zone is already in process '%s'. Problematic.`, dbzone.Name, g, SignerJoinGroupProcess, dbzone.FSM)
}

// Leaving a signer group is different from joining in the sense that
// if the group is locked (due to ongoing process) a zone cannot join at
// all, but it is possible to leave as long as the leaving zone is done
// with the process.

func (mdb *MusicDB) ZoneLeaveGroup(dbzone *Zone, g string) (error, string) {
	if !dbzone.Exists {
		return fmt.Errorf("Zone %s unknown", dbzone.Name), ""
	}

	if _, err := mdb.GetSignerGroup(g, false); err != nil { // not apisafe
		return err, ""
	}

	sg := dbzone.SignerGroup()

	if sg.Name != g {
		return fmt.Errorf("Zone %s is not assigned to signer group %s",
			dbzone.Name, g), ""
	}

	// It *this* zone in a process or not?
	//	if dbzone.FSM != "" && dbzone.FSM != "---" {
	//		return fmt.Errorf(
	//			"Zone %s is executing process '%s'. Cannot leave until finished.", dbzone.Name, dbzone.FSM), ""
	//	}

	mdb.mu.Lock()
	sqlq := "UPDATE zones SET sgroup='' WHERE name=?"
	stmt, err := mdb.Prepare(sqlq)
	if err != nil {
		fmt.Printf("ZoneLeaveGroup: Error from db.Prepare(%s): %v\n", sqlq, err)
	}

	_, err = stmt.Exec(dbzone.Name)
	if CheckSQLError("ZoneLeaveGroup", sqlq, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}

//	sqlq = "UPDATE signergroups SET numzones=numzones-1 WHERE name=?"
//	stmt, err = mdb.Prepare(sqlq)
//	if err != nil {
//		fmt.Printf("ZoneLeaveGroup: Error from db.Prepare(%s): %v\n", sqlq, err)
//	}

//	_, err = stmt.Exec(g, g)
//	if CheckSQLError("ZoneLeaveGroup", sqlq, err, false) {
//		mdb.mu.Unlock()
//		return err, ""
//	}

//	if dbzone.FSM != "" && dbzone.FSM != "---" {
//		sqlq = "UPDATE signergroups SET numprocesszones=numprocesszones-1 WHERE name=?"
//		stmt, err = mdb.Prepare(sqlq)
//		if err != nil {
//			fmt.Printf("ZoneLeaveGroup: Error from db.Prepare(%s): %v\n", sqlq, err)
//		}
//
//		_, err = stmt.Exec(g, g)
//		if CheckSQLError("ZoneLeaveGroup", sqlq, err, false) {
//			mdb.mu.Unlock()
//			return err, ""
//		}
//	}

	mdb.mu.Unlock()
	return nil, fmt.Sprintf("Zone %s has left the signer group %s.",
		dbzone.Name, sg.Name)
}

const (
	layout = "2006-01-02 15:04:05"
	LZsqlq = `
SELECT name, zonetype, state, fsm,
  COALESCE(statestamp, datetime('now')) AS timestamp,
  COALESCE(sgroup, '') AS signergroup
FROM zones`
)

func (mdb *MusicDB) ListZones() (map[string]Zone, error) {
	var zl = make(map[string]Zone, 10)

	stmt, err := mdb.Prepare(LZsqlq)
	if err != nil {
		fmt.Printf("ListZones: Error from db.Prepare: %v\n", err)
	}

	rows, err := stmt.Query()
	if err != nil {
		log.Printf("ListZones: Error from db query: %v\n", err)
	}
	defer rows.Close()

	if CheckSQLError("ListZones", LZsqlq, err, false) {
		return zl, err
	} else {
		rowcounter := 0
		var name, zonetype, state, fsm string
		var timestamp string
		var signergroup string
		for rows.Next() {
			err := rows.Scan(&name, &zonetype, &state, &fsm, &timestamp, &signergroup)
			if err != nil {
				log.Fatal("ListZones: Error from rows.Next():", err)
			}
			t, err := time.Parse(layout, timestamp)
			if err != nil {
				log.Fatal("ListZones: Error from time.Parse():", err)
			}

			sg, _ := mdb.GetSignerGroup(signergroup, true) // apisafe
			// for _, s := range sg.SignerMap {
			//    s.DB = nil // can not be json encoded
			// }
			nexttransitions := mdb.FSMlist[fsm].States[state].Next
			next := map[string]bool{}
			for k, _ := range nexttransitions {
				next[k] = true
			}

			// fmt.Printf("ListZones: got [zone=%s, next=%v, SGroup=%s sg=%v]\n",
			//		       name, next, signergroup, sg)

			zl[name] = Zone{
				Name:       name,
				ZoneType:   zonetype,
				State:      state,
				Statestamp: t,
				NextState:  next,
				FSM:        fsm,
				SGroup:     sg,
				SGname:     sg.Name,
			}
			rowcounter++
		}
		// fmt.Printf("ListZones: rowcounter: %d zonemap: %v\n", rowcounter, zl)
	}

	return zl, nil
}
