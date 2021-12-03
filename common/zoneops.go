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

func (mdb *MusicDB) AddZone(z *Zone, group string) (error, string) {
	fqdn := dns.Fqdn(z.Name)
	dbzone, _ := mdb.GetZone(fqdn)
	if dbzone.Exists {
		return fmt.Errorf("Zone %s already present in MuSiC system.", fqdn), ""
	}

	sqlq := "INSERT INTO zones(name, state, statestamp, fsm) VALUES (?, ?, datetime('now'), ?)"
	stmt, err := mdb.db.Prepare(sqlq)
	if err != nil {
		fmt.Printf("Error in SQL prepare: %v", err)
	}

	mdb.mu.Lock()
	_, err = stmt.Exec(fqdn, "---", "---")
	if CheckSQLError("AddZone", sqlq, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()

	if group != "" {
		fmt.Printf("AddGroup: notice that the zone %s has the signergroup %s specified so we set that too\n", z.Name, group)
		dbzone, _ := mdb.GetZone(z.Name)
		mdb.ZoneJoinGroup(dbzone, group) // we know that the zone exist
		return nil, fmt.Sprintf(
			"Zone %s was added and immediately attached to signer group %s.", fqdn, group)
	}
	return nil, fmt.Sprintf("Zone %s was added but is not yet attached to any signer group.", fqdn)
}

func (mdb *MusicDB) DeleteZone(z *Zone) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	mdb.mu.Lock()
	stmt, err := mdb.db.Prepare("DELETE FROM zones WHERE name=?")
	if err != nil {
		fmt.Printf("DeleteZone: Error from db.Prepare: %v\n", err)
	}
	_, err = stmt.Exec(z.Name)
	if err != nil {
		fmt.Printf("DeleteZone: Error from stmt.Exec: %v\n", err)
	}
	stmt, err = mdb.db.Prepare("DELETE FROM records WHERE zone=?")
	_, err = stmt.Exec(z.Name)
	stmt, err = mdb.db.Prepare("DELETE FROM metadata WHERE zone=?")
	_, err = stmt.Exec(z.Name)

	if CheckSQLError("DeleteZone", "DELETE FROM ... WHERE zone=...", err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()
	return nil, fmt.Sprintf("Zone %s deleted.", z.Name)
}

func (mdb *MusicDB) ZoneMeta(z *Zone, key, value string) (error, string) {
	if !z.Exists {
		return fmt.Errorf("Zone %s not present in MuSiC system.", z.Name), ""
	}

	mdb.mu.Lock()
	stmt, err := mdb.db.Prepare("INSERT OR REPLACE INTO metadata (zone, key, value) VALUES (?, ?, ?)")
	if err != nil {
		fmt.Printf("ZoneMeta: Error from db.Prepare: %v\n", err)
	}

	_, err = stmt.Exec(z.Name, key, value)
	if CheckSQLError("ZoneMeta", "INSERT OR REPLACE INTO", err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()
	return nil, fmt.Sprintf("Zone %s metadata '%s' updated to be '%s'",
		z.Name, key, value)
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
	stmt, err := mdb.db.Prepare(sqlq)
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
	err, _ = mdb.ZoneMeta(z, "stop-reason", "")
	if err != nil {
		log.Printf("StateTransition: Error from ZoneMeta: %v\n", err)
	}
	log.Printf("Zone %s transitioned from %s to %s in process %s", z.Name, from, to, fsm)

	return nil
}

func (mdb *MusicDB) GetZone(zonename string) (*Zone, bool) {
	sqlq := "SELECT name, state, COALESCE(statestamp, datetime('now')) AS timestamp, fsm, COALESCE(sgroup, '') AS signergroup FROM zones WHERE name=?"
	stmt, err := mdb.db.Prepare(sqlq)
	if err != nil {
		fmt.Printf("GetZone: Error from db.Prepare: %v\n", err)
	}
	row := stmt.QueryRow(zonename)

	var name, state, timestamp, fsm, signergroup string
	switch err = row.Scan(&name, &state, &timestamp, &fsm, &signergroup); err {
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

		sg, _ := mdb.GetSignerGroup(signergroup)
		nexttransitions := mdb.FSMlist[fsm].States[state].Next
		next := map[string]bool{}
		for k, _ := range nexttransitions {
			next[k] = true
		}

		return &Zone{
			Name:       name,
			Exists:     true,
			State:      state,
			Statestamp: t,
			NextState:  next,
			FSM:        fsm,
			SGroup:     sg,
			SGname:     sg.Name,
			MusicDB:    mdb,
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
	stmt, err := mdb.db.Prepare(sqlq)
	if err != nil {
		fmt.Printf("GetSignerGroupZones: Error from db.Prepare: %v\n", err)
	}
	rows, err := stmt.Query(sg.Name)

	defer rows.Close()

	if CheckSQLError("GetSignerGroupZones", sqlq, err, false) {
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
				State:      state,
				Statestamp: t,
				FSM:        fsm,
				SGroup:     sg,
				MusicDB:    mdb,
			})
			rowcounter++
		}
		fmt.Printf("GetSignerGroupZones: found %d zones attached to signer group %s\n",
			rowcounter, sg.Name)
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

func (mdb *MusicDB) ZoneJoinGroup(dbzone *Zone, g string) (error, string) {
	if !dbzone.Exists {
		return fmt.Errorf("Zone %s unknown", dbzone.Name), ""
	}

	if _, err := mdb.GetSignerGroup(g); err != nil {
		return err, ""
	}

	sg := dbzone.SignerGroup()
	// fmt.Printf("ZoneJoinGroup: dbzone: %v sg: %v\n", dbzone, sg)

	// must test for existence of sg, as after AddZone() it is still nil
	if sg != nil && sg.Name != "" {
		return errors.New(fmt.Sprintf("Zone %s already assigned to signer group %s\n",
			dbzone.Name, sg.Name)), ""
	}

	mdb.mu.Lock()
	sqlq := "UPDATE zones SET sgroup=? WHERE name=?"
	stmt, err := mdb.db.Prepare(sqlq)
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

	if dbzone.FSM == "" || dbzone.FSM == "---" {
		err, msg := mdb.ZoneAttachFsm(dbzone, SignerJoinGroupProcess)
		if err != nil {
			return err, msg
		}
		return nil, fmt.Sprintf(
			"Zone %s has joined signer group %s and started the process '%s'.", dbzone.Name, g, SignerJoinGroupProcess)
	}
	return nil, fmt.Sprintf(
		`Zone %s has joined signer group %s but could not start the process '%s'
as the zone is already in process '%s'. Problematic.`, dbzone.Name, g, SignerJoinGroupProcess, dbzone.FSM)
}

func (mdb *MusicDB) ZoneLeaveGroup(dbzone *Zone, g string) (error, string) {
	if !dbzone.Exists {
		return fmt.Errorf("Zone %s unknown", dbzone.Name), ""
	}

	if _, err := mdb.GetSignerGroup(g); err != nil {
		return err, ""
	}

	sg := dbzone.SignerGroup()

	if sg.Name != g {
		return fmt.Errorf("Zone %s is not assigned to signer group %s",
			dbzone.Name, g), ""
	}

	if dbzone.FSM != "" && dbzone.FSM != "---" {
		return fmt.Errorf(
			"Zone %s is executing process '%s'. Cannot leave until finished.", dbzone.Name, dbzone.FSM), ""
	}

	mdb.mu.Lock()
	sqlq := "UPDATE zones SET sgroup='' WHERE name=?"
	stmt, err := mdb.db.Prepare(sqlq)
	if err != nil {
		fmt.Printf("ZoneLeaveGroup: Error from db.Prepare: %v\n", err)
	}

	_, err = stmt.Exec(dbzone.Name)
	if CheckSQLError("LeaveGroup", sqlq, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()
	return nil, fmt.Sprintf("Zone %s has left the signer group %s.",
		dbzone.Name, sg.Name)
}

const layout = "2006-01-02 15:04:05"

func (mdb *MusicDB) ListZones() (map[string]Zone, error) {
	var zl = make(map[string]Zone, 10)

	sqlq := "SELECT name, state, COALESCE(statestamp, datetime('now')) AS timestamp, fsm, COALESCE(sgroup, '') AS signergroup FROM zones"
	stmt, err := mdb.db.Prepare(sqlq)
	if err != nil {
		fmt.Printf("ListZones: Error from db.Prepare: %v\n", err)
	}

	rows, err := stmt.Query()
	defer rows.Close()

	if CheckSQLError("ListZones", sqlq, err, false) {
		return zl, err
	} else {
		rowcounter := 0
		var name, state, fsm string
		var timestamp string
		var signergroup string
		for rows.Next() {
			err := rows.Scan(&name, &state, &timestamp, &fsm, &signergroup)
			if err != nil {
				log.Fatal("ListZones: Error from rows.Next():", err)
			}
			t, err := time.Parse(layout, timestamp)
			if err != nil {
				log.Fatal("ListZones: Error from time.Parse():", err)
			}

			sg, _ := mdb.GetSignerGroup(signergroup)
			nexttransitions := mdb.FSMlist[fsm].States[state].Next
			next := map[string]bool{}
			for k, _ := range nexttransitions {
				next[k] = true
			}

			zl[name] = Zone{
				Name:       name,
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
