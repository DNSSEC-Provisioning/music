/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func (mdb *MusicDB) AddSignerGroup(sg string) (error, string) {
	fmt.Printf("AddSignerGroup(%s)\n", sg)

	if sg == "" {
		return errors.New("Signer group without name cannot be created"), ""
	}
	
	_, err := mdb.GetSignerGroup(sg, false)
	if err == nil {
	    return err, fmt.Sprintf("Signergroup %s already exists.", sg)
	}

	addcmd := "INSERT OR REPLACE INTO signergroups(name) VALUES (?)"
	addstmt, err := mdb.Prepare(addcmd)
	if err != nil {
		fmt.Printf("AddSignerGroup: Error from db.Prepare: %v\n", err)
	}

	mdb.mu.Lock()
	_, err = addstmt.Exec(sg)
	mdb.mu.Unlock()

	if CheckSQLError("AddSignerGroup", addcmd, err, false) {
		return err, fmt.Sprintf("Signergroup %s not created. Reason: %v", sg, err)
	}
	return nil, fmt.Sprintf("Signergroup %s created.", sg)
}

const (
	GSGsql1 = `
SELECT name, locked, COALESCE(curprocess, '') AS curp, COALESCE(pendadd, '') AS padd,
  COALESCE(pendremove, '') AS prem
FROM signergroups WHERE name=?`
)

func (mdb *MusicDB) GetSignerGroup(sg string, apisafe bool) (*SignerGroup, error) {
	if sg == "" {
		return &SignerGroup{}, errors.New("Empty signer group does not exist")
	}

	stmt, err := mdb.Prepare(GSGsql1)
	if err != nil {
		fmt.Printf("GetSignerGroup: Error from db.Prepare '%s': %v\n", GSGsql1, err)
	}

	row := stmt.QueryRow(sg)

	var sqllocked int
	var name, curprocess, pendadd, pendremove string
	switch err = row.Scan(&name, &sqllocked, &curprocess, &pendadd, &pendremove); err {
	case sql.ErrNoRows:
		fmt.Printf("GetSignerGroup: Signer group \"%s\" does not exist\n", sg)
		return &SignerGroup{}, fmt.Errorf("GetSignerGroup: Signer group \"%s\" does not exist", sg)
	case nil:
		_, sm := mdb.GetGroupSigners(name, apisafe)
		dbref := mdb
		if apisafe {
			dbref = nil
		}

		sg := SignerGroup{
			Name:            name,
			Locked:          sqllocked == 1,
			CurrentProcess:  curprocess,
			PendingAddition: pendadd,
			PendingRemoval:  pendremove,
			SignerMap:       sm,
			DB:              dbref,
		}

		zones, _ := mdb.GetSignerGroupZones(&sg)
		pzones := 0
		for _, z := range zones {
			if z.FSM != "" {
				pzones++
			}
		}
		sg.NumZones = len(zones)
		sg.NumProcessZones = pzones
		return &sg, nil

	default:
		log.Fatalf("GetSignerGroup: error from row.Scan(): name=%s, err=%v", sg, err)
	}
	return &SignerGroup{}, err
}

// DeleteSignerGroup: it is always possible to delete a signer group.
// * If there are signers that are part of the signer group then they are thrown out.
// * If there are zones that are part of the signer group, then they are thrown out.
// Obviously, deleting a signer
// group is a major change that should not be undertaken lightly, but at the same time it is
// more or less the only tool we have to force a cleanup if or when stuff has gotten seriously
// out of whack.

const (
	DSGsql1 = "DELETE FROM signergroups WHERE name=?"
	DSGsql2 = "UPDATE signers SET sgroup=? WHERE sgroup=?"
	DSGsql3 = "DELETE FROM group_signers WHERE name=?"
	DSGsql4 = "UPDATE zones SET sgroup='' WHERE sgroup=?"
)

func (mdb *MusicDB) DeleteSignerGroup(group string) (error, string) {
	_, err := mdb.GetSignerGroup(group, false)
	if err != nil {
	    return err, fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err)
	}

        tx, err := mdb.Begin()
	if err != nil {
	   log.Printf("DeleteSignerGroup: Error from mdb.Begin(): %v", err)
	}
	defer tx.Commit()
	
	// mdb.mu.Lock()
	stmt, err := mdb.Prepare(DSGsql1)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from db.Prepare '%s': %v\n", DSGsql1, err)
	}
	_, err = stmt.Exec(group)
	if CheckSQLError("DeleteSignerGroup", DSGsql1, err, false) {
		// mdb.mu.Unlock()
		return err, fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err)
	}

	stmt, err = mdb.Prepare(DSGsql3)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from db.Prepare '%s': %v\n", DSGsql3, err)
	}
		_, err = stmt.Exec(group)
	// mdb.mu.Unlock()

	if CheckSQLError("DeleteSignerGroup", DSGsql3, err, false) {
		return err, fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err)
	}

	stmt, err = mdb.Prepare(DSGsql4)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from db.Prepare '%s': %v\n", DSGsql4, err)
	}
	_, err = stmt.Exec(group)
	// mdb.mu.Unlock()

	if CheckSQLError("DeleteSignerGroup", DSGsql3, err, false) {
		return err, fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err)
	}

	return nil, fmt.Sprintf("Signergroup %s deleted. Any zones or signers in signergroup were detached.", group)
}

const (
	LSGsql = `
SELECT name, COALESCE(curprocess, '') AS curp, COALESCE (pendadd, '') AS padd,
   COALESCE(pendremove, '') AS prem, locked
FROM signergroups`
	LSGsql2 = "SELECT DISTINCT name FROM signergroups"
	LSGsql3 = "SELECT COALESCE (signer, '') AS signer2 FROM group_signers WHERE name=?"
)

func (mdb *MusicDB) ListSignerGroups() (map[string]SignerGroup, error) {
	var sgl = make(map[string]SignerGroup, 2)

	rows, err := mdb.db.Query(LSGsql)

	if CheckSQLError("ListSignerGroups", LSGsql, err, false) {
		return sgl, err
	} else {
		var name, curp, pendadd, pendrem string
		var sqllocked int
		for rows.Next() {
			err := rows.Scan(&name, &curp, &pendadd, &pendrem, &sqllocked)
			if err != nil {
				log.Fatal("ListSignerGroups: Error from rows.Next():", err)
			}
			sgl[name] = SignerGroup{
				Name:            name,
				Locked:          sqllocked == 1,
				CurrentProcess:  curp,
				PendingAddition: pendadd,
				PendingRemoval:  pendrem,
			}
		}
	}
	rows.Close()

	for sgname, sg := range sgl {
		stmt, err := mdb.Prepare(LSGsql3)
		if err != nil {
			log.Printf("ListSignerGroup: Error from db.Prepare: %v\n", err)
		}

		rows, err := stmt.Query(sgname)
		defer rows.Close()

		if CheckSQLError("ListSignerGroups", LSGsql3, err, false) {
			return sgl, err
		} else {
			var signer string
			var zones = []*Zone{}
			signers := map[string]*Signer{}
			for rows.Next() {
				err := rows.Scan(&signer)
				if err != nil {
					log.Fatal("ListSignerGroups: Error from rows.Next():", err)
				}
				if signer == "" { // There may be rows with signer=="" (if group created w/o signers)
					continue
				}
				s, err := mdb.GetSignerByName(signer, true) // apisafe
				if err != nil {
					log.Fatalf("ListSignerGroups: Error from GetSigner: %v", err)
				} else {
					signers[signer] = s
				}
			}
			zones, _ = mdb.GetSignerGroupZones(&sg)

			pzones := 0
			for _, z := range zones {
				if z.FSM != "" {
					pzones++
				}
			}

			sg.SignerMap = signers
			sg.NumZones = len(zones)
			sg.NumProcessZones = pzones
			sgl[sgname] = sg
		}
	}

	fmt.Printf("ListSignerGroup(): %v\n", sgl)
	return sgl, nil
}

func (sg *SignerGroup) PopulateSigners() error {
	mdb := sg.DB
	sqlcmd := "SELECT name FROM signers WHERE sgroup=?"
	stmt, err := mdb.Prepare(sqlcmd)
	if err != nil {
		fmt.Printf("PopulateSigners: Error from db.Prepare: %v\n", err)
	}

	rows, err := stmt.Query(sg.Name)
	defer rows.Close()

	if CheckSQLError("PopulateSigners", sqlcmd, err, false) {
		return err
	} else {
		var name string
		signers := map[string]*Signer{}
		for rows.Next() {
			err := rows.Scan(&name)
			if err != nil {
				log.Fatal("PopulateSigners: Error from rows.Next():",
					err)
			} else {
				// fmt.Printf("PS: got signer name: %s\n", name)
				s, err := mdb.GetSignerByName(name, false) // not apisafe
				if err != nil {
					log.Fatalf("PopulateSigners: Error from GetSigner: %v", err)
				} else {
					signers[name] = s
					fmt.Printf("LSG: found signer obj for %s: %v\n",
						name, s)
				}
			}
		}
		sg.SignerMap = signers
	}
	return nil
}

const (
	GGSsql1 = "SELECT name, method, auth, COALESCE (addr, '') AS address FROM signers WHERE sgroup=?"
	GGSsql2 = "SELECT COALESCE (signer, '') AS signer2 FROM group_signers WHERE name=?"
)

func (mdb *MusicDB) GetGroupSigners(name string, apisafe bool) (error, map[string]*Signer) {

	stmt, err := mdb.Prepare(GGSsql2)
	if err != nil {
		fmt.Printf("GetGroupSigners: Error from db.Prepare: %v\n", err)
	}

	rows, err := stmt.Query(name)
	defer rows.Close()

	signers := map[string]*Signer{}

	if CheckSQLError("GetGroupSigners", GGSsql2, err, false) {
		return err, map[string]*Signer{}
	} else {
		var signer string
		for rows.Next() {
			err := rows.Scan(&signer)
			if err != nil {
				log.Fatal("GetGroupSigners: Error from rows.Next():", err)
			}
			if signer == "" {
				continue // This does happen, not a problem
			}
			// fmt.Printf("GGS: got signer name: %s\n", signer)
			s, err := mdb.GetSignerByName(signer, apisafe)
			if err != nil {
				log.Fatalf("GGS: Error from GetSigner: %v", err)
			} else {
				signers[signer] = s
				// fmt.Printf("LSG: found signer obj for %s: %v\n", signer, s)
			}
		}
	}
	return nil, signers
}

const (
	GGSNGsql = "SELECT signer FROM group_signers WHERE name=?"
)

func (mdb *MusicDB) GetGroupSignersNG(name string, apisafe bool) (error, map[string]*Signer) {
	stmt, err := mdb.Prepare(GGSNGsql)
	if err != nil {
		fmt.Printf("GetGroupSigners: Error from db.Prepare '%s': %v\n", GGSNGsql, err)
	}

	rows, err := stmt.Query(name)
	defer rows.Close()

	signers := map[string]*Signer{}

	if CheckSQLError("GetGroupSigners", GGSNGsql, err, false) {
		return err, map[string]*Signer{}
	} else {
		var signername string
		for rows.Next() {
			err := rows.Scan(&signername)
			if err != nil {
				log.Fatal("GetGroupSigners: Error from rows.Next():",
					err)
			} else {
				// fmt.Printf("GGSNG: got signer name: %s\n", signername)
				s, err := mdb.GetSignerByName(name, apisafe)
				if err != nil {
					log.Fatalf("GGS: Error from GetSigner: %v", err)
				} else {
					signers[signername] = s
					// fmt.Printf("LSG: found signer obj for %s: %v\n", name, s)
				}
			}
		}
	}
	return nil, signers
}

// XXX: Todo: in the wrap up of a REMOVE-SIGNER the signer in PendingRemoval should be physically
//      removed from the signer group.
//
func (mdb *MusicDB) CheckIfProcessComplete(sg *SignerGroup) (bool, string) {
	var msg string
	zones, _ := mdb.GetSignerGroupZones(sg)
	pzones := 0
	for _, z := range zones {
		if z.FSM != "" {
			pzones++
		}
	}

	if len(zones) == 0 || pzones == 0 {
		msg = fmt.Sprintf("Signer group %s: process '%s' is now complete. Unlocking group.",
			sg.Name, sg.CurrentProcess)
		log.Printf(msg)

		var sqlq string
		cp := sg.CurrentProcess
		pr := sg.PendingRemoval
		if cp == SignerJoinGroupProcess {
			sqlq = "UPDATE signergroups SET locked=0, curprocess='', pendadd='' WHERE name=?"
		} else if cp == SignerLeaveGroupProcess {
			sqlq = "UPDATE signergroups SET locked=0, curprocess='', pendremove='' WHERE name=?"
		} else if cp == "" { // curprocess is "" for zones in verify-zone-sync
			sqlq = "UPDATE signergroups SET locked=0, curprocess='', pendremove='' WHERE name=?"
		} else {
			log.Fatalf("CheckIfProcessIsComplete: Unknown process: %s. Terminating.", cp)
		}

		mdb.mu.Lock()
		stmt, err := mdb.Prepare(sqlq)
		if err != nil {
			log.Printf("CheckIfProcessIsComplete: Error from db.Prepare(%s): %v", sqlq, err)
		}
		_, err = stmt.Exec(sg.Name)
		if err != nil {
			log.Printf("CheckIfProcessIsComplete: Error from db.Exec(%s): %v", sqlq, err)
		}

		if cp == SignerLeaveGroupProcess {
			sqlq = "DELETE FROM group_signers WHERE name=? AND signer=?"
			stmt, err := mdb.Prepare(sqlq)
			if err != nil {
				log.Printf("CheckIfProcessIsComplete: Error from db.Prepare(%s): %v",
								      sqlq, err)
			}
			_, err = stmt.Exec(sg.Name, pr)
			if err != nil {
				log.Printf("CheckIfProcessIsComplete: Error from db.Exec(%s): %v",
								      sqlq, err)
			}
		}

		mdb.mu.Unlock()
		return true, msg
	}
	return false, ""
}
