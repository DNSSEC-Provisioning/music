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

func (mdb *MusicDB) AddSignerGroup(tx *sql.Tx, sg string) (error, string) {
	fmt.Printf("AddSignerGroup(%s)\n", sg)

	if sg == "" {
		return errors.New("Signer group without name cannot be created"), ""
	}
	
	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	_, err = mdb.GetSignerGroup(tx, sg, false)
	if err == nil {
	    return err, fmt.Sprintf("Signergroup %s already exists.", sg)
	}

	addcmd := "INSERT OR REPLACE INTO signergroups(name) VALUES (?)"
	addstmt, err := tx.Prepare(addcmd)
	if err != nil {
		fmt.Printf("AddSignerGroup: Error from tx.Prepare: %v\n", err)
	}

	_, err = addstmt.Exec(sg)

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

func (mdb *MusicDB) GetSignerGroup(tx *sql.Tx, sg string, apisafe bool) (*SignerGroup, error) {
	if sg == "" {
//		return &SignerGroup{}, errors.New("Empty signer group does not exist")
		return &SignerGroup{}, nil // A non-existent signergroup is not an error
	}

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return nil, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	stmt, err := tx.Prepare(GSGsql1)
	if err != nil {
		fmt.Printf("GetSignerGroup: Error from tx.Prepare '%s': %v\n", GSGsql1, err)
	}

	row := stmt.QueryRow(sg)

	var sqllocked int
	var name, curprocess, pendadd, pendremove string
	switch err = row.Scan(&name, &sqllocked, &curprocess, &pendadd, &pendremove); err {
	case sql.ErrNoRows:
		fmt.Printf("GetSignerGroup: Signer group \"%s\" does not exist\n", sg)
		return &SignerGroup{}, fmt.Errorf("GetSignerGroup: Signer group \"%s\" does not exist", sg)
	case nil:
		_, sm := mdb.GetGroupSigners(tx, name, apisafe)
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

		zones, _ := mdb.GetSignerGroupZones(tx, &sg)
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

func (mdb *MusicDB) DeleteSignerGroup(tx *sql.Tx, group string) (error, string) {

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

        _, err = mdb.GetSignerGroup(tx, group, false)
	if err != nil {
	    return err, fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err)
	}

	stmt, err := tx.Prepare(DSGsql1)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from tx.Prepare '%s': %v\n", DSGsql1, err)
	}
	_, err = stmt.Exec(group)
	if CheckSQLError("DeleteSignerGroup", DSGsql1, err, false) {
		return err, fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err)
	}

	stmt, err = tx.Prepare(DSGsql3)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from tx.Prepare '%s': %v\n", DSGsql3, err)
	}
		_, err = stmt.Exec(group)

	if CheckSQLError("DeleteSignerGroup", DSGsql3, err, false) {
		return err, fmt.Sprintf("Signergroup %s not deleted. Reason: %v", group, err)
	}

	stmt, err = tx.Prepare(DSGsql4)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from tx.Prepare '%s': %v\n", DSGsql4, err)
	}
	_, err = stmt.Exec(group)

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

func (mdb *MusicDB) ListSignerGroups(tx *sql.Tx) (map[string]SignerGroup, error) {
	var sgl = make(map[string]SignerGroup, 2)

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return sgl, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

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
		stmt, err := tx.Prepare(LSGsql3)
		if err != nil {
			log.Printf("ListSignerGroup: Error from tx.Prepare: %v\n", err)
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
				s, err := mdb.GetSignerByName(tx, signer, true) // apisafe
				if err != nil {
					log.Fatalf("ListSignerGroups: Error from GetSigner: %v", err)
				} else {
					signers[signer] = s
				}
			}
			zones, _ = mdb.GetSignerGroupZones(tx, &sg)

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

func (sg *SignerGroup) PopulateSigners(tx *sql.Tx) error {

     mdb := sg.DB

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	sqlcmd := "SELECT name FROM signers WHERE sgroup=?"
	stmt, err := tx.Prepare(sqlcmd)
	if err != nil {
		fmt.Printf("PopulateSigners: Error from tx.Prepare: %v\n", err)
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
				s, err := mdb.GetSignerByName(tx, name, false) // not apisafe
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

func (mdb *MusicDB) GetGroupSigners(tx *sql.Tx, name string, apisafe bool) (error, map[string]*Signer) {

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return err, nil
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	stmt, err := tx.Prepare(GGSsql2)
	if err != nil {
		fmt.Printf("GetGroupSigners: Error from tx.Prepare: %v\n", err)
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
			s, err := mdb.GetSignerByName(tx, signer, apisafe)
			if err != nil {
				log.Fatalf("GGS: Error from GetSigner: %v", err)
			} else {
				signers[signer] = s
			}
		}
	}
	return nil, signers
}

const (
	GGSNGsql = "SELECT signer FROM group_signers WHERE name=?"
)

func (mdb *MusicDB) GetGroupSignersNG(tx *sql.Tx, name string, apisafe bool) (error, map[string]*Signer) {

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return err, nil
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	stmt, err := tx.Prepare(GGSNGsql)
	if err != nil {
		fmt.Printf("GetGroupSigners: Error from tx.Prepare '%s': %v\n", GGSNGsql, err)
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
				s, err := mdb.GetSignerByName(tx, name, apisafe)
				if err != nil {
					log.Fatalf("GGS: Error from GetSigner: %v", err)
				} else {
					signers[signername] = s
				}
			}
		}
	}
	return nil, signers
}

// XXX: Todo: in the wrap up of a REMOVE-SIGNER the signer in PendingRemoval should be physically
//      removed from the signer group.
//
func (mdb *MusicDB) CheckIfProcessComplete(tx *sql.Tx, sg *SignerGroup) (bool, string, error) {
	var msg string

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return false, err.Error(), err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	zones, _ := mdb.GetSignerGroupZones(tx, sg)
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

		stmt, err := tx.Prepare(sqlq)
		if err != nil {
			log.Printf("CheckIfProcessIsComplete: Error from tx.Prepare(%s): %v", sqlq, err)
			return false, fmt.Sprintf("Error from tx.Prepare(%s): %v", sqlq, err), err
		}
		_, err = stmt.Exec(sg.Name)
		if err != nil {
			log.Printf("CheckIfProcessIsComplete: Error from db.Exec(%s): %v", sqlq, err)
			return false, fmt.Sprintf("Error from stmt.Exec(%s): %v", sqlq, err), err
		}

		if cp == SignerLeaveGroupProcess {
			sqlq = "DELETE FROM group_signers WHERE name=? AND signer=?"
			stmt, err := tx.Prepare(sqlq)
			if err != nil {
				log.Printf("CheckIfProcessIsComplete: Error from tx.Prepare(%s): %v",
								      sqlq, err)
				return false, fmt.Sprintf("Error from tx.Prepare(%s): %v", sqlq, err), err
								      
			}
			_, err = stmt.Exec(sg.Name, pr)
			if err != nil {
				log.Printf("CheckIfProcessIsComplete: Error from db.Exec(%s): %v",
								      sqlq, err)
			        return false, fmt.Sprintf("Error from stmt.Exec(%s): %v", sqlq, err), err

			}
		}

		return true, msg, nil
	}
	return false, "", nil	// not an error
}
