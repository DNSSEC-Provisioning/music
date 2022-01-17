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

func (mdb *MusicDB) AddSignerGroup(group string) error {
	fmt.Printf("AddSignerGroup(%s)\n", group)
	delcmd := "DELETE FROM signergroups WHERE name=?"
	addcmd := "INSERT INTO signergroups(name) VALUES (?)"
	delstmt, err := mdb.Prepare(delcmd)
	if err != nil {
		fmt.Printf("AddSignerGroup: Error from db.Prepare: %v\n", err)
	}
	addstmt, err := mdb.Prepare(addcmd)
	if err != nil {
		fmt.Printf("AddSignerGroup: Error from db.Prepare: %v\n", err)
	}

	mdb.mu.Lock()
	_, err = delstmt.Exec(group)
	if CheckSQLError("AddSignerGroup", delcmd, err, false) {
		mdb.mu.Unlock()
		return err
	}
	_, err = addstmt.Exec(group)
	mdb.mu.Unlock()

	if CheckSQLError("AddSignerGroup", addcmd, err, false) {
		return err
	}
	return nil
}

const (
      GSGsql1 = `
SELECT name, locked, COALESCE(curprocess, '') AS curp, COALESCE(pendadd, '') AS padd,
  COALESCE(pendremove, '') AS prem, numzones, numprocesszones
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

	var locked bool
	var name, curprocess, pendadd, pendremove string
	var numzones, numprocesszones int
	switch err = row.Scan(&name, &locked, &curprocess, &pendadd,
	       	     		     &pendremove, &numzones, &numprocesszones); err {
	case sql.ErrNoRows:
		fmt.Printf("GetSignerGroup: Signer group \"%s\" does not exist\n", sg)
		return &SignerGroup{}, fmt.Errorf("GetSignerGroup: Signer group \"%s\" does not exist", sg)
	case nil:
		_, sm := mdb.GetGroupSigners(name, apisafe)
		dbref := mdb
		if apisafe {
		   dbref = nil
		}
		return &SignerGroup{
			Name:			name,
			Locked:			locked,
			NumZones:		numzones,
			NumProcessZones:	numprocesszones,
			CurrentProcess:		curprocess,
			PendingAddition:	pendadd,
			PendingRemoval:		pendremove,
			SignerMap:		sm,
			DB:        		dbref,
		}, nil

	default:
		log.Fatalf("GetSigner: error from row.Scan(): name=%s, err=%v", sg, err)
	}
	return &SignerGroup{}, err
}

// DeleteSignerGroup: it is always possible to delete a signer group. If there are signers
// that are part of the signer group then they are thrown out. Obviously, deleting a signer
// group is a major change that should not be undertaken lightly, but at the same time it is
// more or less the only tool we have to force a cleanup if or when stuff has gotten seriously
// out of whack.

const (
      DSGsql1 = "DELETE FROM signergroups WHERE name=?"
      DSGsql2 = "UPDATE signers SET sgroup=? WHERE sgroup=?"
      DSGsql3 = "DELETE FROM group_signers WHERE name=?"
)

func (mdb *MusicDB) DeleteSignerGroup(group string) error {
	mdb.mu.Lock()
	stmt, err := mdb.Prepare(DSGsql1)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from db.Prepare '%s': %v\n", DSGsql1, err)
	}
	_, err = stmt.Exec(group)
	if CheckSQLError("DeleteSignerGroup", DSGsql1, err, false) {
	   	mdb.mu.Unlock()
		return err
	}

	stmt, err = mdb.Prepare(DSGsql3)
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from db.Prepare: %v\n", err)
	}
	_, err = stmt.Exec(group)
	mdb.mu.Unlock()

	if CheckSQLError("DeleteSignerGroup", DSGsql3, err, false) {
		return err
	}
	return nil
}

const (
	LSGsql  = `
SELECT name, COALESCE(curprocess, '') AS curp, COALESCE (pendadd, '') AS padd,
   COALESCE(pendremove, '') AS prem
FROM signergroups`
	LSGsql2 = "SELECT DISTINCT name FROM signergroups"
	LSGsql3 = "SELECT COALESCE (signer, '') AS signer2 FROM group_signers WHERE name=?"
)

func (mdb *MusicDB) ListSignerGroups() (map[string]SignerGroup, error) {
	var sgl = make(map[string]SignerGroup, 2)

	rows, err := mdb.db.Query(LSGsql)

	if CheckSQLError("ListSignerGroups", LSGsql2, err, false) {
		return sgl, err
	} else {
		var name, curp, pendadd, pendrem string
		for rows.Next() {
			err := rows.Scan(&name, &curp, &pendadd, &pendrem)
			if err != nil {
				log.Fatal("ListSignerGroups: Error from rows.Next():", err)
			}
			sgl[name] = SignerGroup{
				  Name:			name,
				  CurrentProcess:	curp,
				  PendingAddition:	pendadd,
				  PendingRemoval:	pendrem,
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
				if signer == "" {	// There may be rows with signer=="" (if group created w/o signers)
				   continue
				}
				s, err := mdb.GetSignerByName(signer, true) // apisafe
				if err != nil {
					log.Fatalf("ListSignerGroups: Error from GetSigner: %v", err)
				} else {
					signers[signer] = s
				}
				zones, _ = mdb.GetSignerGroupZones(&sg)
			}
//			sgl[sgname] = SignerGroup{
//				Name:      sgname,
//				SignerMap: signers,
//			}
			sg.SignerMap = signers
			sg.NumZones  = len(zones)
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
				fmt.Printf("PS: got signer name: %s\n", name)
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
			   continue		// This does happen, not a problem
			}
			fmt.Printf("GGS: got signer name: %s\n", signer)
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
				fmt.Printf("GGSNG: got signer name: %s\n", signername)
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
