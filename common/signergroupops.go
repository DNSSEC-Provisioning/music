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

func (mdb *MusicDB) GetSignerGroup(sg string, apisafe bool) (*SignerGroup, error) {
	if sg == "" {
		return &SignerGroup{}, errors.New("Empty signer group does not exist")
	}

	sqlcmd := "SELECT name FROM signergroups WHERE name=?"
	stmt, err := mdb.Prepare(sqlcmd)
	if err != nil {
		fmt.Printf("GetSignerGroup: Error from db.Prepare: %v\n", err)
	}

	row := stmt.QueryRow(sg)

	var name string
	switch err = row.Scan(&name); err {
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
			Name:      name,
			SignerMap: sm,
			DB:        dbref,
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

func (mdb *MusicDB) DeleteSignerGroup(group string) error {
	mdb.mu.Lock()
	stmt, err := mdb.Prepare("DELETE FROM signergroups WHERE name=?")
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from db.Prepare: %v\n", err)
	}
	_, err = stmt.Exec(group)
	if CheckSQLError("DeleteSignerGroup", "DELETE FROM signergroups ...", err, false) {
	   	mdb.mu.Unlock()
		return err
	}

	stmt, err = mdb.Prepare("UPDATE signers SET sgroup=? WHERE sgroup=?")
	if err != nil {
		fmt.Printf("DeleteSignerGroup: Error from db.Prepare: %v\n", err)
	}
	_, err = stmt.Exec("", group)
	mdb.mu.Unlock()

	if CheckSQLError("DeleteSignerGroup", "UPDATE signers SET ...", err, false) {
		return err
	}
	return nil
}

const (
	LSGsql = "SELECT name FROM signergroups"
	LSGsql2 = "SELECT name FROM signers WHERE sgroup=?"
)

func (mdb *MusicDB) ListSignerGroups() (map[string]SignerGroup, error) {
	var sgl = make(map[string]SignerGroup, 2)

	var sgnames []string

	rows, err := mdb.db.Query(LSGsql)

	if CheckSQLError("ListSignerGroups", LSGsql, err, false) {
		return sgl, err
	} else {
		var name string
		for rows.Next() {
			err := rows.Scan(&name)
			if err != nil {
				log.Fatal("ListSignerGroups: Error from rows.Next():", err)
			}
			// sgl[name] = true
			sgnames = append(sgnames, name)
		}
	}
	rows.Close()

	for _, sgname := range sgnames {
		stmt, err := mdb.Prepare(LSGsql2)
		if err != nil {
			fmt.Printf("ListSignerGroup: Error from db.Prepare: %v\n", err)
		}

		rows, err := stmt.Query(sgname)
		defer rows.Close()

		if CheckSQLError("ListSignerGroups", LSGsql2, err, false) {
			return sgl, err
		} else {
			var name string
			signers := map[string]*Signer{}
			for rows.Next() {
				err := rows.Scan(&name)
				if err != nil {
					log.Fatal("ListSignerGroups: Error from rows.Next():", err)
				} else {
					s, err := mdb.GetSignerByName(name, true) // apisafe
					if err != nil {
						log.Fatalf("ListSignerGroups: Error from GetSigner: %v", err)
					} else {
						signers[name] = s
					}
				}
			}
			sgl[sgname] = SignerGroup{
				Name:      sgname,
				SignerMap: signers,
			}
		}
	}

	// fmt.Printf("ListSignerGroup(): %v\n", sgl)
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

func (mdb *MusicDB) GetGroupSigners(name string, apisafe bool) (error, map[string]*Signer) {
	sqlcmd := "SELECT name, method, auth, COALESCE (addr, '') AS address FROM signers WHERE sgroup=?"
	stmt, err := mdb.Prepare(sqlcmd)
	if err != nil {
		fmt.Printf("GetGroupSigners: Error from db.Prepare: %v\n", err)
	}

	rows, err := stmt.Query(name)
	defer rows.Close()

	signers := map[string]*Signer{}

	if CheckSQLError("GetGroupSigners", sqlcmd, err, false) {
		return err, map[string]*Signer{}
	} else {
		var name, method, auth, address string
		for rows.Next() {
			err := rows.Scan(&name, &method, &auth, &address)
			if err != nil {
				log.Fatal("GetGroupSigners: Error from rows.Next():",
					err)
			} else {
				// fmt.Printf("GGS: got signer name: %s\n", name)
				s, err := mdb.GetSignerByName(name, apisafe)
				if err != nil {
					log.Fatalf("GGS: Error from GetSigner: %v", err)
				} else {
					signers[name] = s
					// fmt.Printf("LSG: found signer obj for %s: %v\n", name, s)
				}
			}
		}
	}
	return nil, signers
}

const (
	GGSNGsql = "SELECT signer FROM signergroups WHERE name=?"
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
