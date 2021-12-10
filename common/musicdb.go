/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

var DefaultTables = map[string]string{
	"zones": `CREATE TABLE IF NOT EXISTS 'zones' (
id          INTEGER PRIMARY KEY,
name        TEXT,
state       TEXT,
statestamp  DATETIME,
fsm         TEXT,
sgroup      TEXT
)`,

	"zone_dnskeys": `CREATE TABLE IF NOT EXISTS 'zone_dnskeys' (
id          INTEGER PRIMARY KEY,
zone        TEXT,
dnskey      TEXT,
signer      TEXT,
UNIQUE (zone, dnskey)
)`,

	"zone_nses": `CREATE TABLE IF NOT EXISTS 'zone_nses' (
id          INTEGER PRIMARY KEY,
zone        TEXT,
ns          TEXT,
signer      TEXT,
UNIQUE (zone, ns)
)`,

	"signers": `CREATE TABLE IF NOT EXISTS 'signers' (
id          INTEGER PRIMARY KEY,
name        TEXT,
method      TEXT,
auth        TEXT,
addr        TEXT,
status      TEXT,
sgroup      TEXT
)`,

	"signergroups": `CREATE TABLE IF NOT EXISTS 'signergroups' (
id          INTEGER PRIMARY KEY,
name        TEXT
)`,

	"records": `CREATE TABLE IF NOT EXISTS 'records' (
id          INTEGER PRIMARY KEY,
zone	    TEXT,
owner       TEXT,
signer      TEXT,
rrtype      INTEGER,
rdata       TEXT
)`,

	"metadata": `CREATE TABLE IF NOT EXISTS 'metadata' (
id         INTEGER PRIMARY KEY,
zone       TEXT,
key        TEXT,
value      TEXT,
UNIQUE (zone, key)
)`,
}

func dbSetupTables(db *sql.DB) bool {
	fmt.Printf("Setting up missing tables\n")

	for t, s := range DefaultTables {
		stmt, err := db.Prepare(s)
		if err != nil {
			log.Printf("dbSetupTables: Error from %s schema \"%s\": %v",
				t, s, err)
		}
		_, err = stmt.Exec()
		if err != nil {
			log.Fatalf("Failed to set up db schema: %s. Error: %s",
				s, err)
		}
	}

	return false
}

func NewDB(force bool) *MusicDB {
	dbfile := viper.GetString("common.db")
	fmt.Printf("NewMusicDB: using sqlite db in file %s\n", dbfile)
	if err := os.Chmod(dbfile, 0664); err != nil {
		log.Printf("NewMusicDB: Error trying to ensure that db %s is writable: %v",
			err)
	}
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		log.Printf("NewMusicDB: Error from sql.Open: %v", err)
	}

	if force {
		for table, _ := range DefaultTables {
			sqlcmd := fmt.Sprintf("DROP TABLE %s", table)
			_, err = db.Exec(sqlcmd)
			if err != nil {
				log.Printf("NewMusicDB: Error when dropping table %s: %v", table, err)
			}
		}
	}
	dbSetupTables(db)
	var mdb = MusicDB{
			db: db,
			FSMlist: map[string]FSM{},
		  }
        return &mdb
}

func (mdb *MusicDB) Prepare(sqlq string) (*sql.Stmt, error) {
     return mdb.db.Prepare(sqlq)
}

func (mdb *MusicDB) GetSignerByName(signername string, apisafe bool) (*Signer, error) {
	return mdb.GetSigner(&Signer{Name: signername}, apisafe)
}

func (mdb *MusicDB) GetSigner(s *Signer, apisafe bool) (*Signer, error) {
	sqlcmd := "SELECT name, method, auth, COALESCE (addr, '') AS address, COALESCE (sgroup, '') AS signergroup FROM signers WHERE name=?"
	stmt, err := mdb.db.Prepare(sqlcmd)
	if err != nil {
		fmt.Printf("GetSigner: Error from db.Prepare: %v\n", err)
	}

	row := stmt.QueryRow(s.Name)

	var name, method, auth, address, signergroup string
	switch err = row.Scan(&name, &method, &auth, &address, &signergroup); err {
	case sql.ErrNoRows:
		// fmt.Printf("GetSigner: Signer \"%s\" does not exist\n", s.Name)
		return &Signer{
			Name:    s.Name,
			Exists:  false,
			Method:  s.Method,
			Auth:    s.Auth,
			Address: s.Address,
		}, fmt.Errorf("Signer %s is unknown.", s.Name)

	case nil:
		// fmt.Printf("GetSigner: found signer(%s, %s, %s, %s, %s)\n", name,
		// 			  method, auth, address, signergroup)
		dbref := mdb
		if apisafe {
	   	   dbref = nil
		}
		return &Signer{
			Name:        name,
			Exists:      true,
			Method:      method,
			Auth:        auth, // AuthDataTmp(auth), // TODO: Issue #28
			Address:     address,
			SignerGroup: signergroup,
			DB:          dbref,
		}, nil

	default:
		log.Fatalf("GetSigner: error from row.Scan(): name=%s, err=%v", s, err)
	}
	return &Signer{
		Name:   s.Name,
		Exists: false,
	}, err
}

func CheckSQLError(caller, sqlcmd string, err error, abort bool) bool {
	if err != nil {
		if abort {
			log.Fatalf("%s: Error from db.Exec: SQL: %s err: %v",
				caller, sqlcmd, err)
		} else {
			log.Printf("%s: Error from db.Exec: SQL: %s err: %v",
				caller, sqlcmd, err)
		}
	}
	return err != nil
}
