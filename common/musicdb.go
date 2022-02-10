/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

var DefaultTables = map[string]string{

// zones: fsmmode = {auto,manual}, if auto then the fsmengine in musicd will try to move the zone
//        forward through its process until it hits a stop. "stop" is indicated by fststate="stop"
//        and then there should be a documented stop-reason in the metadata table.

	"zones": `CREATE TABLE IF NOT EXISTS 'zones' (
id          INTEGER PRIMARY KEY,
name        TEXT NOT NULL DEFAULT '',
zonetype    TEXT NOT NULL DEFAULT '',
state       TEXT NOT NULL DEFAULT '',
statestamp  DATETIME,
fsm         TEXT NOT NULL DEFAULT '',
fsmsigner   TEXT NOT NULL DEFAULT '',	
fsmmode     TEXT NOT NULL DEFAULT '',
fsmstate    TEXT NOT NULL DEFAULT '',
sgroup      TEXT NOT NULL DEFAULT '',
UNIQUE (name, sgroup)
)`,

	"zone_dnskeys": `CREATE TABLE IF NOT EXISTS 'zone_dnskeys' (
id          INTEGER PRIMARY KEY,
zone        TEXT NOT NULL DEFAULT '',
dnskey      TEXT NOT NULL DEFAULT '',
signer      TEXT NOT NULL DEFAULT '',
UNIQUE (zone, dnskey)
)`,

	"zone_nses": `CREATE TABLE IF NOT EXISTS 'zone_nses' (
id          INTEGER PRIMARY KEY,
zone        TEXT NOT NULL DEFAULT '',
ns          TEXT NOT NULL DEFAULT '',
signer      TEXT NOT NULL DEFAULT '',
UNIQUE (zone, ns)
)`,

	"signers": `CREATE TABLE IF NOT EXISTS 'signers' (
id          INTEGER PRIMARY KEY,
name        TEXT NOT NULL DEFAULT '',
method      TEXT NOT NULL DEFAULT '',
auth        TEXT NOT NULL DEFAULT '',
addr        TEXT NOT NULL DEFAULT '',
port        TEXT NOT NULL DEFAULT '',
status      TEXT NOT NULL DEFAULT '',
usetcp	    BOOLEAN NOT NULL DEFAULT 1 CHECK (usetcp IN (0, 1)),
usetsig	    BOOLEAN NOT NULL DEFAULT 1 CHECK (usetsig IN (0, 1)),
UNIQUE (name)
)`,

	"signergroups": `CREATE TABLE IF NOT EXISTS 'signergroups' (
id          INTEGER PRIMARY KEY,
name        TEXT NOT NULL DEFAULT '',
locked	    INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
curprocess  TEXT NOT NULL DEFAULT '',
pendadd	    TEXT NOT NULL DEFAULT '',
pendremove  TEXT NOT NULL DEFAULT '',
UNIQUE (name)
)`,

	"group_signers": `CREATE TABLE IF NOT EXISTS 'group_signers' (
id          INTEGER PRIMARY KEY,
name        TEXT NOT NULL DEFAULT '',
signer	    TEXT NOT NULL DEFAULT '',
UNIQUE (name, signer)
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
zone       TEXT NOT NULL DEFAULT '',
key        TEXT NOT NULL DEFAULT '',
time	   DATETIME,
value      TEXT NOT NULL DEFAULT '',
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
	log.Printf("NewMusicDB: using sqlite db in file %s\n", dbfile)

	_, err := os.Stat(dbfile)
	if !os.IsNotExist(err) {
	   if err := os.Chmod(dbfile, 0664); err != nil {
		log.Printf("NewMusicDB: Error trying to ensure that db %s is writable: %v", err)
	   }
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
		db:      db,
		FSMlist: map[string]FSM{},
	}
	return &mdb
}

func (mdb *MusicDB) Prepare(sqlq string) (*sql.Stmt, error) {
	return mdb.db.Prepare(sqlq)
}

func (mdb *MusicDB) Begin() (*sql.Tx, error) {
	return mdb.db.Begin()
}

const (
	GSGsql  = "SELECT name FROM signergroups WHERE signer=?"
	GSGsql2 = "SELECT name FROM group_signers WHERE signer=?"
)

func (mdb *MusicDB) GetSignerGroups(name string) ([]string, error) {
	var sgs = []string{}
	stmt, err := mdb.Prepare(GSGsql2)
	if err != nil {
		fmt.Printf("GetSigner: Error from db.Prepare '%s': %v\n", GSGsql2, err)
	}

	rows, err := stmt.Query(name)
	if CheckSQLError("GetSignerGroups", GSGsql2, err, false) {
		return []string{}, err
	} else {
		var signergroup string
		for rows.Next() {
			err := rows.Scan(&signergroup)
			if err != nil {
				log.Fatalf("signer.GetSignerGroups(): Error from rows.Next(): %v", err)
			} else {
				sgs = append(sgs, signergroup)
			}
		}
	}
	return sgs, nil
}

func (mdb *MusicDB) GetSignerByName(signername string, apisafe bool) (*Signer, error) {
	return mdb.GetSigner(&Signer{Name: signername}, apisafe)
}

const (
	GSsql = `
SELECT name, method, auth,
  COALESCE (addr, '') AS address, port, usetcp, usetsig
FROM signers WHERE name=?`
)

func (mdb *MusicDB) GetSigner(s *Signer, apisafe bool) (*Signer, error) {
	stmt, err := mdb.Prepare(GSsql)
	if err != nil {
		fmt.Printf("GetSigner: Error from db.Prepare '%s': %v\n", GSsql, err)
	}

	row := stmt.QueryRow(s.Name)

	var name, method, authstr, address, port string
	var usetcp, usetsig bool
	switch err = row.Scan(&name, &method, &authstr, &address, &port, &usetcp, &usetsig); err {
	case sql.ErrNoRows:
		// fmt.Printf("GetSigner: Signer \"%s\" does not exist\n", s.Name)
		return &Signer{
			Name:    s.Name,
			Exists:  false,
			Method:  s.Method,
			AuthStr: s.AuthStr,
			Auth:    s.Auth,
			Address: s.Address,
			Port:    s.Port,
			UseTcp:  s.UseTcp,
			UseTSIG: s.UseTSIG,
		}, fmt.Errorf("Signer %s is unknown.", s.Name)

	case nil:
		// fmt.Printf("GetSigner: found signer(%s, %s, %s, %s, %s)\n", name,
		// 			  method, authstr, address, signergroup)
		sgs, err := mdb.GetSignerGroups(s.Name)
		if err != nil {
			log.Fatalf("mdb.GetSigner: Error from signer.GetSignerGroups: %v", err)
		}

		auth := AuthData{}
		p := strings.Split(authstr, ":")
		if len(p) == 3 {
			auth = AuthData{
				TSIGAlg:  p[0],
				TSIGName: p[1],
				TSIGKey:  p[2],
			}
		}

		dbref := mdb
		if apisafe {
			dbref = nil
		}
		return &Signer{
			Name:         name,
			Exists:       true,
			Method:       method,
			AuthStr:      authstr,
			Auth:         auth, // AuthDataTmp(auth), // TODO: Issue #28
			Address:      address,
			Port:         port,
			UseTcp:       usetcp,
			UseTSIG:      usetsig,
			SignerGroups: sgs,
			DB:           dbref,
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
