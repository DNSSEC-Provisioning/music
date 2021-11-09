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
id        INTEGER PRIMARY KEY,
name      VARCHAR(128),
state     VARCHAR(32),
statestamp DATETIME,
fsm       VARCHAR(32),
sgroup    VARCHAR(32))`,

    "signers": `CREATE TABLE IF NOT EXISTS 'signers' (
id        INTEGER PRIMARY KEY,
name      VARCHAR(128),
method    VARCHAR(32),
auth      VARCHAR(32),
addr      VARCHAR(32),
status      VARCHAR(32),
sgroup      VARCHAR(32))`,

    "signergroups": `CREATE TABLE IF NOT EXISTS 'signergroups' (
id        INTEGER PRIMARY KEY,
name      VARCHAR(32))`,

    "records": `CREATE TABLE IF NOT EXISTS 'records' (
id        INTEGER PRIMARY KEY,
owner     VARCHAR(64),
signer      VARCHAR(32),
rrtype      INTEGER,
rdata      VARCHAR(128))`,
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
    return &MusicDB{db: db}
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
