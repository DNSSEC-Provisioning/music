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
    "status": `CREATE TABLE IF NOT EXISTS 'status' (
item      VARCHAR(20),
value     VARCHAR(20))`,

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

var StatusInitialItems = map[string]string{
    "signers":      "0",
    "zones":        "0",
    "signergroups": "0",
}

func tableExists(db *sql.DB, name string) bool {

    var match string
    var err error

    sqlcmd := fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' AND name='%s'", name)
    row := db.QueryRow(sqlcmd)

    switch err = row.Scan(&match); err {
    case sql.ErrNoRows:
        fmt.Printf("Error: tableExists: table %s not found.\n", name)
        return false
    case nil:
        // all ok
        fmt.Printf("tableExists: found table '%s'\n", match)
        return true
    default:
        panic(err)
    }
    return false
}

func dbSetupTables(db *sql.DB) bool {
    fmt.Printf("Setting up missing tables\n")

    for t, s := range DefaultTables {
        if !tableExists(db, t) {
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
    }

    stmt, err := db.Prepare("INSERT INTO status (item, value) VALUES (?, ?)")
    for item, value := range StatusInitialItems {
        stmt.Exec(item, value)
        if err != nil {
            log.Fatalf("Failed to insert into status table: <%s, %s>. Error: %v",
                item, value, err)
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

func (mdb *MusicDB) GetStatus(field string) string {
    sqlq := fmt.Sprintf("SELECT value FROM status WHERE item=\"%s\"", field)
    row := mdb.db.QueryRow(sqlq)

    var err error
    var value string
    switch err = row.Scan(&value); err {
    case sql.ErrNoRows:
        fmt.Printf("GetStatus: No rows were returned querying for field \"%s\"\n", field)
    case nil:
        return value
    default:
        log.Fatalf("GetStatus: error from row.Scan(): value=%s, err=%v", value, err)
    }
    return value
}

func (mdb *MusicDB) SetStatus(field, value string) {

    //    sqlcmd := fmt.Sprintf("INSERT OR REPLACE INTO status (item, value) VALUES (%s, '%s')",
    //        field, value)
    //    sqlcmd := fmt.Sprintf("UPDATE status SET value='%s' WHERE item='%s'", value, field)
    sqlcmd := fmt.Sprintf("DELETE FROM status WHERE item='%s'", field)
    _, err := mdb.db.Exec(sqlcmd)
    if err != nil {
        log.Printf("SetStatus: Error executing SQL statement: %s", sqlcmd)
    }
    sqlcmd = fmt.Sprintf("INSERT INTO status(item, value) VALUES ('%s', '%s')",
        field, value)

    _, err = mdb.db.Exec(sqlcmd)
    // defer rows.Close()
    if err != nil {
        log.Printf("SetStatus: Error from db.Query: %v", err)
    }
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
