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
    //delcmd := fmt.Sprintf("DELETE FROM signergroups WHERE name='%s'", group)
    //addcmd := fmt.Sprintf("INSERT INTO signergroups(name) VALUES ('%s')", group)
    delcmd := "DELETE FROM signergroups WHERE name=?"
    addcmd := "INSERT INTO signergroups(name) VALUES (?)"
    delstmt, err := mdb.db.Prepare(delcmd)
    if err != nil {
        fmt.Printf("AddSignerGroup: Error from db.Prepare: %v\n", err)
    }
    addstmt, err := mdb.db.Prepare(addcmd)
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

func (mdb *MusicDB) GetSignerGroup(sg string) (*SignerGroup, error) {
    if sg == "" {
        return &SignerGroup{}, errors.New("Empty signer group does not exist")
    }

    sqlcmd := "SELECT name FROM signergroups WHERE name=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
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
        _, sm := mdb.GetGroupSigners(name)
        return &SignerGroup{
            Name:      name,
            SignerMap: sm,
            DB:        mdb,
        }, nil

    default:
        log.Fatalf("GetSigner: error from row.Scan(): name=%s, err=%v", sg, err)
    }
    return &SignerGroup{}, err
}

func (mdb *MusicDB) DeleteSignerGroup(group string) error {
    sqlcmd := "DELETE FROM signergroups WHERE name=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
    if err != nil {
        fmt.Printf("DeleteSignerGroup: Error from db.Prepare: %v\n", err)
    }

    mdb.mu.Lock()
    _, err = stmt.Exec(group)
    mdb.mu.Unlock()

    if CheckSQLError("DeleteSignerGroup", sqlcmd, err, false) {
        return err
    }
    return nil
}

func (mdb *MusicDB) ListSignerGroups() (map[string]SignerGroup, error) {
    var sgl = make(map[string]SignerGroup, 2)

    var sgnames []string

    sqlcmd := "SELECT name FROM signergroups"
    rows, err := mdb.db.Query(sqlcmd)

    if CheckSQLError("ListSignerGroups", sqlcmd, err, false) {
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
    fmt.Printf("LSG: sgnames: %v\n", sgnames)

    for _, sgname := range sgnames {
        sqlcmd = "SELECT name FROM signers WHERE sgroup=?"
        stmt, err := mdb.db.Prepare(sqlcmd)
        if err != nil {
            fmt.Printf("ListSignerGroup: Error from db.Prepare: %v\n", err)
        }

        rows, err := stmt.Query(sgname)
        defer rows.Close()

        if CheckSQLError("ListSignerGroups", sqlcmd, err, false) {
            return sgl, err
        } else {
            var name string
            signers := map[string]*Signer{}
            for rows.Next() {
                err := rows.Scan(&name)
                if err != nil {
                    log.Fatal("ListSignerGroups: Error from rows.Next():",
                        err)
                } else {
                    fmt.Printf("LSG: got signer name: %s\n", name)
                    s, err := mdb.GetSigner(&Signer{ Name: name })
                    if err != nil {
                        log.Fatalf("ListSignerGroups: Error from GetSigner: %v", err)
                    } else {
                        signers[name] = s
                        fmt.Printf("LSG: found signer obj for %s: %v\n",
                            name, s)
                    }
                }
            }
            sgl[sgname] = SignerGroup{
                Name:      sgname,
                SignerMap: signers,
            }
        }
    }

    fmt.Printf("ListSignerGroup(): %v\n", sgl)
    return sgl, nil
}

func (sg *SignerGroup) PopulateSigners() error {
    mdb := sg.DB
    sqlcmd := "SELECT name FROM signers WHERE sgroup=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
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
                s, err := mdb.GetSigner(&Signer{ Name: name })
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

func (mdb *MusicDB) GetGroupSigners(name string) (error, map[string]*Signer) {
    sqlcmd := "SELECT name, method, auth, COALESCE (addr, '') AS address FROM signers WHERE sgroup=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
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
                s, err := mdb.GetSigner(&Signer{ Name: name })
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
