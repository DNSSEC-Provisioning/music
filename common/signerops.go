/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
    "database/sql"
    "errors"
    "fmt"
    "log"
    "strings"

    _ "github.com/mattn/go-sqlite3"
    "github.com/spf13/viper"
)

// func (s *Signer) Address() string {
//     return s.address
// }

// func (s *Signer) Method() string {
//     return s.method
// }

func (s *Signer) MusicDB() *MusicDB {
    return s.DB
}

func (mdb *MusicDB) AddSigner(s Signer) (error, string) {
    var err error
    if _, err = mdb.GetSigner(s.Name); err == nil {
        return errors.New(fmt.Sprintf("Signer %s already present in MuSiC system.", s.Name)), ""
    }
    fmt.Printf("AddSigner: err: %v\n", err)

    //delcmd := fmt.Sprintf("DELETE FROM signers WHERE name='%s'", s.Name)
    delq := "DELETE FROM signers WHERE name=?"
    // addcmd := fmt.Sprintf("INSERT INTO signers(name, method, auth, addr) VALUES ('%s', '%s', '%s', '%s')",
    //    s.Name, s.Method, s.Auth, s.Address)
    addq := "INSERT INTO signers(name, method, auth, addr) VALUES (?, ?, ?, ?)"

    s.Method = strings.ToLower(s.Method)
    ok := false

    switch s.Method {
    case "ddns", "desec-api":
        ok = true
    }

    if !ok {
        return errors.New(fmt.Sprintf(
            "Unknown signer method: %s. Known methods are: 'ddns' and 'desec-api'", s.Method)), ""
    }

    delstmt, err := mdb.db.Prepare(delq)
    if err != nil {
        fmt.Printf("AddSigner: Error from db.Prepare: %v\n", err)
    }
    addstmt, err := mdb.db.Prepare(addq)
    if err != nil {
        fmt.Printf("AddSigner: Error from db.Prepare: %v\n", err)
    }

    mdb.mu.Lock()
    _, err = delstmt.Exec(s.Name)
    if CheckSQLError("AddSigner", delq, err, false) {
        mdb.mu.Unlock()
        return err, ""
    }
    _, err = addstmt.Exec(s.Name, s.Method, s.Auth, s.Address)
    mdb.mu.Unlock()

    if CheckSQLError("AddSigner", addq, err, false) {
        fmt.Printf("AddSigner: failure: %s, %s, %s, %s\n",
            s.Name, s.Method, s.Auth, s.Address)
        return err, ""
    }
    fmt.Printf("AddSigner: success: %s, %s, %s, %s\n", s.Name, s.Method, s.Auth, s.Address)
    return nil, fmt.Sprintf("New signer %s successfully added.", s.Name)
}

func (mdb *MusicDB) UpdateSigner(s Signer) (error, string) {
    var err error
    if _, err = mdb.GetSigner(s.Name); err != nil {
        return errors.New(fmt.Sprintf("Signer %s not present in MuSiC system.", s.Name)), ""
    }

    s.Method = strings.ToLower(s.Method)
    ok := false

    switch s.Method {
    case "ddns", "desec-api":
        ok = true
    }

    if !ok {
        return errors.New(fmt.Sprintf(
            "Unknown signer method: %s. Known methods are: 'ddns' and 'desec-api'", s.Method)), ""
    }

    stmt, err := mdb.db.Prepare("UPDATE signers SET method = ?, auth = ?, addr = ? WHERE name = ?")
    if err != nil {
        fmt.Printf("UpdateSigner: Error from db.Prepare: %v\n", err)
    }

    mdb.mu.Lock()
    _, err = stmt.Exec(s.Method, s.Auth, s.Address, s.Name)
    mdb.mu.Unlock()
    if CheckSQLError("UpdateSigner", "", err, false) {
        return err, ""
    }

    fmt.Printf("UpdateSigner: success: %s, %s, %s, %s\n", s.Name, s.Method, s.Auth, s.Address)
    return nil, fmt.Sprintf("Signer %s successfully updated.", s.Name)
}

func (mdb *MusicDB) GetSigner(s string) (Signer, error) {
    sqlcmd := "SELECT name, method, auth, COALESCE (addr, '') AS address, COALESCE (sgroup, '') AS signergroup FROM signers WHERE name=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
    if err != nil {
        fmt.Printf("GetSigner: Error from db.Prepare: %v\n", err)
    }

    row := stmt.QueryRow(s)

    var name, method, auth, address, signergroup string
    switch err = row.Scan(&name, &method, &auth, &address, &signergroup); err {
    case sql.ErrNoRows:
        // fmt.Printf("GetSigner: Signer \"%s\" does not exist\n", s)
        return Signer{}, errors.New(fmt.Sprintf("Signer %s is unknown.", s))

    case nil:
        // fmt.Printf("GetSigner: found signer(%s, %s, %s, %s, %s)\n", name, method, auth, address, signergroup)
        return Signer{
            Name:        name,
            Method:      method,
            Auth:        auth, // AuthDataTmp(auth), // TODO: Issue #28
            Address:     address,
            SignerGroup: signergroup,
            DB:          mdb,
        }, nil

    default:
        log.Fatalf("GetSigner: error from row.Scan(): name=%s, err=%v", s, err)
    }
    return Signer{}, err
}

// SignerJoinGroup(): add an already defined signer to an already defined signer group.
//
// Note: this should trigger all zones attached to this signer group to enter the
// "add-signer" process.
//
func (mdb *MusicDB) SignerJoinGroup(s Signer, g string) (error, string) {
    var sg *SignerGroup
    var err error

    if _, err := mdb.GetSigner(s.Name); err != nil {
        return err, ""
    }

    if sg, err = mdb.GetSignerGroup(g); err != nil {
        return err, ""
    }

    mdb.mu.Lock()
    sqlcmd := "UPDATE signers SET sgroup=? WHERE name=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
    if err != nil {
        fmt.Printf("SignerJoinGroup: Error from db.Prepare: %v\n", err)
    }
    _, err = stmt.Exec(g, s.Name)
    if CheckSQLError("SignerJoinGroup", sqlcmd, err, false) {
        mdb.mu.Unlock()
        return err, ""
    }
    mdb.mu.Unlock()

    fmt.Printf("SignerJoinGroup: signers in group %s: %v\n", sg.Name, sg.SignerMap)
    if sg, err = mdb.GetSignerGroup(g); err != nil {
        return err, ""
    }

    // if we now have more than one signer in the signer group it is possible that they
    // are unsynced. Then we must enter the "add-signer" process to get them in sync.
    if len(sg.SignerMap) > 1 {
        zones, err := mdb.GetSignerGroupZones(sg)
        if err != nil {
            return err, ""
        }

        // XXX: this is inefficient, but I don't think we will have enough
        //      zones in the system for that to be an issue
        for _, z := range zones {
            mdb.ZoneAttachFsm(z, SignerJoinGroupProcess) // we know that z exist
        }
        return nil, fmt.Sprintf(
            "Signer %s has joined signer group %s and %d zones have entered the 'add-signer' process.",
            s.Name, g, len(zones))
    }
    return nil, fmt.Sprintf(
        "Signer %s has joined signer group %s as the first signer. No zones entered the 'add-signer' process.",
        s.Name, g)
}

func (mdb *MusicDB) SignerLeaveGroup(s Signer, g string) (error, string) {
    var sg *SignerGroup
    var err error

    if _, err := mdb.GetSigner(s.Name); err != nil {
        return err, ""
    }

    if sg, err = mdb.GetSignerGroup(g); err != nil {
        return err, ""
    }

    // It is not legal to remove the last signer in a signer group (as that would
    // cause rather obvious problems).
    if len(sg.SignerMap) == SignerGroupMinimumSigners {
        return errors.New(fmt.Sprintf(
            "The signer group %s has only %d signer, %s, which can therefore not be removed.",
            sg.Name, SignerGroupMinimumSigners, s.Name)), ""
    }

    mdb.mu.Lock()
    sqlcmd := "UPDATE signers SET sgroup='' WHERE name=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
    if err != nil {
        fmt.Printf("SignerLeaveGroup: Error from db.Prepare: %v\n", err)
    }

    _, err = stmt.Exec(s.Name)
    if CheckSQLError("SignerLeaveGroup", sqlcmd, err, false) {
        mdb.mu.Unlock()
        return err, ""
    }
    mdb.mu.Unlock()

    zones, err := mdb.GetSignerGroupZones(sg)
    if err != nil {
        return err, ""
    }

    // XXX: this is inefficient, but I don't think we will have enough
    //      zones in the system for that to be an issue
    for _, z := range zones {
        mdb.ZoneAttachFsm(z, SignerLeaveGroupProcess) // we know that z exist
    }
    return nil, fmt.Sprintf(
        "Signer %s has left signer group % and therefore %d zones entered the 'remove-signer' process.",
        s.Name, g, len(zones))
}

// XXX: It should not be possible to delete a signer that is part of a signer group. Full stop.
func (mdb *MusicDB) DeleteSigner(dbsigner Signer) (error, string) {
    sg := dbsigner.SignerGroup
    if sg != "" {
        // err, _ := mdb.SignerLeaveGroup(dbsigner, sg)
        // if err != nil {
        //    return err, ""
        // }
        return errors.New(fmt.Sprintf(
            "Signer %s can not be deleted as it is part of the signer group %s.", dbsigner.Name, sg)), ""
    }

    sqlcmd := "DELETE FROM signers WHERE name=?"
    stmt, err := mdb.db.Prepare(sqlcmd)
    if err != nil {
        fmt.Printf("DeleteSigner: Error from db.Prepare: %v\n", err)
    }
    mdb.mu.Lock()
    _, err = stmt.Exec(dbsigner.Name)
    mdb.mu.Unlock()

    if CheckSQLError("DeleteSigner", sqlcmd, err, false) {
        return err, ""
    }
    return nil, fmt.Sprintf("Signer %s deleted.", dbsigner.Name)
}

func (mdb *MusicDB) ListSigners() (map[string]Signer, error) {
    var sl = make(map[string]Signer, 2)

    sqlcmd := "SELECT name, method, auth, COALESCE (sgroup, '') AS signergroup FROM signers"
    stmt, err := mdb.db.Prepare(sqlcmd)
    if err != nil {
        fmt.Printf("ListSigners: Error from db.Prepare: %v\n", err)
    }

    rows, err := stmt.Query()
    defer rows.Close()

    if CheckSQLError("ListSigners", sqlcmd, err, false) {
        return sl, err
    } else {
        var name, method, auth, signergroup string
        for rows.Next() {
            err := rows.Scan(&name, &method, &auth, &signergroup)
            if err != nil {
                log.Fatal("ListSigners: Error from rows.Next():", err)
            }
            sl[name] = Signer{
                Name:        name,
                Method:      method,
                Auth:        auth, // AuthDataTmp(auth), // TODO: Issue #28
                SignerGroup: signergroup,
            }
        }
    }
    return sl, nil
}

func (mdb *MusicDB) SignerLogin(s *Signer, cliconf *CliConfig, tokvip *viper.Viper) (error, string) {
    var err error
    var dlr DesecLResponse
    var msg string

    switch s.Method {
    case "ddns":
        return errors.New(fmt.Sprintf("Signer %s has method=ddns: No login required.",
            s.Name)), ""

    case "desec-api":
        dlr, err = DesecLogin(cliconf, tokvip)
        if err != nil {
            return errors.New(fmt.Sprintf("SignerLogin: error from DesecLogin: %v",
                err)), ""
        }

        if dlr.Token != "" {
            endtime := dlr.Created.Add(dlr.MaxUnused)
            msg = fmt.Sprintf("New token received and stored. It is valid until %v",
                endtime.Format("2006-01-02 15:04:05"))
        } else {
            msg = "Something happened. No token received. Hmm?"
        }
    default:
        return errors.New(fmt.Sprintf("Signer % has method=%s, which is unknown.",
            s.Name, s.Method)), ""
    }
    return nil, msg
}

func (mdb *MusicDB) SignerLogout(s *Signer, cliconf *CliConfig, tokvip *viper.Viper) (error, string) {
    var err error
    var msg string

    switch s.Method {
    case "ddns":
        return errors.New(fmt.Sprintf("Signer %s has method=ddns: No logout required.",
            s.Name)), ""

    case "desec":
        err = DesecLogout(cliconf, tokvip)
        if err != nil {
            return errors.New(fmt.Sprintf("SignerLogout: error from DesecLogout: %v",
                err)), ""
        }
        msg = "Logout from deSEC complete."
    }
    return nil, msg
}

func (mdb *MusicDB) SaveSigners() error {
    _, _ = mdb.ListSigners()

    return nil
}
