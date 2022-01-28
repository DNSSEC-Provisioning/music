/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	// "database/sql"
	"fmt"
	"log"

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

func (mdb *MusicDB) AddSigner(dbsigner *Signer, group string) (error, string) {
	var err error
	if dbsigner.Exists {
		return fmt.Errorf("Signer %s already present in system.",
			dbsigner.Name), ""
	}

	fmt.Printf("AddSigner: err: %v\n", err)

	// dbsigner.Method = strings.ToLower(dbsigner.Method)
	updatermap := ListUpdaters()
	_, ok := updatermap[dbsigner.Method]

	if !ok {
		return fmt.Errorf(
			"Unknown signer method: %s. Known methods are: %v", dbsigner.Method, updatermap), ""
	}


	addstmt, err := mdb.Prepare("INSERT INTO signers(name, method, auth, addr, port) VALUES (?, ?, ?, ?, ?)")

	if err != nil {
		fmt.Printf("AddSigner: Error from db.Prepare: %v\n", err)
	}

	mdb.mu.Lock()
	_, err = addstmt.Exec(dbsigner.Name, dbsigner.Method,
		dbsigner.Auth, dbsigner.Address, dbsigner.Port)
	mdb.mu.Unlock()

	if err != nil {
		fmt.Printf("AddSigner: failure: %s, %s, %s, %s, %s\n",
			dbsigner.Name, dbsigner.Method, dbsigner.Auth,
			dbsigner.Address, dbsigner.Port)
		return err, ""
	}

	if group != "" {
		log.Printf("AddSigner: signer %s has the signergroup %s specified so we set that too\n", dbsigner.Name, group)
		dbsigner, _ := mdb.GetSigner(dbsigner, false) // no need for apisafe
		mdb.SignerJoinGroup(dbsigner, group)          // we know that the signer exist
		return nil, fmt.Sprintf(
			"Signer %s was added and immediately attached to signer group %s.", dbsigner.Name, group)
	}

	log.Printf("AddSigner: success: %s, %s, %s, %s, %s\n", dbsigner.Name,
		dbsigner.Method, dbsigner.Auth, dbsigner.Address, dbsigner.Port)
	return nil, fmt.Sprintf("New signer %s successfully added.", dbsigner.Name)
}

const (
      USsql = "UPDATE signers SET method=?, auth=?, addr=?, port=? WHERE name =?"
)

func (mdb *MusicDB) UpdateSigner(dbsigner *Signer, us Signer) (error, string) {
	var err error
	if !dbsigner.Exists {
		return fmt.Errorf("Signer %s not present in system.",
			dbsigner.Name), ""
	}

	updatermap := ListUpdaters()
	_, ok := updatermap[dbsigner.Method]
	if !ok {
		return fmt.Errorf(
			"Unknown signer method: %s. Known methods are: %v",
				 		dbsigner.Method, updatermap), ""
	}

	stmt, err := mdb.Prepare(USsql)
	if err != nil {
		log.Printf("UpdateSigner: Error from db.Prepare(%s): %v\n", USsql, err)
	}

	if us.Method != "" {
	   dbsigner.Method = us.Method
	}

	if us.Auth != "" {
	   dbsigner.Auth = us.Auth
	}

	if us.Address != "" {
	   dbsigner.Address = us.Address
	}

	if us.Port != "" {
	   dbsigner.Port = us.Port
	}

	mdb.mu.Lock()
	_, err = stmt.Exec(dbsigner.Method, dbsigner.Auth, dbsigner.Address,
	       	 			    dbsigner.Port, dbsigner.Name)
	mdb.mu.Unlock()
	if CheckSQLError("UpdateSigner", USsql, err, false) {
		return err, ""
	}

	fmt.Printf("UpdateSigner: success: %s, %s, %s, %s, %s\n", dbsigner.Name,
		dbsigner.Method, dbsigner.Auth,
		dbsigner.Address, dbsigner.Port)
	return nil, fmt.Sprintf("Signer %s successfully updated.", dbsigner.Name)
}

const (
	SJGsql2 = "INSERT OR IGNORE INTO group_signers (name, signer) VALUES (?, ?)"
)

// SignerJoinGroup(): add an already defined signer to an already defined signer group.
//
// Note: this should trigger all zones attached to this signer group to enter
// the "add-signer" process and the signer will be put in the PendingAddition slot until the zones
// are done with that process.

// XXX: I think we have this one more or less correct now.

func (mdb *MusicDB) SignerJoinGroup(dbsigner *Signer, g string) (error, string) {
	var sg *SignerGroup
	var err error

	if !dbsigner.Exists {
		return fmt.Errorf("Signer %s is unknown.", dbsigner.Name), ""
	}

	if sg, err = mdb.GetSignerGroup(g, false); err != nil { // not apisafe
		return err, ""
	}

	if _, already_member := sg.SignerMap[dbsigner.Name]; already_member {
		return fmt.Errorf("Signer %s is already a member of group %s", dbsigner.Name, sg.Name), ""
	}

	if sg.PendingAddition != "" {
		return fmt.Errorf("Signer group %s has signer %s in the PendingAddition slot already",
			sg.Name, sg.PendingAddition), ""
	}

	if sg.PendingRemoval != "" {
		return fmt.Errorf("Signer group %s has signer %s in the PendingRemoval slot, and only one process at a time is possible",
			sg.Name, sg.PendingRemoval), ""
	}

	if sg.CurrentProcess != "" {
		return fmt.Errorf("Signer group %s is currently in the '%s' process and does not accept signer addition.",
			sg.Name, sg.CurrentProcess), ""
	}

	if sg.NumProcessZones != 0 {
		return fmt.Errorf("Signer group %s has %d zones executing processes and does not accept signer addition.",
			sg.Name, sg.NumProcessZones), ""
	}

	mdb.mu.Lock()
	stmt, err := mdb.Prepare(SJGsql2)
	if err != nil {
		log.Printf("SignerJoinGroup: Error from mdb.Prepare(%s): %v\n", SJGsql2, err)
	}
	_, err = stmt.Exec(g, dbsigner.Name)
	if CheckSQLError("SignerJoinGroup", SJGsql2, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()

	fmt.Printf("SignerJoinGroup: signers in group %s: %v\n", sg.Name, sg.SignerMap)
	if sg, err = mdb.GetSignerGroup(g, false); err != nil { // not apisafe
		return err, ""
	}

	// if we now have more than one signer in the signer group it is possible that they
	// are unsynced. Then we must enter the "add-signer" process to get them in sync.
	if len(sg.SignerMap) > 1 {

		zones, err := mdb.GetSignerGroupZones(sg)
		if err != nil {
			return err, ""
		}

		if len(zones) == 0 {
			return nil, fmt.Sprintf(
				"Signer %s has joined signer group %s, which now has %d signers but no zones.",
				dbsigner.Name, sg.Name, len(sg.SignerMap))
		}

		// At this stage we know that there are now more than one signer and more than zero
		// zones. Hence we need to enter the add-signer process for all the zones.
		const sqlq = "UPDATE signergroups SET curprocess=?, pendadd=?, locked=1 WHERE name=?"

		mdb.mu.Lock()
		stmt, err := mdb.Prepare(sqlq)
		if err != nil {
			log.Printf("Error from db.Prepare '%s': %v\n", sqlq, err)
		}
		_, err = stmt.Exec(SignerJoinGroupProcess, dbsigner.Name, sg.Name)
		if CheckSQLError("SignerJoinGroup", sqlq, err, false) {
			mdb.mu.Unlock()
			return err, ""
		}
		mdb.mu.Unlock()

		// sg.CurrentProcess = SignerJoinGroupProcess
		// sg.PendingAddition = dbsigner.Name
		// XXX: this is inefficient, but I don't think we will have enough
		//      zones in the system for that to be an issue
		for _, z := range zones {
		        log.Printf("SignerJoinGroup: calling ZoneAttachFsm(%s, %s, %s)",
						     z.Name, SignerJoinGroupProcess, dbsigner.Name)
			err, msg := mdb.ZoneAttachFsm(z, SignerJoinGroupProcess, dbsigner.Name) // we know that z exist
			if err != nil {
			   log.Printf("SJG: Error from ZAF: %v", err)
			} else {
			   log.Printf("SJG: Message from ZAF: %s", msg)
			}
		}
		return nil, fmt.Sprintf(
			"Signer %s has joined signer group %s and %d zones have entered the 'add-signer' process.",
			dbsigner.Name, g, len(zones))
	}
	return nil, fmt.Sprintf(
		"Signer %s has joined signer group %s as the first signer. No zones entered the 'add-signer' process.",
		dbsigner.Name, g)
}

// Semantics:
// 1. Check whether there is any other signer already in the signergroup.PendingRemoval state
//    (if so, return error)
// 2. If not, put this signer in sg.PendingRemoval. Keep the signer among the group signers.
// 3. If there are zones connected to this group, put them in the "remove-signer" process
// 4. If there are no zones

// XXX: Note that this function doesn't remove signers from signergroups, it only initiates a process for
//      updating zones so that a future removal may be done safely.

func (mdb *MusicDB) SignerLeaveGroup(dbsigner *Signer, g string) (error, string) {
	var sg *SignerGroup
	var err error

	if !dbsigner.Exists {
		return fmt.Errorf("Signer %s is unknown.", dbsigner.Name), ""
	}

	if sg, err = mdb.GetSignerGroup(g, false); err != nil { // not apisafe
		return err, ""
	}

	if _, member := sg.SignerMap[dbsigner.Name]; !member {
		return fmt.Errorf("Signer %s is not a member of group %s", dbsigner.Name, sg.Name), ""
	}

	if sg.PendingRemoval != "" {
		return fmt.Errorf("Signer group %s has signer %s in the PendingRemoval slot already",
			sg.Name, sg.PendingRemoval), ""
	}

	if sg.PendingAddition != "" {
		return fmt.Errorf("Signer group %s has signer %s in the PendingAddition slot, and only one process at a time is possible",
			sg.Name, sg.PendingAddition), ""
	}

	if sg.CurrentProcess != "" {
		return fmt.Errorf("Signer group %s is currently in the '%s' process and does not accept signer removal.",
			sg.Name, sg.CurrentProcess), ""
	}

	zones, err := mdb.GetSignerGroupZones(sg)
	if err != nil {
		return err, ""
	}

	const (
		SLGsql2 = "DELETE FROM group_signers WHERE name=? AND signer=?"
		SLGsql3 = "UPDATE signergroups SET curprocess=?, pendremove=?, locked=1 WHERE name=?"
	)

	// If the signer group has no zones attached to it, then it is ok to remove a signer immediately
	if len(zones) == 0 {
		mdb.mu.Lock()
		stmt, err := mdb.Prepare(SLGsql2)
		if err != nil {
			fmt.Printf("SignerLeaveGroup: Error from db.Prepare '%s': %v\n", SLGsql2, err)
		}

		_, err = stmt.Exec(sg.Name, dbsigner.Name)
		if CheckSQLError("SignerLeaveGroup", SLGsql2, err, false) {
			mdb.mu.Unlock()
			return err, ""
		}
		mdb.mu.Unlock()
		return nil, fmt.Sprintf(
			"Signer %s was removed from signer group %s immediately (because the signer group has no zones).",
			dbsigner.Name, g)
	}

	// It is not legal to remove the last signer in a signer group with zones
	// (as that would cause rather obvious problems).
	if len(sg.SignerMap) == SignerGroupMinimumSigners {
		return fmt.Errorf(
			"The signer group %s has %d zones but only %d signer, %s, which can therefore not be removed.",
			sg.Name, len(zones), SignerGroupMinimumSigners, dbsigner.Name), ""
	}

	mdb.mu.Lock()
	stmt, err := mdb.Prepare(SLGsql3)
	if err != nil {
		fmt.Printf("SignerLeaveGroup: Error from db.Prepare '%s': %v\n", SLGsql3, err)
	}

	_, err = stmt.Exec(SignerLeaveGroupProcess, dbsigner.Name, sg.Name)
	if CheckSQLError("SignerLeaveGroup", SLGsql3, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()

	// XXX: this is inefficient, but I don't think we will have enough
	//      zones in the system for that to be an issue
	for _, z := range zones {
		mdb.ZoneAttachFsm(z, SignerLeaveGroupProcess, dbsigner.Name) // we know that z exist
	}
	return nil, fmt.Sprintf(
		"Signer %s is in pending removal from signer group %s and therefore %d zones entered the '%s' process.",
		dbsigner.Name, g, len(zones), SignerLeaveGroupProcess)
}

const (
	DSsql  = "DELETE FROM signers WHERE name=?"
	DSsql2 = "DELETE FROM group_signers WHERE signer=?"
)

// XXX: It should not be possible to delete a signer that is part of a signer group.
//      Full stop.
func (mdb *MusicDB) DeleteSigner(dbsigner *Signer) (error, string) {
	sgs := dbsigner.SignerGroups
	if len(sgs) != 0 {
		// err, _ := mdb.SignerLeaveGroup(dbsigner, sg)
		// if err != nil {
		//    return err, ""
		// }
		return fmt.Errorf(
			"Signer %s can not be deleted as it is part of the signer groups %v.",
			dbsigner.Name, sgs), ""
	}

	stmt, err := mdb.Prepare(DSsql)
	if err != nil {
		fmt.Printf("DeleteSigner: Error from db.Prepare '%s': %v\n", DSsql, err)
	}
	mdb.mu.Lock()
	_, err = stmt.Exec(dbsigner.Name)
	mdb.mu.Unlock()

	if CheckSQLError("DeleteSigner", DSsql, err, false) {
		return err, ""
	}

	// This should be a no-op, as the signer must not be a member of any group.
	// But we keep it as a GC mechanism in case something has gone wrong.
	stmt, err = mdb.Prepare(DSsql2)
	if err != nil {
		fmt.Printf("DeleteSigner: Error from db.Prepare '%s': %v\n", DSsql2, err)
	}
	mdb.mu.Lock()
	_, err = stmt.Exec(dbsigner.Name)
	mdb.mu.Unlock()

	if CheckSQLError("DeleteSigner", DSsql2, err, false) {
		return err, ""
	}
	return nil, fmt.Sprintf("Signer %s deleted.", dbsigner.Name)
}

const (
	LSIGsql = `
SELECT name, method, addr, auth, port
FROM signers`
)

func (mdb *MusicDB) ListSigners() (map[string]Signer, error) {
	var sl = make(map[string]Signer, 2)

	stmt, err := mdb.Prepare(LSIGsql)
	if err != nil {
		fmt.Printf("ListSigners: Error from db.Prepare: %v\n", err)
	}

	rows, err := stmt.Query()
	defer rows.Close()

	if CheckSQLError("ListSigners", LSIGsql, err, false) {
		return sl, err
	} else {
		var name, method, address, auth, port string
		for rows.Next() {
			err := rows.Scan(&name, &method, &address, &auth, &port)
			if err != nil {
				log.Fatal("ListSigners: Error from rows.Next():", err)
			}

			s := Signer{
				Name:    name,
				Exists:  true,
				Method:  method,
				Address: address,
				Auth:    auth, // AuthDataTmp(auth), // TODO: Issue #28
				Port:    port,
			}
			sgs, err := mdb.GetSignerGroups(name)
			if err != nil {
				log.Fatalf("mdb.ListSigners: Error from mdb.GetSignerGroups: %v",
					err)
			}
			s.SignerGroups = sgs
			sl[name] = s
		}
	}
	return sl, nil
}

// XXX: not used anymore, should die
func (mdb *MusicDB) SignerLogin(dbsigner *Signer, cliconf *CliConfig,
	tokvip *viper.Viper) (error, string) {
	var err error
	var dlr DesecLResponse
	var msg string

	switch dbsigner.Method {
	case "ddns":
		return fmt.Errorf("Signer %s has method=ddns: No login required.",
			dbsigner.Name), ""

	case "desec-api":
		api := GetUpdater("desec-api").GetApi()
		dlr, err = api.DesecLogin()
		if err != nil {
			return fmt.Errorf("SignerLogin: error from DesecLogin: %v",
				err), ""
		}

		if dlr.Token != "" {
			endtime := dlr.Created.Add(dlr.MaxUnused)
			msg = fmt.Sprintf("New token received and stored. It is valid until %v",
				endtime.Format("2006-01-02 15:04:05"))
		} else {
			msg = "Something happened. No token received. Hmm?"
		}
	default:
		return fmt.Errorf("Signer % has method=%s, which is unknown.",
			dbsigner.Name, dbsigner.Method), ""
	}
	return nil, msg
}

func (mdb *MusicDB) SignerLogout(dbsigner *Signer, cliconf *CliConfig,
	tokvip *viper.Viper) (error, string) {
	var err error
	var msg string

	switch dbsigner.Method {
	case "ddns":
		return fmt.Errorf("Signer %s has method=ddns: No logout required.",
			dbsigner.Name), ""

	case "desec":
		err = DesecLogout(cliconf, tokvip)
		if err != nil {
			return fmt.Errorf("SignerLogout: error from DesecLogout: %v",
				err), ""
		}
		msg = "Logout from deSEC complete."
	}
	return nil, msg
}

func (mdb *MusicDB) SaveSigners() error {
	_, _ = mdb.ListSigners()

	return nil
}
