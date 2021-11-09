/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
    "errors"
    "fmt"
    // "time"

    _ "github.com/mattn/go-sqlite3"
)

func (mdb *MusicDB) ZoneAttachFsm(zonename string, dbzone *Zone, exist bool, fsm string) (error, string) {

    if !exist {
        return errors.New(fmt.Sprintf("Zone %s unknown", dbzone.Name)), ""
    }

    sgname := dbzone.SignerGroup().Name

    if sgname == "" || sgname == "---" {
        return errors.New(fmt.Sprintf("Zone %s not assigned to any signer group, so it can not attach to a process\n",
            dbzone.Name)), ""
    }

    var process FSM
    if process, exist = FSMlist[fsm]; !exist {
        return errors.New(fmt.Sprintf("Process %s unknown. Sorry.", fsm)), ""
    }

    if dbzone.FSM != "" && dbzone.FSM != "---" {
        return errors.New(fmt.Sprintf(
            "Zone %s already attached to process %s. Only one process at a time possible.\n",
            dbzone.Name, dbzone.FSM)), ""
    }

    initialstate := process.InitialState

    mdb.mu.Lock()
    sqlq := "UPDATE zones SET fsm=?, state=? WHERE name=?"
    stmt, err := mdb.db.Prepare(sqlq)
    if err != nil {
        fmt.Printf("ZoneAttachFsm: Error from db.Prepare: %v\n", err)
    }

    _, err = stmt.Exec(fsm, initialstate, dbzone.Name)
    if CheckSQLError("JoinGroup", sqlq, err, false) {
        mdb.mu.Unlock()
        return err, ""
    }
    mdb.mu.Unlock()
    return nil, fmt.Sprintf("Zone %s has now started process '%s' in state '%s'.",
        dbzone.Name, fsm, initialstate)
}

func (mdb *MusicDB) ZoneStepFsm(zonename string, dbzone *Zone, exist bool,
    nextstate string) (error, string, map[string]Zone) {
    var emptyzm = map[string]Zone{}

    if !exist {
        return errors.New(fmt.Sprintf("Zone %s unknown", zonename)), "", emptyzm
    }

    fsmname := dbzone.FSM

    if fsmname == "" || fsmname == "---" {
        return errors.New(fmt.Sprintf("Zone %s not attached to any process.", dbzone.Name)),
            "", emptyzm
    }

    CurrentFsm := FSMlist[fsmname]

    var CurrentState FSMState
    if CurrentState, exist = CurrentFsm.States[dbzone.State]; !exist {
        return errors.New(fmt.Sprintf("Zone state '%s' does not exist in process %s. Terminating.",
            dbzone.State, dbzone.FSM)), "", emptyzm
    }

    transitions := CurrentState.Next

    possibles := ""
    // keys := make([]string, len(transitions))
    var keys []string
    for k, _ := range transitions {
        possibles += " " + k
        keys = append(keys, k)
    }

    msgtmpl := "Zone %s transitioned to state '%s' in process '%s'."

    if len(transitions) == 1 && transitions[keys[0]].Criteria(dbzone) {
        transitions[keys[0]].Action(dbzone)
        return nil, fmt.Sprintf(msgtmpl, dbzone.Name, keys[0], fsmname),
            map[string]Zone{dbzone.Name: *dbzone}
    }

    if len(transitions) > 1 {
        if nextstate != "" {
            if _, exist := transitions[nextstate]; exist {
                if transitions[nextstate].Criteria(dbzone) {
                    transitions[nextstate].Action(dbzone)
                    return nil,
                        fmt.Sprintf(msgtmpl, dbzone.Name,
                            nextstate, fsmname),
                        map[string]Zone{dbzone.Name: *dbzone}
                } else {
                    return errors.New(
                        fmt.Sprintf(
                            "State '%s' is a possible next state from '%s' but criteria failed",
                            nextstate, CurrentState.Name)), "", emptyzm
                }
            } else {
                return errors.New(
                    fmt.Sprintf(
                        "State '%s' is not a possible next state from '%s'",
                        nextstate, CurrentState.Name)), "", emptyzm
            }
        } else {
            return errors.New(fmt.Sprintf(
                "Multiple possible next states from '%s': [%s] but next state not specified",
                CurrentState.Name, possibles[1:])), "", emptyzm
        }
    }

    // Arriving here equals len(transitions) == 0, i.e. you are in a state with no "next" state.
    // If that happens the FSM is likely buggy.
    return errors.New(fmt.Sprintf(
        "Zero possible next states from '%s': you lose.", CurrentState.Name)), "", emptyzm
}
