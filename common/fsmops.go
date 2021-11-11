/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
    "errors"
    "fmt"
    "log"
    "strings"

    _ "github.com/mattn/go-sqlite3"
)

func (mdb *MusicDB) ZoneAttachFsm(dbzone *Zone, fsm string) (error, string) {

    if !dbzone.Exists {
        return fmt.Errorf("Zone %s unknown", dbzone.Name), ""
    }

    sgname := dbzone.SignerGroup().Name

    if sgname == "" || sgname == "---" {
        return fmt.Errorf("Zone %s not assigned to any signer group, so it can not attach to a process\n",
            dbzone.Name), ""
    }

    var exist bool
    var process FSM
    if process, exist = FSMlist[fsm]; !exist {
        return fmt.Errorf("Process %s unknown. Sorry.", fsm), ""
    }

    if dbzone.FSM != "" && dbzone.FSM != "---" {
        return fmt.Errorf(
            "Zone %s already attached to process %s. Only one process at a time possible.\n",
            dbzone.Name, dbzone.FSM), ""
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

func (mdb *MusicDB) ZoneStepFsm(dbzone *Zone, nextstate string) (error,
    string, map[string]Zone) {
    var emptyzm = map[string]Zone{}

    if !dbzone.Exists {
        return fmt.Errorf("Zone %s unknown", dbzone.Name), "", emptyzm
    }

    fsmname := dbzone.FSM

    if fsmname == "" || fsmname == "---" {
        return fmt.Errorf("Zone %s not attached to any process.", dbzone.Name),
            "", emptyzm
    }

    CurrentFsm := FSMlist[fsmname]

    state := dbzone.State
    var CurrentState FSMState
    var exist bool
    if CurrentState, exist = CurrentFsm.States[state]; !exist {
        return errors.New(fmt.Sprintf("Zone state '%s' does not exist in process %s. Terminating.",
            state, dbzone.FSM)), "", emptyzm
    }

    var transistions []string
    for k, _ := range CurrentState.Next {
        transistions = append(transistions, k)
    }

    msgtmpl := "Zone %s transitioned to state '%s' in process '%s'."

    if len(CurrentState.Next) == 1 {
        if CurrentState.Next[transistions[0]].Criteria(dbzone) {
            CurrentState.Next[transistions[0]].Action(dbzone)
            return nil, fmt.Sprintf(msgtmpl, dbzone.Name, transistions[0], fsmname),
                map[string]Zone{dbzone.Name: *dbzone}
        } else {
            return errors.New(
                fmt.Sprintf("Criteria for '%s' failed", state)), "", emptyzm
        }
    }

    if len(CurrentState.Next) > 1 {
        if nextstate != "" {
            if _, exist := CurrentState.Next[nextstate]; exist {
                if CurrentState.Next[nextstate].Criteria(dbzone) {
                    CurrentState.Next[nextstate].Action(dbzone)
                    return nil,
                        fmt.Sprintf(msgtmpl, dbzone.Name,
                            nextstate, fsmname),
                        map[string]Zone{dbzone.Name: *dbzone}
                } else {
                    return errors.New(
                        fmt.Sprintf(
                            "State '%s' is a possible next state from '%s' but criteria failed",
                            nextstate, state)), "", emptyzm
                }
            } else {
                return errors.New(
                    fmt.Sprintf(
                        "State '%s' is not a possible next state from '%s'",
                        nextstate, state)), "", emptyzm
            }
        } else {
            return errors.New(fmt.Sprintf(
                "Multiple possible next states from '%s': [%s] but next state not specified",
                state, strings.Join(transistions, " "))), "", emptyzm
        }
    }

    // Arriving here equals len(CurrentState.Next) == 0, i.e. you are in a state with no "next" state.
    // If that happens the FSM is likely buggy.
    return errors.New(fmt.Sprintf(
        "Zero possible next states from '%s': you lose.", state)), "", emptyzm
}

func (mdb *MusicDB) ListProcesses() ([]Process, error, string) {
    var resp []Process
    for name, fsm := range FSMlist {
        resp = append(resp, Process{
            Name: name,
            Desc: fsm.Desc,
        })
    }
    return resp, nil, ""
}

func GetSortedTransitionKeys(fsm string) ([]string, error) {
    var skeys = []string{}
    return skeys, nil
}

func (mdb *MusicDB) GraphProcess(fsm string) (string, error) {
    var exist bool
    var process FSM

    if process, exist = FSMlist[fsm]; !exist {
        return "", fmt.Errorf("Process %s unknown. Sorry.", fsm)
    }

    gtype := "flowchart"

    switch gtype {
    case "flowchart":
        return MermaidFlowChart(&process)
    case "statediagram":
        return MermaidStateDiagram(&process)
    }
    return "", nil
}

func MermaidStateDiagram(process *FSM) (string, error) {
    return "", nil
}

func MermaidFlowChart(process *FSM) (string, error) {
    //   var exist bool
    graph := "mermaid\ngraph TD\n"
    statenum := 0
    var stateToId = map[string]string{}
    //    var process FSM
    //    if process, exist = FSMlist[fsm]; !exist {
    //        return "", fmt.Errorf("Process %s unknown. Sorry.", process.Name)
    //    }

    log.Printf("GraphProcess: graphing process %s\n", process.Name)
    for sn, _ := range process.States {
        stateId := fmt.Sprintf("State%d", statenum)
        graph += fmt.Sprintf("%s(%s)\n", stateId, sn)
        stateToId[sn] = stateId
        statenum++
    }

    log.Printf("GraphProcess: stateToId: %v\n", stateToId)

    statenum = 0
    for sn, st := range process.States {
        var action string
        var criteria string
        for state, nt := range st.Next {
            thisstate := sn
            nextstate := stateToId[state]
            if nt.MermaidCriteriaDesc != "" {
                criteria = "Criteria: " + nt.MermaidCriteriaDesc + "<br/>"
            }
            if nt.MermaidActionDesc != "" {
                action = "Action: " + nt.MermaidActionDesc + "<br/>"
            }
            txt := criteria + action
            if txt != "" && len(txt) > 5 {
                txt = "|" + txt[:len(txt)-5] + "|"
            }
            graph += fmt.Sprintf("%s --> %s %s\n", stateToId[thisstate],
                txt, nextstate)
        }
        statenum++
    }

    log.Printf("GraphProcess: graph: \n%s\n", graph)

    return graph, nil
}
