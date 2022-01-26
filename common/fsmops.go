/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
        // "github.com/DNSSEC-Provisioning/music/common"
)

func (mdb *MusicDB) ZoneAttachFsm(dbzone *Zone, fsm, fsmsigner string) (error, string) {

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
	if process, exist = mdb.FSMlist[fsm]; !exist {
		return fmt.Errorf("Process %s unknown. Sorry.", fsm), ""
	}

	if dbzone.FSM != "" && dbzone.FSM != "---" {
		return fmt.Errorf(
			"Zone %s already attached to process %s. Only one process at a time possible.\n",
			dbzone.Name, dbzone.FSM), ""
	}

	initialstate := process.InitialState

	mdb.mu.Lock()
	sqlq := "UPDATE zones SET fsm=?, fsmsigner=?, state=? WHERE name=?"
	stmt, err := mdb.db.Prepare(sqlq)
	if err != nil {
		fmt.Printf("ZoneAttachFsm: Error from db.Prepare: %v\n", err)
	}

	_, err = stmt.Exec(fsm, fsmsigner, initialstate, dbzone.Name)
	if CheckSQLError("JoinGroup", sqlq, err, false) {
		mdb.mu.Unlock()
		return err, ""
	}
	mdb.mu.Unlock()
	return nil, fmt.Sprintf("Zone %s has now started process '%s' in state '%s'.",
		dbzone.Name, fsm, initialstate)
}

// XXX: Returning a map[string]Zone just to get rid of an extra call
// to ListZones() was a mistake. Let's simplify.

func (mdb *MusicDB) ZoneStepFsm(dbzone *Zone, nextstate string) (bool, error, string) {

	if !dbzone.Exists {
		return false, fmt.Errorf("Zone %s unknown", dbzone.Name), ""
	}

	fsmname := dbzone.FSM

	if fsmname == "" || fsmname == "---" {
		return false, fmt.Errorf("Zone %s not attached to any process.", dbzone.Name),
			""
	}

	CurrentFsm := mdb.FSMlist[fsmname]

	state := dbzone.State
	var CurrentState FSMState
	var exist bool
	if CurrentState, exist = CurrentFsm.States[state]; !exist {
		return false, fmt.Errorf(
			"Zone state '%s' does not exist in process %s. Terminating.",
			state, dbzone.FSM), ""
	}

	var transitions []string
	for k, _ := range CurrentState.Next {
		transitions = append(transitions, k)
	}

	msgtmpl := "Zone %s transitioned to state '%s' in process '%s'."
	// transittmpl := "Zone %s transitioned to state '%s' in process '%s'."
	// notransittmpl := "Zone %s did not transition to state '%s' (post-condition failed)."

	// Only one possible next state: this it the most common case
	if len(CurrentState.Next) == 1 {
		nextname := transitions[0]
		t := CurrentState.Next[nextname]
		success, err, msg := dbzone.AttemptStateTransition(nextname, t)
		// return dbzone.AttemptStateTransition(nextname, t)
		log.Printf("ZoneStepFsm debug: result from AttemptStateTransition: success: %v, err: %v, msg: '%s'\n", success, err, msg)
		return success, err, msg
	}

	// More than one possible next state: this can happen. Right now we can
	// only deal with multiple possible next states when the "right" next state
	// is explicitly specified (via parameter nextstate).
	// In the future it seems like a better approach will be to iterate through
	// all the pre-conditions and execute on the first that returns true.
	// It can be argued that if multiple pre-conditions can be true at the same
	// time then the FSM is buggy (as in not deterministic).
	if len(CurrentState.Next) > 1 {
		if nextstate != "" {
			if _, exist := CurrentState.Next[nextstate]; exist {
				t := CurrentState.Next[nextstate]
				// success, err, msg := dbzone.AttemptStateTransition(nextstate, t)
				return dbzone.AttemptStateTransition(nextstate, t)
			} else {
				return false, fmt.Errorf(
					"State '%s' is not a possible next state from '%s'",
					nextstate, state), ""
			}
		} else {
			return false, fmt.Errorf(
				"Multiple possible next states from '%s': [%s] but next state not specified",
				state, strings.Join(transitions, " ")), ""
		}
	}

	// More than one possible next state: this can happen; old version
	if len(CurrentState.Next) > 1 {
		if nextstate != "" {
			if _, exist := CurrentState.Next[nextstate]; exist {
				if CurrentState.Next[nextstate].Criteria(dbzone) {
					CurrentState.Next[nextstate].Action(dbzone)
					return true, nil,
						fmt.Sprintf(msgtmpl, dbzone.Name,
							nextstate, fsmname)
				} else {
					return false, fmt.Errorf(
						"State '%s' is a possible next state from '%s' but criteria failed",
						nextstate, state), ""
				}
			} else {
				return false, fmt.Errorf(
					"State '%s' is not a possible next state from '%s'",
					nextstate, state), ""
			}
		} else {
			return false, fmt.Errorf(
				"Multiple possible next states from '%s': [%s] but next state not specified",
				state, strings.Join(transitions, " ")), ""
		}
	}

	// Arriving here equals len(CurrentState.Next) == 0, i.e. you are in a
	// state with no "next" state. If that happens the FSM is likely buggy.
	return false, fmt.Errorf(
		"Zero possible next states from '%s': you lose.", state), ""
}

// pre-condition false ==> return false, nil, "msg": no transit, no error
// pre-cond true + no post-cond ==> return false, error, "msg": no transit, error
// pre-cond true + post-cond false ==> return false, nil, "msg"
// pre-cond true + post-cond true ==> return true, nil, "msg": all ok
func (z *Zone) AttemptStateTransition(nextstate string,
	t FSMTransition) (bool, error, string) {
	currentstate := z.State

	log.Printf("AttemptStateTransition: zone '%s' to state '%s'\n", z.Name, nextstate)

	// If pre-condition(aka criteria)==true ==> execute action
	// If post-condition==true ==> change state.
	// If post-condition==false ==> bump hold time
	// XXX: This should be changed to t.PreCondition once all states have pre conditions
	if t.PreCondition(z) {
	        log.Printf("AttemptStateTransition: zone '%s'--> '%s': PreCondition: true\n", z.Name, nextstate)
		t.Action(z)
		if t.PostCondition != nil {
			postcond := t.PostCondition(z)
			if postcond {
				z.StateTransition(currentstate, nextstate) // success
				return true, nil,
					fmt.Sprintf("Zone %s transitioned from '%s' to '%s'",
						z.Name, currentstate, nextstate)
			} else {
				stopreason, exist := z.MusicDB.GetMeta(z, "stop-reason")
				if exist {
					stopreason = fmt.Sprintf(" Current stop reason: %s", stopreason)
				}
				return false, nil,
					fmt.Sprintf("Zone %s did not transition from %s to %s.",
						z.Name, currentstate, nextstate)
			}

		} else {
			// there is no post-condition
			log.Fatalf("AttemptStateTransition: Error: no PostCondition defined for transition %s --> %s", currentstate, nextstate)
			// obviously, because of the log.Fatalf this return won't happen:
			return false, fmt.Errorf("Cannot transition due to lack of definied post-condition for transition %s --> %s", currentstate, nextstate), ""
		}
	}
	// pre-condition returns false
	stopreason, exist := z.MusicDB.GetMeta(z, "stop-reason")
	if exist {
		stopreason = fmt.Sprintf(" Current stop reason: %s", stopreason)
	}
	return false, nil, fmt.Sprintf("%s: PreCondition for '%s' failed.%s",
		z.Name, nextstate, stopreason)
}

func (mdb *MusicDB) ListProcesses() ([]Process, error, string) {
	var resp []Process
	for name, fsm := range mdb.FSMlist {
		resp = append(resp, Process{
			Name: name,
			Desc: fsm.Desc,
		})
	}
	return resp, nil, ""
}

func (z *Zone) GetParentAddressOrStop() (string, error) {
	var parentAddress string
	var exist bool
	if parentAddress, exist = z.MusicDB.GetMeta(z, "parentaddr"); !exist {
		err, _ := z.MusicDB.ZoneSetMeta(z, "stop-reason", fmt.Sprintf("No parent-agent address registered"))
		if err != nil {
			log.Printf("GetParentAddressOrStop: Error from ZoneSetMeta: %v\n", err)
		}
		log.Printf("GetParentAddressOrStop: Zone %s has no parent address registered.",
			z.Name)
		return "", fmt.Errorf("Zone %s has no parent address registered", z.Name)
	}
	return parentAddress, nil
}

func GetSortedTransitionKeys(fsm string) ([]string, error) {
	var skeys = []string{}
	return skeys, nil
}

func (mdb *MusicDB) GraphProcess(fsm string) (string, error) {
	var exist bool
	var process FSM

	if process, exist = mdb.FSMlist[fsm]; !exist {
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
	//    if process, exist = mdb.FSMlist[fsm]; !exist {
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
