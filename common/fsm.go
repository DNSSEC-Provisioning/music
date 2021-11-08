/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package music

import (
	"fmt"
	"time"
)

type FSMState struct {
	Name string
	Next map[string]FSMTransition
}

type FSMTransition struct {
	Description string
	Dest        string
	Criteria    func(z *Zone) bool
	Action      func(z *Zone) bool
}

type FSM struct {
	Type         string // "single-run" | "permanent"
	InitialState string // zones that enter this process start here
	States       map[string]FSMState
}

func FsmCriteriaFactory(from, to string) func(z *Zone) bool {
	return func(z *Zone) bool {
		PrintTransition(z, "CRITERIA", from, to)
		return true
	}
}

func FsmActionFactory(from, to string) func(z *Zone) bool {
	return func(z *Zone) bool {
		PrintTransition(z, "ACTION", from, to)
		z.StateTransition(from, to)
		return true
	}
}

func FsmTransitionFactory(from, to string) FSMTransition {
	return FSMTransition{
		Dest:     to,
		Criteria: FsmCriteriaFactory(from, to),
		Action:   FsmActionFactory(from, to),
	}
}

func PrintTransition(z *Zone, ttype, from, dest string) {
	fmt.Printf("*** Executing transition %s for %s-->%s for zone %s\n",
		ttype, from, dest, z.Name)
}

func PrintStateDuration(z *Zone, state string) {
	dur := time.Now().Sub(z.Statestamp)
	fmt.Printf("*** Zone %s has been in state '%s' since %s (%v)\n",
		z.Name, state, z.Statestamp.Format(layout), dur)
}

// PROCESS: ADD-SIGNER
var FSMT_AS_1 = FsmTransitionFactory("signers-unsynched", "cds-known")
var FSMT_AS_2 = FsmTransitionFactory("cds-known", "cds-synched")
var FSMT_AS_3 = FsmTransitionFactory("cds-synched", "zsk-synched")
var FSMT_AS_4 = FsmTransitionFactory("zsk-synched", "ds-synched")
var FSMT_AS_5 = FsmTransitionFactory("ds-synched", "cds-removed")
var FSMT_AS_6 = FsmTransitionFactory("cds-removed", "ns-known")
var FSMT_AS_7 = FsmTransitionFactory("ns-known", "ns-synched")
var FSMT_AS_8 = FsmTransitionFactory("ns-synched", "csync-published")
var FSMT_AS_9 = FsmTransitionFactory("csync-published", "parent-synched")
var FSMT_AS_10 = FsmTransitionFactory("parent-synched", "signers-synched")
var FSMT_AS_11 = FsmTransitionFactory("signers-synched", "stop")
var FSMT_AS_12 = FSMTransition{
	Description: "FSMT_AS_12",
	Dest:        "stop",
	Criteria:    FsmCriteriaFactory("stop", "stop"),
	Action: func(z *Zone) bool {
		fmt.Printf("Enter ACTION for <stop, stop>. zone state: %s\n", z.State)
		z.StateTransition("stop", "stop")
		fmt.Printf("FsmAction (stop): Exiting seems to have gone well. Yay!\n")
		return true
	},
}

// PROCESS: REMOVE-SIGNER
var FSMT_RS_1 = FsmTransitionFactory("signers-unsynched", "ns-known")
var FSMT_RS_2 = FsmTransitionFactory("ns-known", "ns-synched")
var FSMT_RS_3 = FsmTransitionFactory("ns-synched", "csync-published")
var FSMT_RS_3b = FsmTransitionFactory("ns-synched", "delegation-ns-synched")
var FSMT_RS_4 = FsmTransitionFactory("csync-published", "delegation-ns-synched")
var FSMT_RS_5 = FsmTransitionFactory("delegation-ns-synched", "delegation-ns-synched-2")
var FSMT_RS_6 = FsmTransitionFactory("delegation-ns-synched-2", "delegation-ns-synched-3")
var FSMT_RS_7 = FsmTransitionFactory("delegation-ns-synched-3", "cds-known")
var FSMT_RS_8 = FsmTransitionFactory("cds-known", "cds-synched")
var FSMT_RS_9 = FsmTransitionFactory("cds-synched", "zsk-synched")
var FSMT_RS_10 = FsmTransitionFactory("zsk-synched", "ds-synched")
var FSMT_RS_11 = FsmTransitionFactory("ds-synched", "signers-synched")
var FSMT_RS_12 = FsmTransitionFactory("signers-synched", "stop") // terminator signal
var FSMT_RS_13 = FSMTransition{
	Description: "FSMT_RS_13",
	Dest:        "stop",
	Criteria:    FsmCriteriaFactory("stop", "stop"),
	Action: func(z *Zone) bool {
		fmt.Printf("Enter ACTION for <stop, stop>. zone state: %s\n", z.State)
		z.StateTransition("stop", "stop")
		fmt.Printf("FsmAction (stop): Exiting the remove-signer process seems to have gone well. Yay!\n")
		return true
	},
}

// PROCESS: ADD-ZONE (bogus process, only for testing)
var FSMT_AZ_1 = FsmTransitionFactory("ready", "join-sync-cds")
var FSMT_AZ_2 = FsmTransitionFactory("join-sync-cds", "join-cds-synched")
var FSMT_AZ_3 = FsmTransitionFactory("join-cds-synched", "ready")
var FSMT_AZ_3b = FsmTransitionFactory("join-cds-synched", "foobar")
var FSMT_AZ_4 = FsmTransitionFactory("foobar", "ready")

// PROCESS: ZSK-ROLLOVER
var FSMT_ZR_1 = FsmTransitionFactory("signers-unsynched", "zsks-known")
var FSMT_ZR_2 = FsmTransitionFactory("zsks-known", "zsks-synched")
var FSMT_ZR_3 = FsmTransitionFactory("zsks-synched", "signers-synched")
var FSMT_ZR_4 = FsmTransitionFactory("signers-synched", "stop")
var FSMT_ZR_5 = FsmTransitionFactory("stop", "stop")

var FSMlist = map[string]FSM{
	// PROCESS: ADD-ZONE: This is a bogus process, only for testing.
	"add-zone": FSM{
		Type:         "single-run",
		InitialState: "ready",
		States: map[string]FSMState{
			"ready": FSMState{
				Name: "ready",
				Next: map[string]FSMTransition{"join-sync-cds": FSMT_AZ_1},
			},
			"join-sync-cds": FSMState{
				Name: "join-sync-cds",
				Next: map[string]FSMTransition{"join-cds-synched": FSMT_AZ_2},
			},
			"join-cds-synched": FSMState{
				Name: "join-cds-synched",
				Next: map[string]FSMTransition{
					"ready":  FSMT_AZ_3,
					"foobar": FSMT_AZ_3b,
				},
			},
			"foobar": FSMState{
				Name: "foobar",
				Next: map[string]FSMTransition{"ready": FSMT_AZ_4},
			},
		},
	},

	// PROCESS: ADD-SIGNER: This is a real process, from the draft doc.
	"add-signer": FSM{
		Type:         "single-run",
		InitialState: "signers-unsynched",
		States: map[string]FSMState{
			"signers-unsynched": FSMState{
				Name: "signers-unsynched",
				Next: map[string]FSMTransition{"cds-known": FSMT_AS_1},
			},
			"cds-known": FSMState{
				Name: "cds-known",
				Next: map[string]FSMTransition{"cds-synched": FSMT_AS_2},
			},
			"cds-synched": FSMState{
				Name: "cds-synched",
				Next: map[string]FSMTransition{"zsk-synched": FSMT_AS_3},
			},
			"zsk-synched": FSMState{
				Name: "zsk-synched",
				Next: map[string]FSMTransition{"ds-synched": FSMT_AS_4},
			},
			"ds-synched": FSMState{
				Name: "ds-synched",
				Next: map[string]FSMTransition{"cds-removed": FSMT_AS_5},
			},
			"cds-removed": FSMState{
				Name: "cds-removed",
				Next: map[string]FSMTransition{"ns-known": FSMT_AS_6},
			},
			"ns-known": FSMState{
				Name: "ns-known",
				Next: map[string]FSMTransition{"ns-synched": FSMT_AS_7},
			},
			"ns-synched": FSMState{
				Name: "ns-synched",
				Next: map[string]FSMTransition{"csync-published": FSMT_AS_8},
			},
			"csync-published": FSMState{
				Name: "csync-published",
				Next: map[string]FSMTransition{"parent-synched": FSMT_AS_9},
			},
			"parent-synched": FSMState{
				Name: "parent-synched",
				Next: map[string]FSMTransition{"signers-synched": FSMT_AS_10},
			},
			"signers-synched": FSMState{
				Name: "signers-synched",
				Next: map[string]FSMTransition{"stop": FSMT_AS_11},
			},
			"stop": FSMState{
				Name: "stop",
				Next: map[string]FSMTransition{"stop": FSMT_AS_12},
			},
		},
	},

	// PROCESS: REMOVE-SIGNER: This is a real process, from the draft doc.
	"remove-signer": FSM{
		Type:         "single-run",
		InitialState: "signers-unsynched",
		States: map[string]FSMState{
			"signers-unsynched": FSMState{
				Name: "signers-unsynched",
				Next: map[string]FSMTransition{"ns-known": FSMT_RS_1},
			},
			"ns-known": FSMState{
				Name: "ns-known",
				Next: map[string]FSMTransition{"ns-synched": FSMT_RS_2},
			},
			"ns-synched": FSMState{
				Name: "ns-synched",
				Next: map[string]FSMTransition{
					"csync-published":       FSMT_RS_3,
					"delegation-ns-synched": FSMT_RS_3b,
				},
			},
			"csync-published": FSMState{
				Name: "csync-published",
				Next: map[string]FSMTransition{
					"delegation-ns-synched": FSMT_RS_4,
				},
			},
			"delegation-ns-synched": FSMState{
				Name: "delegation-ns-synched",
				Next: map[string]FSMTransition{"delegation-ns-synched-2": FSMT_RS_5},
			},
			"delegation-ns-synched-2": FSMState{
				Name: "delegation-ns-synched-2",
				Next: map[string]FSMTransition{"delegation-ns-synched-3": FSMT_RS_6},
			},
			"delegation-ns-synched-3": FSMState{
				Name: "delegation-ns-synched-3",
				Next: map[string]FSMTransition{"cds-known": FSMT_RS_7},
			},
			"cds-known": FSMState{
				Name: "cds-known",
				Next: map[string]FSMTransition{"cds-synched": FSMT_RS_8},
			},
			"cds-synched": FSMState{
				Name: "cds-synched",
				Next: map[string]FSMTransition{"zsk-synched": FSMT_RS_9},
			},
			"zsk-synched": FSMState{
				Name: "zsk-synched",
				Next: map[string]FSMTransition{"ds-synched": FSMT_RS_10},
			},
			"ds-synched": FSMState{
				Name: "ds-synched",
				Next: map[string]FSMTransition{"signers-synched": FSMT_RS_11},
			},
			"signers-synched": FSMState{
				Name: "signers-synched",
				Next: map[string]FSMTransition{"stop": FSMT_RS_12},
			},
			"stop": FSMState{
				Name: "stop",
				Next: map[string]FSMTransition{"stop": FSMT_RS_13},
			},
		},
	},

	// PROCESS: ZSK-ROLLOVER: This is a real process
	"zsk-rollover": FSM{
		Type:         "single-run",
		InitialState: "signers-unsynched",
		States: map[string]FSMState{
			"signers-unsynched": FSMState{
				Name: "signers-unsynched",
				Next: map[string]FSMTransition{"zsk-known": FSMT_ZR_1},
			},
			"zsk-known": FSMState{
				Name: "dnskeys-known",
				Next: map[string]FSMTransition{"zsk-synched": FSMT_ZR_2},
			},
			"zsk-synched": FSMState{
				Name: "zsk-synched",
				Next: map[string]FSMTransition{
					"signers-synched":       FSMT_ZR_3,
				},
			},
			"signers-synched": FSMState{
				Name: "signers-synched",
				Next: map[string]FSMTransition{	"stop": FSMT_ZR_4 },
			},
			"stop": FSMState{
				Name: "stop",
				Next: map[string]FSMTransition{	"stop": FSMT_ZR_5 },
			},
		},
	},

	"ksk-rollover": FSM{
		Type:         "permanent",
		InitialState: "serene-happiness",
		States:       map[string]FSMState{},
	},
}

func (z *Zone) FSMMoveReadyToJSC() bool {
	if z.Name != "" {
		fmt.Printf("Zone %s may move from READY to JOIN-SYNC-CDS\n",
			z.Name)
		return true
	}
	fmt.Printf("Zone %s can not move from READY to JOIN-SYNC-CDS\n",
		z.Name)
	return false
}
