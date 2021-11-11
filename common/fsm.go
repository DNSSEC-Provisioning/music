/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package music

import (
    "fmt"
    "time"
)

const (
    FsmStateSignerUnsynced   = "signers-unsynced"
    FsmStateDnskeysSynced    = "dnskeys-synced"
    FsmStateCdscdnskeysAdded = "cdscdnskeys-added"
    FsmStateParentDsSynced   = "parent-ds-synced"
    FsmStateDsPropagated     = "ds-propagated"
    FsmStateCsyncAdded       = "csync-added"
    FsmStateParentNsSynced   = "parent-ns-synced"
    FsmStateStop             = "stop"
)

type FSMState struct {
    Next map[string]FSMTransition
}

type FSMTransition struct {
    Description string
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

// Generic stop transistion
func FsmTransitionStopFactory(from string) FSMTransition {
    return FSMTransition{
        Description: "Generic stop transition without criteria",
        Criteria:    func(z *Zone) bool { return true },
        Action: func(z *Zone) bool {
            z.StateTransition(from, FsmStateStop)
            return true
        },
    }
}

var FsmGenericStop = FsmTransitionStopFactory(FsmStateStop)

// PROCESS: ADD-SIGNER
// defined in fsm_join*.go

// PROCESS: REMOVE-SIGNER
var FSMT_RS_1 = FsmTransitionFactory(FsmStateSignerUnsynced, "ns-known")
var FSMT_RS_2 = FsmTransitionFactory("ns-known", "ns-synced")
var FSMT_RS_3 = FsmTransitionFactory("ns-synced", "csync-published")
var FSMT_RS_3b = FsmTransitionFactory("ns-synced", "delegation-ns-synced")
var FSMT_RS_4 = FsmTransitionFactory("csync-published", "delegation-ns-synced")
var FSMT_RS_5 = FsmTransitionFactory("delegation-ns-synced", "delegation-ns-synced-2")
var FSMT_RS_6 = FsmTransitionFactory("delegation-ns-synced-2", "delegation-ns-synced-3")
var FSMT_RS_7 = FsmTransitionFactory("delegation-ns-synced-3", "cds-known")
var FSMT_RS_8 = FsmTransitionFactory("cds-known", "cds-synced")
var FSMT_RS_9 = FsmTransitionFactory("cds-synced", "zsk-synced")
var FSMT_RS_10 = FsmTransitionFactory("zsk-synced", "ds-synced")
var FSMT_RS_11 = FsmTransitionFactory("ds-synced", "signers-synced")
var FSMT_RS_12 = FsmTransitionFactory("signers-synced", FsmStateStop) // terminator signal
var FSMT_RS_13 = FSMTransition{
    Description: "FSMT_RS_13",
    Criteria:    FsmCriteriaFactory(FsmStateStop, FsmStateStop),
    Action: func(z *Zone) bool {
        fmt.Printf("Enter ACTION for <stop, stop>. zone state: %s\n", z.State)
        z.StateTransition(FsmStateStop, FsmStateStop)
        fmt.Printf("FsmAction (stop): Exiting the remove-signer process seems to have gone well. Yay!\n")
        return true
    },
}

// PROCESS: ADD-ZONE (bogus process, only for testing)
var FSMT_AZ_1 = FsmTransitionFactory("ready", "join-sync-cds")
var FSMT_AZ_2 = FsmTransitionFactory("join-sync-cds", "join-cds-synced")
var FSMT_AZ_3 = FsmTransitionFactory("join-cds-synced", "ready")
var FSMT_AZ_3b = FsmTransitionFactory("join-cds-synced", "foobar")
var FSMT_AZ_4 = FsmTransitionFactory("foobar", "ready")

// PROCESS: ZSK-ROLLOVER
var FSMT_ZR_1 = FsmTransitionFactory(FsmStateSignerUnsynced, "zsks-known")
var FSMT_ZR_2 = FsmTransitionFactory("zsks-known", "zsks-synced")
var FSMT_ZR_3 = FsmTransitionFactory("zsks-synced", "signers-synced")
var FSMT_ZR_4 = FsmTransitionFactory("signers-synced", FsmStateStop)
var FSMT_ZR_5 = FsmTransitionFactory(FsmStateStop, FsmStateStop)

var FSMlist = map[string]FSM{
    // PROCESS: ADD-ZONE: This is a bogus process, only for testing.
    "add-zone": FSM{
        Type:         "single-run",
        InitialState: "ready",
        States: map[string]FSMState{
            "ready": FSMState{
                Next: map[string]FSMTransition{"join-sync-cds": FSMT_AZ_1},
            },
            "join-sync-cds": FSMState{
                Next: map[string]FSMTransition{"join-cds-synced": FSMT_AZ_2},
            },
            "join-cds-synced": FSMState{
                Next: map[string]FSMTransition{
                    "ready":  FSMT_AZ_3,
                    "foobar": FSMT_AZ_3b,
                },
            },
            "foobar": FSMState{
                Next: map[string]FSMTransition{"ready": FSMT_AZ_4},
            },
        },
    },

    // PROCESS: ADD-SIGNER: This is a real process, from the draft doc.
    "add-signer": FSM{
        Type:         "single-run",
        InitialState: FsmStateSignerUnsynced,
        States: map[string]FSMState{
            FsmStateSignerUnsynced: FSMState{
                Next: map[string]FSMTransition{FsmStateDnskeysSynced: FsmJoinSyncDnskeys},
            },
            FsmStateDnskeysSynced: FSMState{
                Next: map[string]FSMTransition{FsmStateCdscdnskeysAdded: FsmJoinAddCdscdnskeys},
            },
            FsmStateCdscdnskeysAdded: FSMState{
                Next: map[string]FSMTransition{FsmStateParentDsSynced: FsmJoinParentDsSynced},
            },
            FsmStateParentDsSynced: FSMState{
                Next: map[string]FSMTransition{FsmStateDsPropagated: FsmJoinWaitDs},
            },
            FsmStateDsPropagated: FSMState{
                Next: map[string]FSMTransition{FsmStateCsyncAdded: FsmJoinAddCsync},
            },
            FsmStateCsyncAdded: FSMState{
                Next: map[string]FSMTransition{FsmStateParentNsSynced: FsmJoinParentNsSynced},
            },
            FsmStateParentNsSynced: FSMState{
                Next: map[string]FSMTransition{FsmStateStop: FsmTransitionStopFactory(FsmStateParentNsSynced)},
            },
            FsmStateStop: FSMState{
                Next: map[string]FSMTransition{FsmStateStop: FsmGenericStop},
            },
        },
    },

    // PROCESS: REMOVE-SIGNER: This is a real process, from the draft doc.
    "remove-signer": FSM{
        Type:         "single-run",
        InitialState: FsmStateSignerUnsynced,
        States: map[string]FSMState{
            FsmStateSignerUnsynced: FSMState{
                Next: map[string]FSMTransition{"ns-known": FSMT_RS_1},
            },
            "ns-known": FSMState{
                Next: map[string]FSMTransition{"ns-synced": FSMT_RS_2},
            },
            "ns-synced": FSMState{
                Next: map[string]FSMTransition{
                    "csync-published":      FSMT_RS_3,
                    "delegation-ns-synced": FSMT_RS_3b,
                },
            },
            "csync-published": FSMState{
                Next: map[string]FSMTransition{
                    "delegation-ns-synced": FSMT_RS_4,
                },
            },
            "delegation-ns-synced": FSMState{
                Next: map[string]FSMTransition{"delegation-ns-synced-2": FSMT_RS_5},
            },
            "delegation-ns-synced-2": FSMState{
                Next: map[string]FSMTransition{"delegation-ns-synced-3": FSMT_RS_6},
            },
            "delegation-ns-synced-3": FSMState{
                Next: map[string]FSMTransition{"cds-known": FSMT_RS_7},
            },
            "cds-known": FSMState{
                Next: map[string]FSMTransition{"cds-synced": FSMT_RS_8},
            },
            "cds-synced": FSMState{
                Next: map[string]FSMTransition{"zsk-synced": FSMT_RS_9},
            },
            "zsk-synced": FSMState{
                Next: map[string]FSMTransition{"ds-synced": FSMT_RS_10},
            },
            "ds-synced": FSMState{
                Next: map[string]FSMTransition{"signers-synced": FSMT_RS_11},
            },
            "signers-synced": FSMState{
                Next: map[string]FSMTransition{FsmStateStop: FSMT_RS_12},
            },
            FsmStateStop: FSMState{
                Next: map[string]FSMTransition{FsmStateStop: FSMT_RS_13},
            },
        },
    },

    // PROCESS: ZSK-ROLLOVER: This is a real process
    "zsk-rollover": FSM{
        Type:         "single-run",
        InitialState: FsmStateSignerUnsynced,
        States: map[string]FSMState{
            FsmStateSignerUnsynced: FSMState{
                Next: map[string]FSMTransition{"zsk-known": FSMT_ZR_1},
            },
            "zsk-known": FSMState{
                Next: map[string]FSMTransition{"zsk-synced": FSMT_ZR_2},
            },
            "zsk-synced": FSMState{
                Next: map[string]FSMTransition{"signers-synced": FSMT_ZR_3},
            },
            "signers-synced": FSMState{
                Next: map[string]FSMTransition{FsmStateStop: FSMT_ZR_4},
            },
            FsmStateStop: FSMState{
                Next: map[string]FSMTransition{FsmStateStop: FSMT_ZR_5},
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
