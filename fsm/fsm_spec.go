/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package fsm

import (
	"fmt"

	music "github.com/DNSSEC-Provisioning/music/common"
)

const (
	FsmStateSignerUnsynced   = "signers-unsynced"
	FsmStateDnskeysSynced    = "dnskeys-synced"
	FsmStateCDSAdded         = "cds-added"
	FsmStateParentDsSynced   = "parent-ds-synced"
	FsmStateDsPropagated     = "ds-propagated"
	FsmStateCsyncAdded       = "csync-added"
	FsmStateParentNsSynced   = "parent-ns-synced"
	FsmStateNsesSynced       = "nses-synced"
	FsmStateNsPropagated     = "ns-propagated"
	FsmStateStop             = "stop"
)

var FsmGenericStop = music.FsmTransitionStopFactory(FsmStateStop)

// PROCESS: ADD-SIGNER
// defined in fsm_join*.go

// PROCESS: REMOVE-SIGNER
var FSMT_RS_1 = music.FsmTransitionFactory(FsmStateSignerUnsynced, "ns-known")
var FSMT_RS_2 = music.FsmTransitionFactory("ns-known", "ns-synced")
var FSMT_RS_3 = music.FsmTransitionFactory("ns-synced", "csync-published")
var FSMT_RS_3b = music.FsmTransitionFactory("ns-synced", "delegation-ns-synced")
var FSMT_RS_4 = music.FsmTransitionFactory("csync-published", "delegation-ns-synced")
var FSMT_RS_5 = music.FsmTransitionFactory("delegation-ns-synced", "delegation-ns-synced-2")
var FSMT_RS_6 = music.FsmTransitionFactory("delegation-ns-synced-2", "delegation-ns-synced-3")
var FSMT_RS_7 = music.FsmTransitionFactory("delegation-ns-synced-3", "cds-known")
var FSMT_RS_8 = music.FsmTransitionFactory("cds-known", "cds-synced")
var FSMT_RS_9 = music.FsmTransitionFactory("cds-synced", "zsk-synced")
var FSMT_RS_10 = music.FsmTransitionFactory("zsk-synced", "ds-synced")
var FSMT_RS_11 = music.FsmTransitionFactory("ds-synced", "signers-synced")
var FSMT_RS_12 = music.FsmTransitionFactory("signers-synced", FsmStateStop) // terminator signal
var FSMT_RS_13 = music.FSMTransition{
	Desc:     "FSMT_RS_13",
	Criteria: music.FsmCriteriaFactory(FsmStateStop, FsmStateStop),
	Action: func(z *music.Zone) bool {
		fmt.Printf("Enter ACTION for <stop, stop>. zone state: %s\n", z.State)
		// z.StateTransition(FsmStateStop, FsmStateStop)
		fmt.Printf("FsmAction (stop): Exiting the remove-signer process seems to have gone well. Yay!\n")
		return true
	},
}

// PROCESS: ADD-ZONE (bogus process, only for testing)
var FSMT_AZ_1 = music.FsmTransitionFactory("ready", "join-sync-cds")
var FSMT_AZ_2 = music.FsmTransitionFactory("join-sync-cds", "join-cds-synced")
var FSMT_AZ_3 = music.FsmTransitionFactory("join-cds-synced", "ready")
var FSMT_AZ_3b = music.FsmTransitionFactory("join-cds-synced", "foobar")
var FSMT_AZ_4 = music.FsmTransitionFactory("foobar", "ready")

// PROCESS: ZSK-ROLLOVER
var FSMT_ZR_1 = music.FsmTransitionFactory(FsmStateSignerUnsynced, "zsks-known")
var FSMT_ZR_2 = music.FsmTransitionFactory("zsks-known", "zsks-synced")
var FSMT_ZR_3 = music.FsmTransitionFactory("zsks-synced", "signers-synced")
var FSMT_ZR_4 = music.FsmTransitionFactory("signers-synced", FsmStateStop)
var FSMT_ZR_5 = music.FsmTransitionFactory(FsmStateStop, FsmStateStop)

func NewFSMlist() map[string]music.FSM {
     return FSMlist
}

var FSMlist = map[string]music.FSM{
	// PROCESS: ADD-ZONE: This is a bogus process, only for testing.
	"add-zone": music.FSM{
		Type:         "single-run",
		InitialState: "ready",
		States: map[string]music.FSMState{
			"ready": music.FSMState{
				Next: map[string]music.FSMTransition{"join-sync-cds": FSMT_AZ_1},
			},
			"join-sync-cds": music.FSMState{
				Next: map[string]music.FSMTransition{"join-cds-synced": FSMT_AZ_2},
			},
			"join-cds-synced": music.FSMState{
				Next: map[string]music.FSMTransition{
					"ready":  FSMT_AZ_3,
					"foobar": FSMT_AZ_3b,
				},
			},
			"foobar": music.FSMState{
				Next: map[string]music.FSMTransition{"ready": FSMT_AZ_4},
			},
		},
	},

	// PROCESS: ADD-SIGNER: This is a real process, from the draft doc.
	"add-signer": music.FSM{
		Name:         "add-signer",
		Type:         "single-run",
		InitialState: FsmStateSignerUnsynced,
		Desc: `
ADD-SIGNER is the process that all zones attached to a signer group
must execute when a new signer is added to the group. It contains
steps for synching DNSKEYs among signers as well as updating the
DS and NS RRsets in the parent.`,
		States: map[string]music.FSMState{
			FsmStateSignerUnsynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateDnskeysSynced: FsmJoinSyncDnskeys},
			},
			FsmStateDnskeysSynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateCDSAdded: FsmJoinAddCDS},
			},
			FsmStateCDSAdded: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateParentDsSynced: FsmJoinParentDsSynced},
			},
			FsmStateParentDsSynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateDsPropagated: FsmJoinWaitDs},
			},
			FsmStateDsPropagated: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateCsyncAdded: FsmJoinAddCsync},
			},
			FsmStateCsyncAdded: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateParentNsSynced: FsmJoinParentNsSynced},
			},
			FsmStateParentNsSynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: music.FsmTransitionStopFactory(FsmStateParentNsSynced)},
			},
			FsmStateStop: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: FsmGenericStop},
			},
		},
	},

	"remove-signer": music.FSM{
		Name:         "remove-signer",
		Type:         "single-run",
		InitialState: FsmStateSignerUnsynced,
		Desc: `
REMOVE-SIGNER is the process that all zones attached to a signer
group must execute when an existing signer is removed from the group.
It contains steps for synching DNSKEYs among signers as well as
updating the DS and NS RRsets in the parent.

Note that it is not possible to remove the last signer in a group,
as that would cause the attached zones to have to go unsigned.`,
		States: map[string]music.FSMState{
			FsmStateSignerUnsynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateNsesSynced: FsmLeaveSyncNses},
			},
			FsmStateNsesSynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateCsyncAdded: FsmLeaveAddCsync},
			},
			FsmStateCsyncAdded: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateParentNsSynced: FsmLeaveParentNsSynced},
			},
			FsmStateParentNsSynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateNsPropagated: FsmLeaveWaitNs},
			},
			FsmStateNsPropagated: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateDnskeysSynced: FsmLeaveSyncDnskeys},
			},
			FsmStateDnskeysSynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateCDSAdded: FsmLeaveAddCDS},
			},
			FsmStateCDSAdded: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateParentDsSynced: FsmLeaveParentDsSynced},
			},
			FsmStateParentDsSynced: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: music.FsmTransitionStopFactory(FsmStateParentDsSynced)},
			},
			FsmStateStop: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: FsmGenericStop},
			},
		},
	},

	// PROCESS: REMOVE-SIGNER: This is a real process, from the draft doc.
	"remove-signer-old": music.FSM{
		Type:         "single-run",
		InitialState: FsmStateSignerUnsynced,
		States: map[string]music.FSMState{
			FsmStateSignerUnsynced: music.FSMState{
				Next: map[string]music.FSMTransition{"ns-known": FSMT_RS_1},
			},
			"ns-known": music.FSMState{
				Next: map[string]music.FSMTransition{"ns-synced": FSMT_RS_2},
			},
			"ns-synced": music.FSMState{
				Next: map[string]music.FSMTransition{
					"csync-published":      FSMT_RS_3,
					"delegation-ns-synced": FSMT_RS_3b,
				},
			},
			"csync-published": music.FSMState{
				Next: map[string]music.FSMTransition{
					"delegation-ns-synced": FSMT_RS_4,
				},
			},
			"delegation-ns-synced": music.FSMState{
				Next: map[string]music.FSMTransition{"delegation-ns-synced-2": FSMT_RS_5},
			},
			"delegation-ns-synced-2": music.FSMState{
				Next: map[string]music.FSMTransition{"delegation-ns-synced-3": FSMT_RS_6},
			},
			"delegation-ns-synced-3": music.FSMState{
				Next: map[string]music.FSMTransition{"cds-known": FSMT_RS_7},
			},
			"cds-known": music.FSMState{
				Next: map[string]music.FSMTransition{"cds-synced": FSMT_RS_8},
			},
			"cds-synced": music.FSMState{
				Next: map[string]music.FSMTransition{"zsk-synced": FSMT_RS_9},
			},
			"zsk-synced": music.FSMState{
				Next: map[string]music.FSMTransition{"ds-synced": FSMT_RS_10},
			},
			"ds-synced": music.FSMState{
				Next: map[string]music.FSMTransition{"signers-synced": FSMT_RS_11},
			},
			"signers-synced": music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: FSMT_RS_12},
			},
			FsmStateStop: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: FSMT_RS_13},
			},
		},
	},

	// PROCESS: ZSK-ROLLOVER: This is a real process
	"zsk-rollover": music.FSM{
		Name:         "zsk-rollover",
		Type:         "single-run",
		InitialState: FsmStateSignerUnsynced,
		States: map[string]music.FSMState{
			FsmStateSignerUnsynced: music.FSMState{
				Next: map[string]music.FSMTransition{"zsk-known": FSMT_ZR_1},
			},
			"zsk-known": music.FSMState{
				Next: map[string]music.FSMTransition{"zsk-synced": FSMT_ZR_2},
			},
			"zsk-synced": music.FSMState{
				Next: map[string]music.FSMTransition{"signers-synced": FSMT_ZR_3},
			},
			"signers-synced": music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: FSMT_ZR_4},
			},
			FsmStateStop: music.FSMState{
				Next: map[string]music.FSMTransition{FsmStateStop: FSMT_ZR_5},
			},
		},
	},

	"ksk-rollover": music.FSM{
		Name:         "ksk-rollover",
		Type:         "permanent",
		InitialState: "serene-happiness",
		States:       map[string]music.FSMState{},
	},
}

