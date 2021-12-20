/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package fsm

import (
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
//	FsmStateStop             = "stop"		// XXX: This state is defined in music package
)

var FsmGenericStop = music.FsmTransitionStopFactory(music.FsmStateStop)

func NewFSMlist() map[string]music.FSM {
     return FSMlist
}

var FSMlist = map[string]music.FSM{
	// PROCESS: ADD-ZONE: This is a bogus process, only for testing.

	"add-zone": music.FSM{
		Type:         "single-run",
		InitialState: "ready",
		States: map[string]music.FSMState{
		},
	},

	// PROCESS: ADD-SIGNER: This is a real process, from the draft doc.
	// defined in fsm/join*.go

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
				Next: map[string]music.FSMTransition{
					FsmStateDnskeysSynced: FsmJoinSyncDnskeys,
					},
			},
			FsmStateDnskeysSynced: music.FSMState{
				Next: map[string]music.FSMTransition{
					FsmStateCDSAdded: FsmJoinAddCDS,
					},
			},
			FsmStateCDSAdded: music.FSMState{
				Next: map[string]music.FSMTransition{
					FsmStateParentDsSynced: FsmJoinParentDsSynced,
					},
			},
			FsmStateParentDsSynced: music.FSMState{
				Next: map[string]music.FSMTransition{
					FsmStateDsPropagated: FsmJoinWaitDs,
					},
			},
			FsmStateDsPropagated: music.FSMState{
				Next: map[string]music.FSMTransition{
					FsmStateCsyncAdded: FsmJoinAddCsync,
					},
			},
			FsmStateCsyncAdded: music.FSMState{
				Next: map[string]music.FSMTransition{
					FsmStateParentNsSynced: FsmJoinParentNsSynced,
					},
			},
			FsmStateParentNsSynced: music.FSMState{
				Next: map[string]music.FSMTransition{
					music.FsmStateStop: music.FsmTransitionStopFactory(FsmStateParentNsSynced),
					},
			},
			music.FsmStateStop: music.FSMState{
				Next: map[string]music.FSMTransition{
				      music.FsmStateStop: FsmGenericStop,
				      },
			},
		},
	},

	// PROCESS: REMOVE-SIGNER: This is a real process, from the draft.
	// defined in fsm/leave*.go

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
				Next: map[string]music.FSMTransition{music.FsmStateStop: music.FsmTransitionStopFactory(FsmStateParentDsSynced)},
			},
			music.FsmStateStop: music.FSMState{
				Next: map[string]music.FSMTransition{music.FsmStateStop: FsmGenericStop},
			},
		},
	},

	// PROCESS: ZSK-ROLLOVER: This is a real process
	"zsk-rollover": music.FSM{
		Name:         "zsk-rollover",
		Type:         "single-run",
		InitialState: FsmStateSignerUnsynced,
		States: map[string]music.FSMState{
// 			FsmStateSignerUnsynced: music.FSMState{
// 				Next: map[string]music.FSMTransition{"zsk-known": FSMT_ZR_1},
// 			},
// 			"zsk-known": music.FSMState{
// 				Next: map[string]music.FSMTransition{"zsk-synced": FSMT_ZR_2},
// 			},
// 			"zsk-synced": music.FSMState{
// 				Next: map[string]music.FSMTransition{"signers-synced": FSMT_ZR_3},
// 			},
// 			"signers-synced": music.FSMState{
// 				Next: map[string]music.FSMTransition{FsmStateStop: FSMT_ZR_4},
// 			},
// 			FsmStateStop: music.FSMState{
// 				Next: map[string]music.FSMTransition{FsmStateStop: FSMT_ZR_5},
// 			},
		},
	},

	"ksk-rollover": music.FSM{
		Name:         "ksk-rollover",
		Type:         "permanent",
		InitialState: "serene-happiness",
		States:       map[string]music.FSMState{},
	},
}

