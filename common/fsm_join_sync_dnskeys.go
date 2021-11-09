package music

var FsmJoinSyncDnskeys = FSMTransition{
    Description: "First step when joining, this transistion has no criteria and will sync DNSKEYs between all signers (action)",
    Criteria:    func(z *Zone) bool { return true },
    Action: func(z *Zone) bool {
        z.StateTransition(FsmStateSignerUnsynced, FsmStateSyncDnskeys)
        return true
    },
}
