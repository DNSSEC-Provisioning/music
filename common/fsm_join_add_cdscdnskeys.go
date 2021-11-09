package music

var FsmJoinAddCdscdnskeys = FSMTransition{
    Description: "Once all DNSKEYs are present in all signers (criteria), build CDS/CDNSKEYs RRset and push to all signers (action)",
    Criteria:    func(z *Zone) bool { return true },
    Action: func(z *Zone) bool {
        z.StateTransition(FsmStateSyncDnskeys, FsmStateAddCdscdnskeys)
        return true
    },
}
