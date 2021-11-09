package music

var FsmJoinParentDsSynced = FSMTransition{
    Description: "Wait for parent to pick up CDS/CDNSKEYs and update it's DS (criteria), then remove CDS/CDNSKEYs from all signers (action)",
    Criteria:    func(z *Zone) bool { return true },
    Action: func(z *Zone) bool {
        z.StateTransition(FsmStateAddCdscdnskeys, FsmStateParentDsSynced)
        return true
    },
}
