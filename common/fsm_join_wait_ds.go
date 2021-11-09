package music

var FsmJoinWaitDs = FSMTransition{
    Description: "Wait enough time for parent DS records to propagate (criteria), then sync NS records between all signers (action)",
    Criteria:    func(z *Zone) bool { return true },
    Action: func(z *Zone) bool {
        z.StateTransition(FsmStateParentDsSynced, FsmStateWaitDs)
        return true
    },
}
