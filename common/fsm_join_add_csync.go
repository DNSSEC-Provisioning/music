package music

var FsmJoinAddCsync = FSMTransition{
    Description: "Once all NS are present in all signers (criteria), build CSYNC record and push to all signers (action)",
    Criteria:    func(z *Zone) bool { return true },
    Action: func(z *Zone) bool {
        z.StateTransition(FsmStateWaitDs, FsmStateAddCsync)
        return true
    },
}
