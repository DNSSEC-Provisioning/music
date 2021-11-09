package music

var FsmJoinParentNsSynced = FSMTransition{
    Description: "Wait for parent to pick up CSYNC and update it's NS records (criteria), then remove CSYNC from all signers and STOP (action)",
    Criteria:    func(z *Zone) bool { return true },
    Action: func(z *Zone) bool {
        z.StateTransition(FsmStateAddCsync, FsmStateParentNsSynced)
        return true
    },
}
