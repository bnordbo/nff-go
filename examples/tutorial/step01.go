package main

import "github.com/bnordbo/nff-go/flow"

func main() {
	// Init NFF-GO system
	flow.CheckFatal(flow.SystemInit(nil))

	initCommonState()

	flow.CheckFatal(flow.SystemStart())
}
