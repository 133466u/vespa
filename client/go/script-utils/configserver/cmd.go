// Copyright Yahoo. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
// Author: arnej

package configserver

import (
	"github.com/vespa-engine/vespa/client/go/trace"
	"github.com/vespa-engine/vespa/client/go/vespa"
)

func Run() int {
	trace.AdjustVerbosity(1)
	err := vespa.LoadDefaultEnv()
	if err != nil {
		panic(err)
	}
	hostname, err := vespa.FindOurHostname()
	if err != nil {
		trace.Warning("could not detect hostname:", err, "; using fallback:", hostname)
	}
	vespa.RunPreStart()
	return startConfigserver()
}
