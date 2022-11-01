// Copyright Yahoo. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
// Author: arnej

package configserver

import (
	"fmt"

	"github.com/vespa-engine/vespa/client/go/defaults"
	"github.com/vespa-engine/vespa/client/go/trace"
	"github.com/vespa-engine/vespa/client/go/util"
)

func checkIsConfigserver(myname string) {
	for _, hn := range defaults.VespaConfigserverHosts() {
		if hn == "localhost" || hn == myname {
			trace.Trace("should run configserver:", hn)
			return
		}
	}
	trace.Warning("only these hosts should run a config server:", defaults.VespaConfigserverHosts())
	util.JustExitMsg(fmt.Sprintf("this host [%s] should not run a config server", myname))
}
