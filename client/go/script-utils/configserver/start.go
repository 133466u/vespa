// Copyright Yahoo. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
// Author: arnej

package configserver

import (
	"github.com/vespa-engine/vespa/client/go/jvm"
	"github.com/vespa-engine/vespa/client/go/util"
	"github.com/vespa-engine/vespa/client/go/vespa"
)

const (
	SERVICE_NAME = "configserver"
)

func startConfigserver() int {
	vespaHome := vespa.FindHome()
	veHost, e := vespa.FindOurHostname()
	if e != nil {
		panic(e)
	}
	checkIsConfigserver(veHost)
	fixSpec := makeFixSpec()
	fixDirsAndFiles(fixSpec)
	util.TuneResourceLimits()
	vespa.MaybeSwitchUser("start-configserver")
	maybeStartLogd()
	exportSettings(vespaHome)
	removeStaleZkLock(vespaHome)
	c := jvm.NewStandaloneContainer(SERVICE_NAME)
	jvmOpts := jvm.NewOptions(c)
	jvmOpts.AddCommonXX()
	jvmOpts.AddCommonOpens()
	jvmOpts.AddCommonJdkProperties()
	jvmOpts.AddCommonJdiscProperties()
	rs := RunServer{
		ServiceName: SERVICE_NAME,
		Args:        jvmOpts.Args(),
	}
	rs.Exec("java")
	return 1
}
