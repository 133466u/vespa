// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.config.server;

import com.yahoo.config.provision.ApplicationId;
import com.yahoo.vespa.config.server.application.ApplicationSet;

import java.util.Set;

/**
 * @author Ulf Lilleengen
 */
public class MockReloadHandler implements ReloadHandler {

    public volatile ApplicationId lastRemoved = null;

    @Override
    public void reloadConfig(ApplicationSet application) {
    }

    @Override
    public void removeApplication(ApplicationId applicationId) {
        lastRemoved = applicationId;
    }

    @Override
    public void removeApplicationsExcept(Set<ApplicationId> applicationIds) { }

}
