// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.config.server.deploy;

import com.yahoo.config.provision.ApplicationId;
import com.yahoo.config.provision.Deployment;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * @author Ulf Lilleengen
 */
public class MockDeployer implements com.yahoo.config.provision.Deployer {

    @Override
    public Optional<Deployment> deployFromLocalActive(ApplicationId application) {
        return deployFromLocalActive(application, Duration.ofSeconds(60));
    }

    @Override
    public Optional<Deployment> deployFromLocalActive(ApplicationId application, boolean bootstrap) {
        return Optional.empty();
    }

    @Override
    public Optional<Deployment> deployFromLocalActive(ApplicationId application, Duration timeout) {
        return Optional.empty();
    }

    @Override
    public Optional<Deployment> deployFromLocalActive(ApplicationId application, Duration timeout, boolean bootstrap) {
        return Optional.empty();
    }

    @Override
    public Optional<Instant> lastDeployTime(ApplicationId application) {
        return Optional.empty();
    }

}
