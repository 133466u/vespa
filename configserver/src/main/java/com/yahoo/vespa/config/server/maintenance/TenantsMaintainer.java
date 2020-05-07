// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.config.server.maintenance;

import com.yahoo.vespa.config.server.ApplicationRepository;
import com.yahoo.vespa.curator.Curator;

import java.time.Duration;
import java.time.Instant;

/**
 * Removes unused tenants (has no applications and was created more than 7 days ago)
 *
 * @author hmusum
 */
public class TenantsMaintainer extends ConfigServerMaintainer {

    private final Duration ttlForUnusedTenant;

    TenantsMaintainer(ApplicationRepository applicationRepository, Curator curator, Duration interval) {
        this(applicationRepository, curator, interval, Duration.ofDays(7));
    }

    private TenantsMaintainer(ApplicationRepository applicationRepository, Curator curator, Duration interval, Duration ttlForUnusedTenant) {
        super(applicationRepository, curator, interval, interval);
        this.ttlForUnusedTenant = ttlForUnusedTenant;
    }

    @Override
    protected void maintain() {
        applicationRepository.deleteUnusedTenants(ttlForUnusedTenant, Instant.now());
    }
}
