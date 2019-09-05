// Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.controller.api.integration.organization;

import com.yahoo.config.provision.ApplicationId;
import com.yahoo.config.provision.zone.ZoneId;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A summary of activity in an application.
 *
 * @author mpolden
 */
public class ApplicationSummary {

    private final ApplicationId application;
    private final Optional<Instant> lastQueried;
    private final Optional<Instant> lastWritten;
    private final Map<ZoneId, Metric> metrics;

    public ApplicationSummary(ApplicationId application, Optional<Instant> lastQueried, Optional<Instant> lastWritten, Map<ZoneId, Metric> metrics) {
        this.application = Objects.requireNonNull(application);
        this.lastQueried = Objects.requireNonNull(lastQueried);
        this.lastWritten = Objects.requireNonNull(lastWritten);
        this.metrics = Map.copyOf(Objects.requireNonNull(metrics));
    }

    public ApplicationId application() {
        return application;
    }

    public Optional<Instant> lastQueried() {
        return lastQueried;
    }

    public Optional<Instant> lastWritten() {
        return lastWritten;
    }

    public Map<ZoneId, Metric> metrics() {
        return metrics;
    }

    public static class Metric {

        private final double documentCount;
        private final double queriesPerSecond;
        private final double writesPerSecond;

        public Metric(double documentCount, double queriesPerSecond, double writesPerSecond) {
            this.documentCount = documentCount;
            this.queriesPerSecond = queriesPerSecond;
            this.writesPerSecond = writesPerSecond;
        }

        public double documentCount() {
            return documentCount;
        }

        public double queriesPerSecond() {
            return queriesPerSecond;
        }

        public double writesPerSecond() {
            return writesPerSecond;
        }

    }

}
