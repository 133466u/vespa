// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "metrics.h"
#include <vespa/vespalib/metrics/simple_metrics.h>
#include <vespa/fastos/timestamp.h>

namespace config::sentinel {

using vespalib::metrics::SimpleMetricsManager;
using vespalib::metrics::SimpleManagerConfig;

StartMetrics::StartMetrics()
    : metrics(SimpleMetricsManager::create(SimpleManagerConfig())),
      producer(metrics),
      currentlyRunningServices(0),
      totalRestartsCounter(0),
      startedTime(fastos::time()),
      sentinel_restarts(metrics->counter("sentinel.restarts",
              "how many times sentinel restarted a service")),
      sentinel_totalRestarts(metrics->gauge("sentinel.totalRestarts",
              "how many times sentinel restarted a service since sentinel start")),
      sentinel_running(metrics->gauge("sentinel.running",
              "how many services the sentinel has running currently")),
      sentinel_uptime(metrics->gauge("sentinel.uptime",
              "how many seconds has the sentinel been running"))
{
    // account for the sentinel itself restarting
    sentinel_restarts.add();
}

StartMetrics::~StartMetrics() = default;

void
StartMetrics::maybeLog()
{
    uint32_t curTime = fastos::time();
    sentinel_totalRestarts.sample(totalRestartsCounter);
    sentinel_running.sample(currentlyRunningServices);
    sentinel_uptime.sample(curTime - startedTime);
}

}
