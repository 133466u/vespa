/*
 * Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
 */

package com.yahoo.vespa.model.admin.metricsproxy;

import ai.vespa.metricsproxy.core.ConsumersConfig;
import ai.vespa.metricsproxy.metric.dimensions.ApplicationDimensionsConfig;
import ai.vespa.metricsproxy.metric.dimensions.NodeDimensionsConfig;
import ai.vespa.metricsproxy.rpc.RpcConnectorConfig;
import ai.vespa.metricsproxy.service.VespaServicesConfig;
import com.yahoo.config.provision.Flavor;
import com.yahoo.config.provisioning.FlavorsConfig;
import com.yahoo.search.config.QrStartConfig;
import com.yahoo.vespa.model.VespaModel;
import com.yahoo.vespa.model.admin.monitoring.Metric;
import com.yahoo.vespa.model.test.VespaModelTester;

import static com.yahoo.vespa.model.admin.monitoring.DefaultMetricsConsumer.VESPA_CONSUMER_ID;
import static org.junit.Assert.assertEquals;

/**
 * @author gjoranv
 */
class MetricsProxyModelTester {

    static final String MY_TENANT = "mytenant";
    static final String MY_APPLICATION = "myapp";
    static final String MY_INSTANCE = "myinstance";
    static final String MY_FLAVOR = "myflavor";

    static final String CLUSTER_CONFIG_ID = "admin/metrics";

    // Used for all configs that are produced by the container, not the cluster.
    static final String CONTAINER_CONFIG_ID = CLUSTER_CONFIG_ID + "/metricsproxy.0";

    static VespaModel getModel(String servicesXml) {
        var numberOfHosts = 1;
        var tester = new VespaModelTester();
        tester.enableMetricsProxyContainer(true);
        tester.addHosts(numberOfHosts);
        tester.setHosted(false);
        return tester.createModel(servicesXml, true);
    }

    static VespaModel getHostedModel(String servicesXml) {
        var numberOfHosts = 2;
        var tester = new VespaModelTester();
        tester.enableMetricsProxyContainer(true);
        tester.addHosts(flavorFromString(MY_FLAVOR), numberOfHosts);
        tester.setHosted(true);
        tester.setApplicationId(MY_TENANT, MY_APPLICATION, MY_INSTANCE);
        return tester.createModel(servicesXml, true);
    }

    static boolean checkMetric(ConsumersConfig.Consumer consumer, Metric metric) {
        for (ConsumersConfig.Consumer.Metric m : consumer.metric()) {
            if (metric.name.equals(m.name()) && metric.outputName.equals(m.outputname()))
                return true;
        }
        return false;
    }

    static ConsumersConfig.Consumer getCustomConsumer(String servicesXml) {
        ConsumersConfig config = consumersConfigFromXml(servicesXml);
        assertEquals(2, config.consumer().size());
        for (ConsumersConfig.Consumer consumer : config.consumer()) {
            if (! consumer.name().equals(VESPA_CONSUMER_ID))
                return consumer;
        }
        throw new RuntimeException("Two consumers with the reserved id - this cannot happen.");
    }

    static ConsumersConfig consumersConfigFromXml(String servicesXml) {
        return consumersConfigFromModel(getModel(servicesXml));
    }

    static ConsumersConfig consumersConfigFromModel(VespaModel model) {
        return new ConsumersConfig((ConsumersConfig.Builder) model.getConfig(new ConsumersConfig.Builder(), CLUSTER_CONFIG_ID));
    }

    static ApplicationDimensionsConfig getApplicationDimensionsConfig(VespaModel model) {
        return new ApplicationDimensionsConfig((ApplicationDimensionsConfig.Builder) model.getConfig(new ApplicationDimensionsConfig.Builder(), CLUSTER_CONFIG_ID));
    }

    static QrStartConfig getQrStartConfig(VespaModel model) {
        return new QrStartConfig((QrStartConfig.Builder) model.getConfig(new QrStartConfig.Builder(), CLUSTER_CONFIG_ID));
    }

    static NodeDimensionsConfig getNodeDimensionsConfig(VespaModel model) {
        return new NodeDimensionsConfig((NodeDimensionsConfig.Builder) model.getConfig(new NodeDimensionsConfig.Builder(), CONTAINER_CONFIG_ID));
    }

    static VespaServicesConfig getVespaServicesConfig(String servicesXml) {
        VespaModel model = getModel(servicesXml);
        return new VespaServicesConfig((VespaServicesConfig.Builder) model.getConfig(new VespaServicesConfig.Builder(), CONTAINER_CONFIG_ID));
    }

    static RpcConnectorConfig getRpcConnectorConfig(VespaModel model) {
        return new RpcConnectorConfig((RpcConnectorConfig.Builder) model.getConfig(new RpcConnectorConfig.Builder(), CONTAINER_CONFIG_ID));
    }

    private static Flavor flavorFromString(String name) {
        return new Flavor(new FlavorsConfig.Flavor(new FlavorsConfig.Flavor.Builder().
                name(name)));
    }

}
