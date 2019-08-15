// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.orchestrator.model;

import com.yahoo.vespa.applicationmodel.ApplicationInstance;
import com.yahoo.vespa.applicationmodel.ApplicationInstanceId;
import com.yahoo.vespa.applicationmodel.ClusterId;
import com.yahoo.vespa.applicationmodel.HostName;
import com.yahoo.vespa.applicationmodel.ServiceCluster;
import com.yahoo.vespa.applicationmodel.ServiceStatus;
import com.yahoo.vespa.applicationmodel.ServiceType;
import com.yahoo.vespa.applicationmodel.TenantId;
import com.yahoo.vespa.orchestrator.OrchestratorUtil;
import com.yahoo.vespa.orchestrator.policy.HostStateChangeDeniedException;
import com.yahoo.vespa.orchestrator.policy.HostedVespaClusterPolicy;
import com.yahoo.vespa.orchestrator.status.HostStatus;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClusterApiImplTest {
    final ApplicationApi applicationApi = mock(ApplicationApi.class);
    final ModelTestUtils modelUtils = new ModelTestUtils();

    @Test
    public void testServicesDownAndNotInGroup() {
        HostName hostName1 = new HostName("host1");
        HostName hostName2 = new HostName("host2");
        HostName hostName3 = new HostName("host3");
        HostName hostName4 = new HostName("host4");
        HostName hostName5 = new HostName("host5");

        ServiceCluster serviceCluster = modelUtils.createServiceCluster(
                "cluster",
                new ServiceType("service-type"),
                Arrays.asList(
                        modelUtils.createServiceInstance("service-1", hostName1, ServiceStatus.UP),
                        modelUtils.createServiceInstance("service-2", hostName2, ServiceStatus.DOWN),
                        modelUtils.createServiceInstance("service-3", hostName3, ServiceStatus.UP),
                        modelUtils.createServiceInstance("service-4", hostName4, ServiceStatus.DOWN),
                        modelUtils.createServiceInstance("service-5", hostName5, ServiceStatus.UP)
                )
        );
        modelUtils.createApplicationInstance(Collections.singletonList(serviceCluster));

        modelUtils.createNode(hostName1, HostStatus.NO_REMARKS);
        modelUtils.createNode(hostName2, HostStatus.NO_REMARKS);
        modelUtils.createNode(hostName3, HostStatus.ALLOWED_TO_BE_DOWN);
        modelUtils.createNode(hostName4, HostStatus.ALLOWED_TO_BE_DOWN);
        modelUtils.createNode(hostName5, HostStatus.NO_REMARKS);

        ClusterApiImpl clusterApi = new ClusterApiImpl(
                applicationApi,
                serviceCluster,
                new NodeGroup(modelUtils.createApplicationInstance(new ArrayList<>()), hostName5),
                modelUtils.getHostStatusMap(),
                modelUtils.getClusterControllerClientFactory());

        assertEquals("{ clusterId=cluster, serviceType=service-type }", clusterApi.clusterInfo());
        assertFalse(clusterApi.isStorageCluster());
        assertEquals("[ServiceInstance{configId=service-2, hostName=host2, serviceStatus=" +
                        "ServiceStatusInfo{status=DOWN, since=Optional.empty, lastChecked=Optional.empty}}, "
                        + "ServiceInstance{configId=service-3, hostName=host3, serviceStatus=" +
                        "ServiceStatusInfo{status=UP, since=Optional.empty, lastChecked=Optional.empty}}, "
                        + "ServiceInstance{configId=service-4, hostName=host4, serviceStatus=" +
                        "ServiceStatusInfo{status=DOWN, since=Optional.empty, lastChecked=Optional.empty}}]",
                clusterApi.servicesDownAndNotInGroupDescription());
        assertEquals("[host3, host4]",
                clusterApi.nodesAllowedToBeDownNotInGroupDescription());
        assertEquals(60, clusterApi.percentageOfServicesDown());
        assertEquals(80, clusterApi.percentageOfServicesDownIfGroupIsAllowedToBeDown());
    }

    /** Make a ClusterApiImpl for the cfg1 config server, with cfg3 missing from the cluster (not provisioned). */
    private ClusterApiImpl makeCfg1ClusterApi(ServiceStatus cfg1ServiceStatus, ServiceStatus cfg2ServiceStatus) {
        HostName cfg1Hostname = new HostName("cfg1");
        HostName cfg2Hostname = new HostName("cfg2");

        ServiceCluster serviceCluster = modelUtils.createServiceCluster(
                ClusterId.CONFIG_SERVER.s(),
                ServiceType.CONFIG_SERVER,
                Arrays.asList(
                        modelUtils.createServiceInstance("cs1", cfg1Hostname, cfg1ServiceStatus),
                        modelUtils.createServiceInstance("cs2", cfg2Hostname, cfg2ServiceStatus))
        );

        Set<ServiceCluster> serviceClusterSet = new HashSet<>(Set.of(serviceCluster));

        ApplicationInstance application = new ApplicationInstance(
                TenantId.HOSTED_VESPA,
                ApplicationInstanceId.CONFIG_SERVER,
                serviceClusterSet);

        serviceCluster.setApplicationInstance(application);

        when(applicationApi.applicationId()).thenReturn(OrchestratorUtil.toApplicationId(application.reference()));

        ClusterApiImpl clusterApi = new ClusterApiImpl(
                applicationApi,
                serviceCluster,
                new NodeGroup(application, cfg1Hostname),
                modelUtils.getHostStatusMap(),
                modelUtils.getClusterControllerClientFactory());

        assertEquals(1, clusterApi.missingServices());
        assertFalse(clusterApi.noServicesOutsideGroupIsDown());

        return clusterApi;
    }

    @Test
    public void testCfg1SuspensionFailsWithMissingCfg3() {
        ClusterApiImpl clusterApi = makeCfg1ClusterApi(ServiceStatus.UP, ServiceStatus.UP);

        HostedVespaClusterPolicy policy = new HostedVespaClusterPolicy();

        try {
            policy.verifyGroupGoingDownIsFine(clusterApi);
            fail();
        } catch (HostStateChangeDeniedException e) {
            assertThat(e.getMessage(),
                    containsString("Changing the state of cfg1 would violate enough-services-up: Suspension percentage " +
                            "for service type configserver would increase from 33% to 66%, over the limit of 10%. " +
                            "These instances may be down: [1 missing config server] and these hosts are allowed to be down: []"));
        }
    }

    @Test
    public void testCfg1SuspendsIfDownWithMissingCfg3() throws HostStateChangeDeniedException {
        ClusterApiImpl clusterApi = makeCfg1ClusterApi(ServiceStatus.DOWN, ServiceStatus.UP);

        HostedVespaClusterPolicy policy = new HostedVespaClusterPolicy();

        policy.verifyGroupGoingDownIsFine(clusterApi);
    }

    @Test
    public void testNoServices() {
        HostName hostName1 = new HostName("host1");
        HostName hostName2 = new HostName("host2");
        HostName hostName3 = new HostName("host3");
        HostName hostName4 = new HostName("host4");
        HostName hostName5 = new HostName("host5");

        ServiceCluster serviceCluster = modelUtils.createServiceCluster(
                "cluster",
                new ServiceType("service-type"),
                Arrays.asList(
                        modelUtils.createServiceInstance("service-1", hostName1, ServiceStatus.UP),
                        modelUtils.createServiceInstance("service-2", hostName2, ServiceStatus.DOWN),
                        modelUtils.createServiceInstance("service-3", hostName3, ServiceStatus.UP),
                        modelUtils.createServiceInstance("service-4", hostName4, ServiceStatus.DOWN),
                        modelUtils.createServiceInstance("service-5", hostName5, ServiceStatus.UP)
                )
        );
        modelUtils.createApplicationInstance(Collections.singletonList(serviceCluster));

        modelUtils.createNode(hostName1, HostStatus.NO_REMARKS);
        modelUtils.createNode(hostName2, HostStatus.NO_REMARKS);
        modelUtils.createNode(hostName3, HostStatus.ALLOWED_TO_BE_DOWN);
        modelUtils.createNode(hostName4, HostStatus.ALLOWED_TO_BE_DOWN);
        modelUtils.createNode(hostName5, HostStatus.NO_REMARKS);

        verifyNoServices(serviceCluster, false, false, hostName1);
        verifyNoServices(serviceCluster, true, false, hostName2);
        verifyNoServices(serviceCluster, true, false, hostName3);
        verifyNoServices(serviceCluster, true, false, hostName4);
        verifyNoServices(serviceCluster, false, false, hostName5);

        verifyNoServices(serviceCluster, false, false, hostName1, hostName2);
        verifyNoServices(serviceCluster, true, false, hostName2, hostName3);
        verifyNoServices(serviceCluster, true, true, hostName2, hostName3, hostName4);
        verifyNoServices(serviceCluster, false, true, hostName1, hostName2, hostName3, hostName4);
    }

    private void verifyNoServices(ServiceCluster serviceCluster,
                                  boolean expectedNoServicesInGroupIsUp,
                                  boolean expectedNoServicesOutsideGroupIsDown,
                                  HostName... groupNodes) {
        ClusterApiImpl clusterApi = new ClusterApiImpl(
                applicationApi,
                serviceCluster,
                new NodeGroup(modelUtils.createApplicationInstance(new ArrayList<>()), groupNodes),
                modelUtils.getHostStatusMap(),
                modelUtils.getClusterControllerClientFactory());

        assertEquals(expectedNoServicesInGroupIsUp, clusterApi.noServicesInGroupIsUp());
        assertEquals(expectedNoServicesOutsideGroupIsDown, clusterApi.noServicesOutsideGroupIsDown());
    }

    @Test
    public void testStorageCluster() {
        HostName hostName1 = new HostName("host1");
        HostName hostName2 = new HostName("host2");
        HostName hostName3 = new HostName("host3");

        ServiceCluster serviceCluster = modelUtils.createServiceCluster(
                "cluster",
                VespaModelUtil.STORAGENODE_SERVICE_TYPE,
                Arrays.asList(
                        modelUtils.createServiceInstance("storage-1", hostName1, ServiceStatus.UP),
                        modelUtils.createServiceInstance("storage-2", hostName2, ServiceStatus.DOWN)
                )
        );


        ApplicationInstance applicationInstance = modelUtils.createApplicationInstance(new ArrayList<>());
        serviceCluster.setApplicationInstance(applicationInstance);

        ClusterApiImpl clusterApi = new ClusterApiImpl(
                applicationApi,
                serviceCluster,
                new NodeGroup(applicationInstance, hostName1, hostName3),
                new HashMap<>(),
                modelUtils.getClusterControllerClientFactory());

        assertTrue(clusterApi.isStorageCluster());
        assertEquals(Optional.of(hostName1), clusterApi.storageNodeInGroup().map(storageNode -> storageNode.hostName()));
        assertEquals(Optional.of(hostName1), clusterApi.upStorageNodeInGroup().map(storageNode -> storageNode.hostName()));
    }
}
