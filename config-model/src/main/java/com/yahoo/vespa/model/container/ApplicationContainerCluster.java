// Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.model.container;

import com.yahoo.component.ComponentId;
import com.yahoo.component.ComponentSpecification;
import com.yahoo.config.FileReference;
import com.yahoo.config.application.api.ComponentInfo;
import com.yahoo.config.model.api.TlsSecrets;
import com.yahoo.config.model.deploy.DeployState;
import com.yahoo.config.model.producer.AbstractConfigProducer;
import com.yahoo.container.BundlesConfig;
import com.yahoo.container.bundle.BundleInstantiationSpecification;
import com.yahoo.container.jdisc.ContainerMbusConfig;
import com.yahoo.container.jdisc.messagebus.MbusServerProvider;
import com.yahoo.jdisc.http.ServletPathsConfig;
import com.yahoo.osgi.provider.model.ComponentModel;
import com.yahoo.search.config.QrStartConfig;
import com.yahoo.vespa.config.search.RankProfilesConfig;
import com.yahoo.vespa.config.search.core.RankingConstantsConfig;
import com.yahoo.vespa.defaults.Defaults;
import com.yahoo.vespa.model.container.component.Component;
import com.yahoo.vespa.model.container.component.ConfigProducerGroup;
import com.yahoo.vespa.model.container.component.Servlet;
import com.yahoo.vespa.model.container.jersey.Jersey2Servlet;
import com.yahoo.vespa.model.container.jersey.RestApi;
import com.yahoo.vespa.model.utils.FileSender;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A container cluster that is typically set up from the user application.
 *
 * @author gjoranv
 */
public final class ApplicationContainerCluster extends ContainerCluster<ApplicationContainer> implements
        BundlesConfig.Producer,
        QrStartConfig.Producer,
        RankProfilesConfig.Producer,
        RankingConstantsConfig.Producer,
        ServletPathsConfig.Producer,
        ContainerMbusConfig.Producer
{

    private final Set<FileReference> applicationBundles = new LinkedHashSet<>();

    private final ConfigProducerGroup<Servlet> servletGroup;
    private final ConfigProducerGroup<RestApi> restApiGroup;

    private ContainerModelEvaluation modelEvaluation;

    private Optional<TlsSecrets> tlsSecrets;
    private Optional<String> tlsClientAuthority;

    private MbusParams mbusParams;
    private boolean messageBusEnabled = true;

    public ApplicationContainerCluster(AbstractConfigProducer<?> parent, String subId, String name, DeployState deployState) {
        super(parent, subId, name, deployState);

        this.tlsSecrets = deployState.tlsSecrets();
        this.tlsClientAuthority = deployState.tlsClientAuthority();
        restApiGroup = new ConfigProducerGroup<>(this, "rest-api");
        servletGroup = new ConfigProducerGroup<>(this, "servlet");

        addSimpleComponent(DEFAULT_LINGUISTICS_PROVIDER);
        addSimpleComponent("com.yahoo.container.jdisc.SecretStoreProvider");
        addSimpleComponent("com.yahoo.container.jdisc.DeprecatedSecretStoreProvider");
        addSimpleComponent("com.yahoo.container.jdisc.CertificateStoreProvider");
        addTestrunnerComponentsIfTester(deployState);
    }

    @Override
    protected void doPrepare(DeployState deployState) {
        addAndSendApplicationBundles(deployState);
        if (modelEvaluation != null)
            modelEvaluation.prepare(containers);
        sendUserConfiguredFiles(deployState);
        for (RestApi restApi : restApiGroup.getComponents())
            restApi.prepare();
    }

    private void addAndSendApplicationBundles(DeployState deployState) {
        for (ComponentInfo component : deployState.getApplicationPackage().getComponentsInfo(deployState.getVespaVersion())) {
            FileReference reference = FileSender.sendFileToServices(component.getPathRelativeToAppDir(), containers);
            applicationBundles.add(reference);
        }
    }

    private void sendUserConfiguredFiles(DeployState deployState) {
        // Files referenced from user configs to all components.
        for (Component<?, ?> component : getAllComponents()) {
            FileSender.sendUserConfiguredFiles(component, containers, deployState.getDeployLogger());
        }
    }

    private void addTestrunnerComponentsIfTester(DeployState deployState) {
        if (deployState.isHosted() && deployState.getProperties().applicationId().instance().isTester())
            addPlatformBundle(Paths.get(Defaults.getDefaults().underVespaHome("lib/jars/vespa-testrunner-components-jar-with-dependencies.jar")));
    }

    public void setModelEvaluation(ContainerModelEvaluation modelEvaluation) {
        this.modelEvaluation = modelEvaluation;
    }

    public final void addRestApi(RestApi restApi) {
        restApiGroup.addComponent(ComponentId.fromString(restApi.getBindingPath()), restApi);
    }

    public Map<ComponentId, RestApi> getRestApiMap() {
        return restApiGroup.getComponentMap();
    }


    public Map<ComponentId, Servlet> getServletMap() {
        return servletGroup.getComponentMap();
    }

    public final void addServlet(Servlet servlet) {
        servletGroup.addComponent(servlet.getGlobalComponentId(), servlet);
    }

    // Returns all servlets, including rest-api/jersey servlets.
    public Collection<Servlet> getAllServlets() {
        return allServlets().collect(Collectors.toCollection(ArrayList::new));
    }

    private Stream<Servlet> allServlets() {
        return Stream.concat(allJersey2Servlets(),
                             servletGroup.getComponents().stream());
    }

    private Stream<Jersey2Servlet> allJersey2Servlets() {
        return restApiGroup.getComponents().stream().map(RestApi::getJersey2Servlet);
    }

    @Override
    public void getConfig(BundlesConfig.Builder builder) {
        applicationBundles.stream().map(FileReference::value)
                .forEach(builder::bundle);
        super.getConfig(builder);
    }

    @Override
    public void getConfig(ServletPathsConfig.Builder builder) {
        allServlets().forEach(servlet ->
                                      builder.servlets(servlet.getComponentId().stringValue(),
                                                       servlet.toConfigBuilder())
        );
    }

    @Override
    public void getConfig(RankProfilesConfig.Builder builder) {
        if (modelEvaluation != null) modelEvaluation.getConfig(builder);
    }

    @Override
    public void getConfig(RankingConstantsConfig.Builder builder) {
        if (modelEvaluation != null) modelEvaluation.getConfig(builder);
    }

    @Override
    public void getConfig(ContainerMbusConfig.Builder builder) {
        if (mbusParams != null) {
            if (mbusParams.maxConcurrentFactor != null)
                builder.maxConcurrentFactor(mbusParams.maxConcurrentFactor);
            if (mbusParams.documentExpansionFactor != null)
                builder.documentExpansionFactor(mbusParams.documentExpansionFactor);
            if (mbusParams.containerCoreMemory != null)
                builder.containerCoreMemory(mbusParams.containerCoreMemory);
        }
        if (getDocproc() != null)
            getDocproc().getConfig(builder);
    }

    @Override
    public void getConfig(QrStartConfig.Builder builder) {
        super.getConfig(builder);
        builder.jvm.verbosegc(true)
                .availableProcessors(0)
                .minHeapsize(1536)
                .heapsize(1536);
        if (getMemoryPercentage().isPresent()) {
            builder.jvm.heapSizeAsPercentageOfPhysicalMemory(getMemoryPercentage().get());
        } else if (isHostedVespa()) {
            builder.jvm.heapSizeAsPercentageOfPhysicalMemory(getHostClusterId().isPresent() ? 17 : 60);
        }
    }

    public Optional<TlsSecrets> getTlsSecrets() {
        return tlsSecrets;
    }

    public Optional<String> getTlsClientAuthority() {
        return tlsClientAuthority;
    }

    public void setMbusParams(MbusParams mbusParams) {
        this.mbusParams = mbusParams;
    }

    public final void setMessageBusEnabled(boolean messageBusEnabled) { this.messageBusEnabled = messageBusEnabled; }

    protected boolean messageBusEnabled() { return messageBusEnabled; }

    public void addMbusServer(ComponentId chainId) {
        ComponentId serviceId = chainId.nestInNamespace(ComponentId.fromString("MbusServer"));

        addComponent(
                new Component<>(new ComponentModel(new BundleInstantiationSpecification(
                        serviceId,
                        ComponentSpecification.fromString(MbusServerProvider.class.getName()),
                        null))));
    }

    public static class MbusParams {
        // the amount of the maxpendingbytes to process concurrently, typically 0.2 (20%)
        final Double maxConcurrentFactor;

        // the amount that documents expand temporarily when processing them
        final Double documentExpansionFactor;

        // the space to reserve for container, docproc stuff (memory that cannot be used for processing documents), in MB
        final Integer containerCoreMemory;

        public MbusParams(Double maxConcurrentFactor, Double documentExpansionFactor, Integer containerCoreMemory) {
            this.maxConcurrentFactor = maxConcurrentFactor;
            this.documentExpansionFactor = documentExpansionFactor;
            this.containerCoreMemory = containerCoreMemory;
        }
    }
}
