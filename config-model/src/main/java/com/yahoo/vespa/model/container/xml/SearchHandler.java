// Copyright Verizon Media. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.model.container.xml;

import com.yahoo.config.model.deploy.DeployState;
import com.yahoo.container.handler.threadpool.ContainerThreadpoolConfig;
import com.yahoo.vespa.model.container.ApplicationContainerCluster;
import com.yahoo.vespa.model.container.ContainerThreadpoolComponent;
import com.yahoo.vespa.model.container.component.BindingPattern;
import com.yahoo.vespa.model.container.component.SystemBindingPattern;
import com.yahoo.vespa.model.container.component.chain.ProcessingHandler;
import com.yahoo.vespa.model.container.search.searchchain.SearchChains;

import java.util.List;

/**
 * Component definition for {@link com.yahoo.search.handler.SearchHandler}
 *
 * @author bjorncs
 */
class SearchHandler extends ProcessingHandler<SearchChains> {

    static final String HANDLER_CLASS = com.yahoo.search.handler.SearchHandler.class.getName();
    static final BindingPattern DEFAULT_BINDING = SystemBindingPattern.fromHttpPath("/search/*");

    private final ApplicationContainerCluster cluster;

    SearchHandler(ApplicationContainerCluster cluster, List<BindingPattern> bindings, DeployState deployState) {
        super(cluster.getSearchChains(), HANDLER_CLASS);
        this.cluster = cluster;
        bindings.forEach(this::addServerBindings);
        Threadpool threadpool = new Threadpool(cluster, deployState);
        inject(threadpool);
        addComponent(threadpool);
    }

    private static class Threadpool extends ContainerThreadpoolComponent {
        private final ApplicationContainerCluster cluster;
        private final DeployState deployState;

        Threadpool(ApplicationContainerCluster cluster, DeployState deployState) {
            super("search-handler");
            this.cluster = cluster;
            this.deployState = deployState;
        }

        @Override
        public void getConfig(ContainerThreadpoolConfig.Builder builder) {
            super.getConfig(builder);

            builder.maxThreadExecutionTimeSeconds(190);
            builder.keepAliveTime(5.0);

            double threadPoolSizeFactor = deployState.getProperties().threadPoolSizeFactor();
            double vcpu = vcpu(cluster);
            if (threadPoolSizeFactor <= 0 || vcpu == 0) {
                builder.maxThreads(500);
                builder.minThreads(500);
                builder.queueSize(0);
            } else {
                // Controls max number of concurrent requests per container
                int workerThreads = Math.max(2, (int)Math.ceil(vcpu * threadPoolSizeFactor));
                builder.maxThreads(workerThreads);
                builder.minThreads(workerThreads);

                // This controls your burst handling capability.
                // 0 => No extra burst handling beyond you max concurrent requests (maxthreads).
                // N => N times max concurrent requests as a buffer for handling bursts
                builder.queueSize((int)(workerThreads * deployState.getProperties().queueSizeFactor()));
            }
        }


    }
}
