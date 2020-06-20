// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.config.server.session;

import com.yahoo.cloud.config.ConfigserverConfig;
import com.yahoo.vespa.config.server.filedistribution.FileDistributionFactory;
import com.yahoo.vespa.config.server.filedistribution.MockFileDistributionProvider;

import java.io.File;

/**
* @author Ulf Lilleengen
*/
public class MockFileDistributionFactory extends FileDistributionFactory {

    public final MockFileDistributionProvider mockFileDistributionProvider;

    public MockFileDistributionFactory(ConfigserverConfig configserverConfig) {
        super(configserverConfig);
        mockFileDistributionProvider = new MockFileDistributionProvider(new File(configserverConfig.fileReferencesDir()));
    }

    @Override
    public com.yahoo.vespa.config.server.filedistribution.FileDistributionProvider createProvider(File applicationFile) {
        return mockFileDistributionProvider;
    }
}
