// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.config.server;

import com.yahoo.path.Path;
import com.yahoo.transaction.AbstractTransaction;
import com.yahoo.transaction.Transaction;
import com.yahoo.vespa.config.GenerationCounter;
import com.yahoo.vespa.curator.recipes.CuratorCounter;
import com.yahoo.vespa.curator.Curator;

/**
 * Distributed global generation counter for the super model.
 *
 * @author Ulf Lilleengen
 * @since 5.9
 */
public class SuperModelGenerationCounter implements GenerationCounter {

    private static final Path counterPath = Path.fromString("/config/v2/RPC/superModelGeneration");
    private final CuratorCounter counter;

    public SuperModelGenerationCounter(Curator curator) {
        this.counter =  new CuratorCounter(curator, counterPath.getAbsolute());
    }

    /**
     * Increment counter and return next value. This method is thread safe and provides an atomic value
     * across zookeeper clusters.
     *
     * @return incremented counter value.
     */
    public synchronized long increment() {
        return counter.next();
    }

    /**
     * @return current counter value.
     */
    public synchronized long get() {
        return counter.get();
    }

}
