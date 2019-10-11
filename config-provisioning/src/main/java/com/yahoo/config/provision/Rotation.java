// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.config.provision;

import java.util.Objects;

/**
 * A rotation (virtual endpoint).
 */
public class Rotation {

    private final String id;

    public Rotation(String id) {
        this.id = Objects.requireNonNull(id, "Rotation id cannot be null");
    }

    public String getId() {
        return id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Rotation)) {
            return false;
        }
        final Rotation that = (Rotation) o;
        return (this.id.equals(that.id));
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return "rotation '" + id + "'";
    }

}
