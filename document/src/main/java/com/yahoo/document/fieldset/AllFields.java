// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.document.fieldset;

/**
 * Created with IntelliJ IDEA.
 * User: thomasg
 * Date: 4/25/12
 * Time: 3:18 PM
 * To change this template use File | Settings | File Templates.
 */
public class AllFields implements FieldSet {
    @Override
    public boolean contains(FieldSet o) {
        return true;
    }

    @Override
    public FieldSet clone() {
        return new AllFields();
    }
}
