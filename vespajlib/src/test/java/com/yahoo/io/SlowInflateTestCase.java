// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.io;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.zip.Deflater;

import org.junit.Before;
import org.junit.Test;

import com.yahoo.text.Utf8;

/**
 * Check decompressor used among other things for packed summary fields.
 *
 * @author <a href="mailto:steinar@yahoo-inc.com">Steinar Knutsen</a>
 */
public class SlowInflateTestCase {

    private String value;
    private byte[] raw;
    private byte[] output;
    private byte[] compressed;
    private int compressedDataLength;

    @Before
    public void setUp() throws Exception {
        value = "000000000000000000000000000000000000000000000000000000000000000";
        raw = Utf8.toBytesStd(value);
        output = new byte[raw.length * 2];
        Deflater compresser = new Deflater();
        compresser.setInput(raw);
        compresser.finish();
        compressedDataLength = compresser.deflate(output);
        compresser.end();
        compressed = Arrays.copyOf(output, compressedDataLength);
    }

    @Test
    public final void test() {
        byte[] unpacked = new SlowInflate().unpack(compressed, raw.length);
        assertArrayEquals(raw, unpacked);
    }

    @Test
    public final void testCorruptData() {
        compressed[0] = (byte) (compressed[0] ^ compressed[1]);
        compressed[1] = (byte) (compressed[1] ^ compressed[2]);
        compressed[2] = (byte) (compressed[2] ^ compressed[3]);
        compressed[3] = (byte) (compressed[3] ^ compressed[4]);
        boolean caught = false;
        try {
            new SlowInflate().unpack(compressed, raw.length);
        } catch (RuntimeException e) {
            caught = true;
        }
        assertTrue(caught);
    }

}
