/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2015 Ingo Bauersachs
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

package org.jitsi.dnssec;

import static org.junit.Assert.assertEquals;

import org.jitsi.dnssec.validator.ByteArrayComparator;
import org.junit.Test;

public class TestByteArrayComparator {
    private ByteArrayComparator c = new ByteArrayComparator();
    private byte[] b1 = new byte[] { 0 };
    private byte[] b2 = new byte[] { 0 };
    private byte[] b3 = new byte[] { 1 };
    private byte[] b4 = new byte[] { 1, 0 };

    @Test
    public void testEquals() {
        assertEquals(0, c.compare(b1, b2));
    }

    @Test
    public void testLessThan() {
        assertEquals(-1, c.compare(b2, b3));
        assertEquals(-1, c.compare(b1, b4));
    }

    @Test
    public void testGreaterThan() {
        assertEquals(1, c.compare(b3, b2));
        assertEquals(1, c.compare(b4, b1));
    }
}
