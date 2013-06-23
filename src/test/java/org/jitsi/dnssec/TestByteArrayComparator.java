/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (C) 2013 Ingo Bauersachs. All rights reserved.
 *
 * This file is part of dnssecjava.
 *
 * Dnssecjava is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dnssecjava is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with dnssecjava.  If not, see <http://www.gnu.org/licenses/>.
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
