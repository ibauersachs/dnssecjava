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
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestPartiallyInvalid extends TestBase {
    @Test
    public void testValidExising() throws IOException {
        Message response = resolver.send(createMessage("www.partial.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertEquals(localhost, firstA(response));
    }

    @Test
    public void testValidExisingNoType() throws IOException {
        Message response = resolver.send(createMessage("www.partial.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertTrue(isEmptyAnswer(response));
    }

    @Test
    public void testValidNonExising() throws IOException {
        Message response = resolver.send(createMessage("www.gibtsnicht.partial.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }
}
