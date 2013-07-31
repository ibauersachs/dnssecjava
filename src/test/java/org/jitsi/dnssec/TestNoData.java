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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestNoData extends TestBase {
    @Test
    public void testFakedNoDataNsec3WithoutNsecs() throws IOException {
        Message m = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
        Message message = messageFromString(m.toString().replaceAll("www\\.nsec3\\.ingotronic\\.ch\\.\\s+.*", ""));
        add("www.nsec3.ingotronic.ch./A", message);

        Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertTrue(getReason(response).startsWith("failed.nodata"));
    }

    @Test
    public void testFakedNoDataNsec3WithNsecs() throws IOException {
        Message m = resolver.send(createMessage("www.nsec3.ingotronic.ch./MX"));
        Message message = messageFromString(m.toString().replaceAll("type = MX", "type = A"));
        add("www.nsec3.ingotronic.ch./A", message);

        Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertTrue(getReason(response).startsWith("failed.nodata"));
    }
}
