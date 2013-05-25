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

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class TestCNames extends TestBase {
    @Test
    public void testCNameToUnsigned() throws IOException {
        Message response = resolver.send(createMessage("cunsinged.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testCNameToSigned() throws IOException {
        Message response = resolver.send(createMessage("csigned.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testCNameToInvalidSigned() throws IOException {
        Message response = resolver.send(createMessage("cfailed.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testCNameToUnsignedNsec3() throws IOException {
        Message response = resolver.send(createMessage("cunsinged.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testCNameToSignedNsec3() throws IOException {
        Message response = resolver.send(createMessage("csigned.nsec3.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testCNameToInvalidSignedNsec3() throws IOException {
        Message response = resolver.send(createMessage("cfailed.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testCNameToVoid3Chain() throws IOException {
        Message response = resolver.send(createMessage("cvoid3.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testCNameToVoid2Chain() throws IOException {
        Message response = resolver.send(createMessage("cvoid2.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testCNameToVoid() throws IOException {
        Message response = resolver.send(createMessage("cvoid1.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testCNameToUnsignedVoid() throws IOException {
        Message response = resolver.send(createMessage("cvoid4.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testCNameToExternalUnsignedVoid() throws IOException {
        Message response = resolver.send(createMessage("cvoid.dnssectest.jitsi.net./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testCNameToExternalReturnsServfailIfIntermediateFails() throws IOException {
        Message m = new Message();
        m.getHeader().setRcode(Rcode.NOTAUTH);
        m.addRecord(Record.newRecord(Name.fromString("gibtsnicht.ingotronic.ch."), Type.CNAME, DClass.IN), Section.QUESTION);
        add("gibtsnicht.ingotronic.ch./CNAME", m);

        Message response = resolver.send(createMessage("cvoid1.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testCNameToVoidExternalInvalidTld() throws IOException {
        Message response = resolver.send(createMessage("cvoidext1.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testCNameToVoidExternalValidTld() throws IOException {
        Message response = resolver.send(createMessage("cvoidext2.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testCNameToVoidNsec3() throws IOException {
        Message response = resolver.send(createMessage("cvoid.nsec3.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }
}
