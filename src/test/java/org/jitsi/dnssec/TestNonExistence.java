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
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Section;

public class TestNonExistence extends TestBase {
    @Test
    public void testNonExistingBelowRoot() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testSingleLabelABelowSigned() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testSingleLabelABelowSignedNsec3() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht.nsec3.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testDoubleLabelABelowSigned() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testDoubleLabelABelowSignedNsec3() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testSingleLabelMXBelowSignedForExistingA() throws IOException {
        Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testSingleLabelMXBelowSignedForExistingANsec3() throws IOException {
        Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testDoubleLabelMXBelowSignedForExistingA() throws IOException {
        // a.b.ingotronic.ch./A exists
        Message response = resolver.send(createMessage("a.b.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testDoubleLabelMXBelowSignedForExistingANsec3() throws IOException {
        // a.b.nsec3.ingotronic.ch./A exists
        Message response = resolver.send(createMessage("a.b.nsec3.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testDoubleLabelMXBelowSignedForExistingWildcardA() throws IOException {
        // *.d.ingotronic.ch./A exists
        Message response = resolver.send(createMessage("b.d.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testDoubleLabelMXBelowSignedForExistingWildcardANsec3() throws IOException {
        // *.d.nsec3.ingotronic.ch./A exists
        Message response = resolver.send(createMessage("b.d.nsec3.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testNxDomainWithInvalidNsecSignature() throws IOException {
        Message m = resolver.send(createMessage("x.ingotronic.ch./A"));
        Message message = messageFromString(m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
        add("x.ingotronic.ch./A", message);

        Message response = resolver.send(createMessage("x.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testNoDataWithInvalidNsecSignature() throws IOException {
        Message m = resolver.send(createMessage("www.ingotronic.ch./MX"));
        Message message = messageFromString(m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
        add("www.ingotronic.ch./MX", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }
}
