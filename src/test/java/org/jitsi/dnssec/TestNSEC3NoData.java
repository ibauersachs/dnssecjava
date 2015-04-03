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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;

public class TestNSEC3NoData extends TestBase {
    @Test
    @AlwaysOffline
    public void testNodataButHasCname() throws IOException {
        Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./MX"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertTrue(getReason(response).startsWith("failed.nodata"));
    }

    @Test
    @AlwaysOffline
    public void testNodataApexNsec3Abused() throws IOException {
        // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the nsec3.ingotronic.ch.
        // then return NODATA for the following query, "proofed" by the NSEC3 from the parent
        Message response = resolver.send(createMessage("sub.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertTrue(getReason(response).startsWith("failed.nodata"));
    }

    @Test
    @AlwaysOffline
    public void testNodataApexNsec3ProofInsecureDelegation() throws IOException {
        // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the nsec3.ingotronic.ch. zone
        // then return NODATA for the following query, "proofed" by the NSEC3 from the parent
        // which has the DS flag removed, effectively making the reply insecure
        Message response = resolver.send(createMessage("sub.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }

    @Test
    @AlwaysOffline
    public void testNodataApexNsec3WithSOAValid() throws IOException {
        // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the nsec3.ingotronic.ch.
        // then return NODATA for the following query, "proofed" by the NSEC3 from the parent
        Message response = resolver.send(createMessage("sub.nsec3.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }

    @Test
    @AlwaysOffline
    public void testNodataApexNsec3AbusedForNoDS() throws IOException {
        // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the sub.nsec3.ingotronic.ch.
        // then return NODATA for the following query, "proofed" by the NSEC3 from the child
        Message response = resolver.send(createMessage("sub.nsec3.ingotronic.ch./DS"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertTrue(getReason(response).startsWith("failed.nodata"));
    }

    @Test
    @AlwaysOffline
    public void testNoDSProofCanExistForRoot() throws IOException {
        // ./DS can exist
        resolver.getTrustAnchors().clear();
        resolver.getTrustAnchors().store(new SRRset(new RRset(toRecord(".           300 IN  DS  16758 7 1 EC88DF5E2902FD4AB9E9C246BEEA9B822BD7BCF7"))));
        Message response = resolver.send(createMessage("./DS"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }

    @Test
    @AlwaysOffline
    public void testNodataNsec3ForDSMustNotHaveSOA() throws IOException {
        // bogus./DS cannot coexist with bogus./SOA
        resolver.getTrustAnchors().clear();
        resolver.getTrustAnchors().store(new SRRset(new RRset(toRecord("bogus.           300 IN  DS  16758 7 1 A5D56841416AB42DC39629E42D12C98B0E94232A"))));
        Message response = resolver.send(createMessage("bogus./DS"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }

    @Test
    @AlwaysOffline
    public void testNsec3ClosestEncloserIsInsecureDelegation() throws IOException {
        Message response = resolver.send(createMessage("a.unsigned.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }

    @Test
    @AlwaysOffline
    public void testNsec3ClosestEncloserIsInsecureDelegationDS() throws IOException {
        //rfc5155#section-7.2.4
        //response does not contain next closer NSEC3, thus bogus
        Message response = resolver.send(createMessage("a.unsigned.nsec3.ingotronic.ch./DS"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertTrue(getReason(response).startsWith("failed.nodata"));
    }
}
