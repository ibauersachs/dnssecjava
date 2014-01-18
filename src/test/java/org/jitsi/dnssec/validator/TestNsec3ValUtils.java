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

package org.jitsi.dnssec.validator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.PublicKey;
import java.util.Properties;

import mockit.Invocation;
import mockit.Mock;
import mockit.MockUp;

import org.jitsi.dnssec.AlwaysOffline;
import org.jitsi.dnssec.TestBase;
import org.junit.Test;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;

public class TestNsec3ValUtils extends TestBase {
    @Test(expected = IllegalArgumentException.class)
    public void testTooLargeIterationCountMustThrow() {
        Properties config = new Properties();
        config.put("org.jitsi.dnssec.nsec3.iterations.512", Integer.MAX_VALUE);
        NSEC3ValUtils val = new NSEC3ValUtils();
        val.init(config);
    }

    @Test
    public void testNsec3WithoutClosestEncloser() throws IOException {
        Message m = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
        Message message = messageFromString(m.toString().replaceAll("((UDUMPS9J6F8348HFHH2FAED6I9DDE0U6)|(NTV3QJT4VQDVBPB6BNOVM40NMKJ3H29P))\\.nsec3.*", ""));
        add("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A", message);

        Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
    }

    @Test
    public void testNsec3NodataChangedToNxdomainIsBogus() throws IOException {
        Message m = resolver.send(createMessage("a.b.nsec3.ingotronic.ch./MX"));
        Message message = messageFromString(m.toString().replaceAll("status: NOERROR", "status: NXDOMAIN"));
        add("a.b.nsec3.ingotronic.ch./A", message);

        Message response = resolver.send(createMessage("a.b.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
    }

    @Test
    public void testNsec3ClosestEncloserIsDelegation() throws IOException {
        // hash(n=9.nsec3.ingotronic.ch.,it=10,s=1234)=6jl2t4i2bb7eilloi8mdhbf3uqjgvu4s
        Message cem = resolver.send(createMessage("9.nsec3.ingotronic.ch./A"));
        Record delegationNsec = null;
        Record delegationNsecSig = null;
        for (RRset set : cem.getSectionRRsets(Section.AUTHORITY)) {
            // hash(n=sub.nsec3.ingotronic.ch.,it=10,s=1234)=5RFQOLI81S6LKQTUG5HLI19UVJNKUL3H
            if (set.getName().toString().startsWith("5RFQOLI81S6LKQTUG5HLI19UVJNKUL3H")) {
                delegationNsec = set.first();
                delegationNsecSig = (Record)set.sigs().next();
                break;
            }
        }

        Message m = resolver.send(createMessage("a.sub.nsec3.ingotronic.ch./A"));
        String temp = m.toString().replaceAll("^sub\\.nsec3.*", "");
        // hash(n=sub.nsec3.ingotronic.ch.,it=11,s=4321)=8N8QLBCUIH7R2BG7DMCJ5AEE63K4KVUA
        temp = temp.replaceAll("8N8QLBCUIH7R2BG7DMCJ5AEE63K4KVUA.*", "");
        Message message = messageFromString(temp);
        message.addRecord(delegationNsec, Section.AUTHORITY);
        message.addRecord(delegationNsecSig, Section.AUTHORITY);
        add("a.sub.nsec3.ingotronic.ch./A", message);

        Message response = resolver.send(createMessage("a.sub.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
    }

    @Test
    @AlwaysOffline
    public void testNsec3ClosestEncloserIsInsecureDelegation() throws IOException {
        Message response = resolver.send(createMessage("a.unsigned.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
        assertEquals("failed.nxdomain.nsec3_insecure", getReason(response));
    }

    @Test
    public void testPublicKeyLoadingException() throws IOException {
        new MockUp<DNSKEYRecord>() {
            @Mock
            public PublicKey getPublicKey(Invocation invocation) throws DNSSEC.DNSSECException {
                DNSKEYRecord dr = ((DNSKEYRecord)invocation.getInvokedInstance());

                if (dr.getName().equals(Name.fromConstantString("nsec3.ingotronic.ch.")) && invocation.getInvocationCount() == 11) {
                    DNSSEC.DNSSECException e = null;
                    try {
                        Constructor<?> c = DNSSEC.DNSSECException.class.getDeclaredConstructor(String.class);
                        c.setAccessible(true);
                        e = (DNSSEC.DNSSECException)c.newInstance("mock-test");
                    }
                    catch (Exception ex) {
                    }

                    throw e;
                }

                return dr.getPublicKey();
            }
        };

        Message response = resolver.send(createMessage("www.wc.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nsec3_ignored", getReason(response));
    }
}
