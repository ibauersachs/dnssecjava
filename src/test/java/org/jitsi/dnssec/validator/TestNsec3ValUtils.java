/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2015 Ingo Bauersachs
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

package org.jitsi.dnssec.validator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;

import org.jitsi.dnssec.AlwaysOffline;
import org.jitsi.dnssec.TestBase;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;

@RunWith(PowerMockRunner.class)
@PrepareForTest({NSEC3ValUtils.class})
public class TestNsec3ValUtils extends TestBase {
    @Test(expected = IllegalArgumentException.class)
    public void testTooLargeIterationCountMustThrow() {
        Properties config = new Properties();
        config.put("org.jitsi.dnssec.nsec3.iterations.512", Integer.MAX_VALUE);
        NSEC3ValUtils val = new NSEC3ValUtils();
        val.init(config);
    }

    @Test
    public void testInvalidIterationCountMarksInsecure() throws IOException {
        Properties config = new Properties();
        config.put("org.jitsi.dnssec.nsec3.iterations.1024", 0);
        config.put("org.jitsi.dnssec.nsec3.iterations.2048", 0);
        config.put("org.jitsi.dnssec.nsec3.iterations.4096", 0);
        resolver.init(config);

        Message response = resolver.send(createMessage("www.wc.nsec3.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertEquals("failed.nsec3_ignored", getReason(response));
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
    public void testNsecEcdsa256() throws IOException {
        Provider[] providers = Security.getProviders("KeyFactory.EC");
        Assume.assumeTrue(providers != null && providers.length > 0);

        Message response = resolver.send(createMessage("www.wc.nsec3-ecdsa256.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testNsecEcdsa384() throws IOException {
        Provider[] providers = Security.getProviders("KeyFactory.EC");
        Assume.assumeTrue(providers != null && providers.length > 0);

        Message response = resolver.send(createMessage("www.wc.nsec3-ecdsa384.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }
}
