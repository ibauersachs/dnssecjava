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
import static org.junit.Assert.assertFalse;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

@RunWith(PowerMockRunner.class)
@PrepareForTest(DNSKEYRecord.class)
public class TestPriming extends TestBase {
    @Test
    public void testDnskeyPrimeResponseWithEmptyAnswerIsBad() throws IOException {
        Message message = new Message();
        message.addRecord(Record.newRecord(Name.root, Type.DNSKEY, DClass.IN), Section.QUESTION);
        add("./DNSKEY", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_rrset:.", getReason(response));
    }

    @Test
    public void testRootDnskeyPrimeResponseWithNxDomainIsBad() throws IOException {
        Message message = new Message();
        message.addRecord(Record.newRecord(Name.root, Type.DNSKEY, DClass.IN), Section.QUESTION);
        message.getHeader().setRcode(Rcode.NXDOMAIN);
        add("./DNSKEY", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_rrset:.", getReason(response));
    }

    @Test
    public void testDnskeyPrimeResponseWithInvalidSignatureIsBad() throws IOException, NumberFormatException, DNSSECException {
        Message m = resolver.send(createMessage("./DNSKEY"));
        Message message = messageFromString(m.toString().replaceAll("(.*\\sRRSIG\\sDNSKEY\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
        add("./DNSKEY", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    }

    @Test
    @PrepareMocks("prepareTestDnskeyPrimeResponseWithMismatchedFootprintIsBad")
    public void testDnskeyPrimeResponseWithMismatchedFootprintIsBad() throws Exception {
        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    }

    public void prepareTestDnskeyPrimeResponseWithMismatchedFootprintIsBad() throws Exception {
        DNSKEYRecord emptyDnskeyRecord = spy(Whitebox.invokeConstructor(DNSKEYRecord.class));
        when(emptyDnskeyRecord.getFootprint()).thenReturn(-1);
        whenNew(DNSKEYRecord.class).withNoArguments().thenReturn(emptyDnskeyRecord);
    }

    @Test
    @PrepareMocks("prepareTestDnskeyPrimeResponseWithMismatchedAlgorithmIsBad")
    public void testDnskeyPrimeResponseWithMismatchedAlgorithmIsBad() throws IOException, NumberFormatException, DNSSECException {
        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    }

    public void prepareTestDnskeyPrimeResponseWithMismatchedAlgorithmIsBad() throws Exception {
        DNSKEYRecord emptyDnskeyRecord = spy(Whitebox.invokeConstructor(DNSKEYRecord.class));
        when(emptyDnskeyRecord.getAlgorithm()).thenReturn(-1);
        whenNew(DNSKEYRecord.class).withNoArguments().thenReturn(emptyDnskeyRecord);
    }

    @Test
    public void testDnskeyPrimeResponseWithWeirdHashIsBad() throws Exception {
        spy(DNSSEC.class);
        doReturn(new byte[]{1, 2, 3}).when(DNSSEC.class, "generateDSDigest", any(DNSKEYRecord.class), anyInt());

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    }

    @Test
    public void testDsPrimeResponseWithEmptyAnswerIsBad() throws IOException {
        Message message = new Message();
        message.addRecord(Record.newRecord(Name.fromString("ch."), Type.DS, DClass.IN), Section.QUESTION);
        add("ch./DS", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:ch.:failed.ds.nonsec:ch.", getReason(response));
    }

    @Test
    public void testDsPrimeResponseWithNxDomainForTld() throws IOException {
        Message message = new Message();
        message.addRecord(Record.newRecord(Name.fromString("ch."), Type.DS, DClass.IN), Section.QUESTION);
        message.getHeader().setRcode(Rcode.NXDOMAIN);
        add("ch./DS", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:ch.:failed.ds.nonsec:ch.", getReason(response));
    }

    @Test
    public void testDsNoDataWhenNsecIsFromChildApex() throws IOException {
        Message nsec = resolver.send(createMessage("1.sub.ingotronic.ch./NSEC"));
        Record delegationNsec = null;
        Record delegationNsecSig = null;
        for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
            if (set.getName().toString().startsWith("sub.ingotronic.ch") && set.getType() == Type.NSEC) {
                delegationNsec = set.first();
                delegationNsecSig = (Record)set.sigs().next();
                break;
            }
        }

        Message m = createMessage("sub.ingotronic.ch./DS");
        m.getHeader().setRcode(Rcode.NOERROR);
        m.addRecord(delegationNsec, Section.AUTHORITY);
        m.addRecord(delegationNsecSig, Section.AUTHORITY);
        add("sub.ingotronic.ch./DS", m);

        Message response = resolver.send(createMessage("sub.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:sub.ingotronic.ch.:failed.ds.nsec", getReason(response));
    }

    @Test
    public void testDsNoDataWhenNsecOnEntIsBad() throws IOException {
        Message m = resolver.send(createMessage("e.ingotronic.ch./DS"));
        Message message = messageFromString(m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
        add("e.ingotronic.ch./DS", message);

        Message response = resolver.send(createMessage("a.e.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus:failed.ds.nsec.ent", getReason(response));
    }

    @Test
    public void testDsNoDataWhenOnInsecureDelegationWithWrongNsec() throws IOException {
        Message nsec = resolver.send(createMessage("alias.ingotronic.ch./NSEC"));
        Record delegationNsec = null;
        Record delegationNsecSig = null;
        for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
            if (set.getName().toString().startsWith("alias.ingotronic.ch") && set.getType() == Type.NSEC) {
                delegationNsec = set.first();
                delegationNsecSig = (Record)set.sigs().next();
                break;
            }
        }

        Message m = createMessage("unsigned.ingotronic.ch./DS");
        m.getHeader().setRcode(Rcode.NOERROR);
        m.addRecord(delegationNsec, Section.AUTHORITY);
        m.addRecord(delegationNsecSig, Section.AUTHORITY);
        add("unsigned.ingotronic.ch./DS", m);

        Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus:failed.ds.unknown", getReason(response));
    }
}
