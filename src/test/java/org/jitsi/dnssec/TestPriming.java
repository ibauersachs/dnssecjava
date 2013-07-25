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

import java.io.IOException;

import mockit.Mock;
import mockit.MockUp;
import mockit.Mocked;
import mockit.NonStrictExpectations;

import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

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
    public void testDnskeyPrimeResponseWithMismatchedFootprintIsBad() throws IOException, NumberFormatException, DNSSECException {
        new NonStrictExpectations() {
            @Mocked({ "getFootprint()" })
            DNSKEYRecord mock;

            {
                mock.getFootprint();
                result = -1;
            }
        };

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    }

    @Test
    public void testDnskeyPrimeResponseWithMismatchedAlgorithmIsBad() throws IOException, NumberFormatException, DNSSECException {
        new NonStrictExpectations() {
            @Mocked({ "getAlgorithm()" })
            DNSKEYRecord mock;

            {
                mock.getAlgorithm();
                result = -1;
            }
        };

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    }

    @Test
    public void testDnskeyPrimeResponseWithWeirdHashIsBad() throws IOException, NumberFormatException, DNSSECException {
        new MockUp<DNSSEC>() {
            @Mock
            public byte[] generateDSDigest(DNSKEYRecord key, int digestid) {
                return new byte[] { 1, 2, 3 };
            }
        };

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
        assertEquals("validate.bogus.badkey:ch.:failed.ds.unknown", getReason(response));
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
        assertEquals("validate.bogus.badkey:ch.:failed.ds.unknown", getReason(response));
    }
}
