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

 package org.jitsi;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Date;

import org.junit.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class TestInvalid extends TestBase {
    @Test
    public void testUnknownAlg() throws IOException {
        Message response = resolver.send(createMessage("unknownalgorithm.dnssec.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testSigNotIncepted() throws IOException {
        Message response = resolver.send(createMessage("signotincepted.dnssec.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testSigExpired() throws IOException {
        Message response = resolver.send(createMessage("sigexpired.dnssec.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testBogusSig() throws IOException {
        Message response = resolver.send(createMessage("bogussig.dnssec.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testSignedBelowUnsignedBelowSigned() throws IOException {
        Message response = resolver.send(createMessage("ok.nods.ok.dnssec.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertFalse(isEmptyAnswer(response));
    }

    @Test
    public void testUnknownAlgNsec3() throws IOException {
        Message response = resolver.send(createMessage("unknownalgorithm.Nsec3.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

//    @Test  disabled, the signature is actually valid
//    public void testSigNotInceptedNsec3() throws IOException {
//        Message response = resolver.send(createMessage("signotincepted.Nsec3.tjeb.nl./A"));
//        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
//        assertEquals(Rcode.SERVFAIL, response.getRcode());
//    }

    @Test
    public void testSigExpiredNsec3() throws IOException {
        Message response = resolver.send(createMessage("sigexpired.Nsec3.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testBogusSigNsec3() throws IOException {
        Message response = resolver.send(createMessage("bogussig.Nsec3.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testSignedBelowUnsignedBelowSignedNsec3() throws IOException {
        Message response = resolver.send(createMessage("ok.nods.ok.Nsec3.tjeb.nl./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertFalse(isEmptyAnswer(response));
    }

    @Test
    public void testUnsignedThatMustBeSigned() throws IOException {
        Name query = Name.fromString("www.ingotronic.ch.");

        // prepare a faked, unsigned response message that must have a signature
        // to be valid
        Message message = new Message();
        message.addRecord(Record.newRecord(query, Type.A, DClass.IN), Section.QUESTION);
        message.addRecord(new ARecord(query, Type.A, DClass.IN, InetAddress.getByName(localhost)), Section.ANSWER);
        add("www.ingotronic.ch./A", toHex(message.toWire()));

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testModifiedSignature() throws IOException {
        Name query = Name.fromString("www.ingotronic.ch.");

        // prepare a faked, unsigned response message that must have a signature
        // to be valid
        Message message = new Message();
        message.addRecord(Record.newRecord(query, Type.A, DClass.IN), Section.QUESTION);
        message.addRecord(new ARecord(query, Type.A, DClass.IN, InetAddress.getByName(localhost)), Section.ANSWER);
        message.addRecord(new RRSIGRecord(query, DClass.IN, 0, Type.A, Algorithm.RSASHA256, 5, new Date(System.currentTimeMillis() + 5000), new Date(System.currentTimeMillis() - 5000), 1234, Name.fromString("ingotronic.ch."), new byte[] { 1, 2, 3 }), Section.ANSWER);
        add("www.ingotronic.ch./A", toHex(message.toWire()));

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }
}
