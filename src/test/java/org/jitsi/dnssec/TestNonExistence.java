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

import org.joda.time.DateTime;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base64;

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
        Message message = new Message();
        message.getHeader().setRcode(Rcode.NXDOMAIN);
        message.addRecord(Record.newRecord(Name.fromString("x.ingotronic.ch."), Type.A, DClass.IN), Section.QUESTION);

        // ingotronic.ch. 300 IN NSEC alias.ingotronic.ch. A NS SOA RRSIG NSEC DNSKEY TYPE65534
        message.addRecord(new NSECRecord(Name.fromString("ingotronic.ch."), DClass.IN, 300, Name.fromString("alias.ingotronic.ch."), new int[] { Type.A,
                Type.NS, Type.SOA, Type.RRSIG, Type.NSEC, Type.DNSKEY, 65534 }), Section.AUTHORITY);
        // ingotronic.ch. 300 IN RRSIG NSEC 5 2 300 20130609091347 20130510090432 17430 ingotronic.ch. UiFF0yQlyUG9R+4pM7ou55BeopogqsqULK/MTxmSltTNUY7yNO3VB62us/2b7xxn29DpIa95oYynt1yG9t2ReqN8k+zdIL9HjP7dpMD9PN3KE0NTXcTAl+XuKv9cjuVHCK6ZNsJzyum2/5CD5zc6VfpnhiLBIIqxmBw4yBbzy4A=
        message.addRecord(
                new RRSIGRecord(
                        Name.fromString("ingotronic.ch."),
                        DClass.IN,
                        300,
                        Type.NSEC,
                        5,
                        300,
                        DateTime.parse("2013-06-09T09:13:47Z").toDate(),
                        DateTime.parse("2013-05-10T09:04:32Z").toDate(),
                        17430,
                        Name.fromString("ingotronic.ch."),
                        base64.fromString("AiFF0yQlyUG9R+4pM7ou55BeopogqsqULK/MTxmSltTNUY7yNO3VB62us/2b7xxn29DpIa95oYynt1yG9t2ReqN8k+zdIL9HjP7dpMD9PN3KE0NTXcTAl+XuKv9cjuVHCK6ZNsJzyum2/5CD5zc6VfpnhiLBIIqxmBw4yBbzy4A=")),
                Section.AUTHORITY);

        // www.ingotronic.ch.   300 IN  NSEC    ingotronic.ch. A AAAA RRSIG NSEC
        message.addRecord(new NSECRecord(Name.fromString("www.ingotronic.ch."), DClass.IN, 300, Name.fromString("ingotronic.ch."), new int[] { Type.A,
                Type.AAAA, Type.RRSIG, Type.NSEC }), Section.AUTHORITY);
        // www.ingotronic.ch.   300 IN  RRSIG   NSEC 5 3 300 20130609091347 20130510090432 17430 ingotronic.ch. X+s3QZZMbIxSQglhBrwqzUV70x4usqNhICuIFrPFkvx1zg8cinm3lbQYymkDKz2bEUGz40DV4lv5024ZboVD5fD8up5UkZbYcvxJijkW6MjA0vBB01PIQ+MMqIWbwUcaj2mBdo+qqIIrmJ1w6ED80MBhzGAUtnNvNpXUzo8dqqE=
        message.addRecord(
                new RRSIGRecord(
                        Name.fromString("www.ingotronic.ch."),
                        DClass.IN,
                        300,
                        Type.NSEC,
                        5,
                        300,
                        DateTime.parse("2013-06-09T09:13:47Z").toDate(),
                        DateTime.parse("2013-05-10T09:04:32Z").toDate(),
                        17430,
                        Name.fromString("ingotronic.ch."),
                        base64.fromString("X+s3QZZMbIxSQglhBrwqzUV70x4usqNhICuIFrPFkvx1zg8cinm3lbQYymkDKz2bEUGz40DV4lv5024ZboVD5fD8up5UkZbYcvxJijkW6MjA0vBB01PIQ+MMqIWbwUcaj2mBdo+qqIIrmJ1w6ED80MBhzGAUtnNvNpXUzo8dqqE=")),
                Section.AUTHORITY);

        add("x.ingotronic.ch./A", message);

        Message response = resolver.send(createMessage("x.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testNoDataWithInvalidNsecSignature() throws IOException {
        Message message = new Message();
        message.getHeader().setRcode(Rcode.NOERROR);
        message.addRecord(Record.newRecord(Name.fromString("www.ingotronic.ch."), Type.MX, DClass.IN), Section.QUESTION);

        // www.ingotronic.ch.   300 IN  NSEC    ingotronic.ch. A AAAA RRSIG NSEC
        message.addRecord(new NSECRecord(Name.fromString("www.ingotronic.ch."), DClass.IN, 300, Name.fromString("ingotronic.ch."), new int[] { Type.A,
                Type.AAAA, Type.RRSIG, Type.NSEC }), Section.AUTHORITY);
        // www.ingotronic.ch.   300 IN  RRSIG   NSEC 5 3 300 20130609091347 20130510090432 17430 ingotronic.ch. X+s3QZZMbIxSQglhBrwqzUV70x4usqNhICuIFrPFkvx1zg8cinm3lbQYymkDKz2bEUGz40DV4lv5024ZboVD5fD8up5UkZbYcvxJijkW6MjA0vBB01PIQ+MMqIWbwUcaj2mBdo+qqIIrmJ1w6ED80MBhzGAUtnNvNpXUzo8dqqE=
        message.addRecord(
                new RRSIGRecord(
                        Name.fromString("www.ingotronic.ch."),
                        DClass.IN,
                        300,
                        Type.NSEC,
                        5,
                        300,
                        DateTime.parse("2013-06-09T09:13:47Z").toDate(),
                        DateTime.parse("2013-05-10T09:04:32Z").toDate(),
                        17430,
                        Name.fromString("ingotronic.ch."),
                        base64.fromString("Y+s3QZZMbIxSQglhBrwqzUV70x4usqNhICuIFrPFkvx1zg8cinm3lbQYymkDKz2bEUGz40DV4lv5024ZboVD5fD8up5UkZbYcvxJijkW6MjA0vBB01PIQ+MMqIWbwUcaj2mBdo+qqIIrmJ1w6ED80MBhzGAUtnNvNpXUzo8dqqE=")),
                Section.AUTHORITY);

        add("www.ingotronic.ch./MX", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }
}
