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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;

public class TestPositive extends TestBase {
    @Test
    public void testValidExising() throws IOException {
        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertEquals(localhost, firstA(response));
        assertNull(getReason(response));
    }

    @Test
    public void testValidNonExising() throws IOException {
        Message response = resolver.send(createMessage("ingotronic.ch./ANY"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }

    @Test
    public void testValidAnswerToDifferentQueryTypeIsBogus() throws IOException {
        Message m = resolver.send(createMessage("www.ingotronic.ch./A"));
        Message message = createMessage("www.ingotronic.ch./MX");
        for (int i = 1; i < Section.ADDITIONAL; i++) {
            for (Record r: m.getSection(i)) {
                message.addRecord(r, i);
            }
        }

        add("www.ingotronic.ch./A", message);
        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.response.unknown:UNKNOWN", getReason(response));
    }

    @Test
    public void testCDonQueryDoesntDoAnything() throws IOException {
        Message m = resolver.send(createMessage("www.ingotronic.ch./A"));
        Message message = messageFromString(m.toString().replaceAll("(.*\\sRRSIG\\s+A\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
        add("www.ingotronic.ch./A", message);

        Message query = createMessage("www.ingotronic.ch./A");
        query.getHeader().setFlag(Flags.CD);
        Message response = resolver.send(query);
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }
}
