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
            for (Record r: m.getSectionArray(i)) {
                message.addRecord(r, i);
            }
        }

        add("www.ingotronic.ch./A", message);
        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("validate.response.unknown:UNKNOWN", getReason(response));
    }
}
