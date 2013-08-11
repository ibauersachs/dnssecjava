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

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestRRsig extends TestBase {
    @Test
    public void testRRsigNodata() throws IOException {
        Message message = createMessage("www.ingotronic.ch./RRSIG");
        add("www.ingotronic.ch./RRSIG", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./RRSIG"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nodata", getReason(response));
    }

    @Test
    public void testRRsigServfail() throws IOException {
        Message message = createMessage("www.ingotronic.ch./RRSIG");
        message.getHeader().setRcode(Rcode.SERVFAIL);
        add("www.ingotronic.ch./RRSIG", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./RRSIG"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nodata", getReason(response));
    }
}
