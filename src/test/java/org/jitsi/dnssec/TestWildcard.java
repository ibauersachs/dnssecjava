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

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestWildcard extends TestBase {
    @Test
    public void testNameNotExpandedFromWildcardWhenNonWildcardExists() throws IOException {
        // create a faked response: the original query/response was for
        // b.d.ingotronic.ch. and is changed to a.d.ingotronic.ch.
        Message m = resolver.send(createMessage("b.d.nsec3.ingotronic.ch./A"));
        add("a.d.ingotronic.ch./A", messageFromString(m.toString().replace("b.d.ingotronic.ch.", "a.d.ingotronic.ch.")));

        // a.d.ingotronic.ch./A exists, but the response is faked from *.d.ingotronic.ch. which must be detected by the NSEC proof
        Message response = resolver.send(createMessage("a.d.ingotronic.ch./A"));
        assertFalse(response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getHeader().getRcode());
    }

    @Test
    public void testNameNotExpandedFromWildcardWhenNonWildcardExistsNsec3() throws IOException {
        // create a faked response: the original query/response was for
        // b.d.nsec3.ingotronic.ch. and is changed to a.d.nsec3.ingotronic.ch.
        Message m = resolver.send(createMessage("b.d.nsec3.ingotronic.ch./A"));
        add("a.d.nsec3.ingotronic.ch./A", messageFromString(m.toString().replace("b.d.nsec3.ingotronic.ch.", "a.d.nsec3.ingotronic.ch.")));

        // a.d.nsec3.ingotronic.ch./A exists, but the response is faked from
        // *.d.nsec3.ingotronic.ch. which must be detected by the NSEC proof
        Message response = resolver.send(createMessage("a.d.nsec3.ingotronic.ch./A"));
        assertFalse(response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getHeader().getRcode());
    }
}
