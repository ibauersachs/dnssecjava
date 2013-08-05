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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.jitsi.dnssec.TestBase;
import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;

public class TestValUtils extends TestBase {
    @Test
    public void testLongestCommonNameRootIsRoot() {
        assertEquals(Name.root, ValUtils.longestCommonName(Name.fromConstantString("example.com."), Name.fromConstantString("example.net.")));
    }

    @Test
    public void testNoDataWhenResultIsFromDelegationPoint() throws IOException {
        Message nsec = resolver.send(createMessage("t.ingotronic.ch./A"));
        Record delegationNsec = null;
        Record delegationNsecSig = null;
        for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
            if (set.getName().toString().startsWith("sub.ingotronic.ch")) {
                delegationNsec = set.first();
                delegationNsecSig = (Record)set.sigs().next();
                break;
            }
        }

        Message m = resolver.send(createMessage("sub.ingotronic.ch./MX"));
        Message message = messageFromString(m.toString().replaceAll("sub\\.ingotronic\\.ch\\.\\s+\\d+.*", ""));
        message.addRecord(delegationNsec, Section.AUTHORITY);
        message.addRecord(delegationNsecSig, Section.AUTHORITY);
        add("sub.ingotronic.ch./MX", message);

        Message response = resolver.send(createMessage("sub.ingotronic.ch./MX"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nodata", getReason(response));
    }

    @Test
    public void testNoDataWhenDSResultIsFromChild() throws IOException {
        Message m = resolver.send(createMessage("samekey.ingotronic.ch./MX"));
        // this test needs to have the key in the cache
        add("samekey.ingotronic.ch./DS", m, false);

        Message response = resolver.send(createMessage("samekey.ingotronic.ch./DS"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
        assertEquals("failed.nodata", getReason(response));
    }

    @Test
    public void testNoDataOfDSForRoot() throws IOException {
        Message response = resolver.send(createMessage("./DS"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertNull(getReason(response));
    }
}
