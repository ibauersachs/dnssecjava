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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestPartiallyInvalid extends TestBase {
    @Test
    public void testValidExising() throws IOException {
        Message response = resolver.send(createMessage("www.partial.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertEquals(localhost, firstA(response));
        assertNull(getReason(response));
    }

    @Test
    public void testValidExisingNoType() throws IOException {
        Message response = resolver.send(createMessage("www.partial.ingotronic.ch./MX"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
        assertTrue(isEmptyAnswer(response));
        assertNull(getReason(response));
    }

    @Test
    public void testValidNonExising() throws IOException {
        Message response = resolver.send(createMessage("www.gibtsnicht.partial.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
        assertNull(getReason(response));
    }
}
