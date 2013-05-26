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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.net.UnknownHostException;

import org.jitsi.dnssec.validator.ValidatingResolver;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.SimpleResolver;

public class TestTrustAnchorLoading {
    private ValidatingResolver resolver;

    @Before
    public void setup() throws UnknownHostException {
        this.resolver = new ValidatingResolver(new SimpleResolver());
    }

    @Test
    public void testLoadRootTrustAnchors() throws IOException {
        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
    }

    @Test
    public void testLoadRootTrustAnchorsAlongWithGarbage() throws IOException {
        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors_test"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
    }

    @Test
    public void testLoadEmptyTrustAnchors() throws IOException {
        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors_empty"));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
    }

    @Test
    public void testInsecureWithEmptyTrustAnchor() throws IOException {
        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors_empty"));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

        Message response = resolver.send((new TestBase(){}).createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }
}
