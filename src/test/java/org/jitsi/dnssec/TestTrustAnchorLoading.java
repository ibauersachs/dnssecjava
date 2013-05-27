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
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;

public class TestTrustAnchorLoading extends TestBase {
    @Test
    public void testLoadRootTrustAnchors() throws IOException {
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
    }

    @Test
    public void testLoadRootTrustAnchorWithDNSKEY() throws IOException {
        resolver.getTrustAnchors().clear();
        resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_dnskey"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testLoadRootTrustAnchorWithInvalidDNSKEY() throws IOException {
        resolver.getTrustAnchors().clear();
        resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_dnskey_invalid"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testLoadRootTrustAnchorWithInvalidDS() throws IOException {
        resolver.getTrustAnchors().clear();
        resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_invalid"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }

    @Test
    public void testLoadRootTrustAnchorsAlongWithGarbage() throws IOException {
        resolver.getTrustAnchors().clear();
        resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_test"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
    }

    @Test
    public void testLoadEmptyTrustAnchors() throws IOException {
        resolver.getTrustAnchors().clear();
        resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_empty"));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
    }

    @Test
    public void testInsecureWithEmptyTrustAnchor() throws IOException {
        resolver.getTrustAnchors().clear();
        resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_empty"));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NOERROR, response.getRcode());
    }
}
