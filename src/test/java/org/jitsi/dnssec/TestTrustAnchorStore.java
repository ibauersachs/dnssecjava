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

import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.validator.TrustAnchorStore;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;

public class TestTrustAnchorStore {
    @Test
    public void testNullKeyWhenNameNotUnderAnchor() throws TextParseException {
        TrustAnchorStore tas = new TrustAnchorStore();
        SRRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
        assertNull(anchor);
    }

    @Test
    public void testKeyWhenNameUnderAnchorDS() throws TextParseException {
        SRRset set = new SRRset(new RRset(new DSRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[]{0})));
        TrustAnchorStore tas = new TrustAnchorStore();
        tas.store(set);
        SRRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
        assertEquals(set, anchor);
    }

    @Test
    public void testKeyWhenNameUnderAnchorDNSKEY() throws TextParseException {
        SRRset set = new SRRset(new RRset(new DNSKEYRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[]{0})));
        TrustAnchorStore tas = new TrustAnchorStore();
        tas.store(set);
        SRRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
        assertEquals(set, anchor);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidAnchorRecord() throws TextParseException {
        SRRset set = new SRRset(new RRset(new TXTRecord(Name.fromString("bla."), DClass.IN, 0, "root")));
        TrustAnchorStore tas = new TrustAnchorStore();
        tas.store(set);
    }
}
