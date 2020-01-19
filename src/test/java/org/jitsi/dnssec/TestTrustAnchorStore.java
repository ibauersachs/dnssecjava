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

import static org.junit.Assert.*;

import org.jitsi.dnssec.validator.TrustAnchorStore;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
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
    SRRset set =
        new SRRset(new DSRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    TrustAnchorStore tas = new TrustAnchorStore();
    tas.store(set);
    SRRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
    assertEquals(set, anchor);
  }

  @Test
  public void testKeyWhenNameUnderAnchorDNSKEY() throws TextParseException {
    SRRset set =
        new SRRset(
            new DNSKEYRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    TrustAnchorStore tas = new TrustAnchorStore();
    tas.store(set);
    SRRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
    assertEquals(set.getName(), anchor.getName());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testInvalidAnchorRecord() throws TextParseException {
    SRRset set = new SRRset(new TXTRecord(Name.fromString("bla."), DClass.IN, 0, "root"));
    TrustAnchorStore tas = new TrustAnchorStore();
    tas.store(set);
  }

  @Test
  public void testClear() throws TextParseException {
    SRRset set =
        new SRRset(
            new DNSKEYRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    TrustAnchorStore tas = new TrustAnchorStore();
    tas.store(set);
    SRRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
    assertNotNull(anchor);
    tas.clear();
    assertNull(tas.find(Name.fromString("asdf.bla."), DClass.IN));
  }
}
