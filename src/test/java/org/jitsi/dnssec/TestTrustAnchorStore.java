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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import org.jitsi.dnssec.validator.TrustAnchorStore;
import org.junit.jupiter.api.Test;
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

  @Test
  public void testInvalidAnchorRecord() throws TextParseException {
    SRRset set = new SRRset(new TXTRecord(Name.fromString("bla."), DClass.IN, 0, "root"));
    TrustAnchorStore tas = new TrustAnchorStore();
    assertThrows(IllegalArgumentException.class, () -> tas.store(set));
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

  @Test
  public void testCaseInsensitiveAnchor() throws TextParseException {
    TrustAnchorStore tas = new TrustAnchorStore();
    SRRset set1 =
        new SRRset(new DSRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    SRRset set2 =
        new SRRset(new DSRecord(Name.fromString("Bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    tas.store(set1);
    tas.store(set2);
    SRRset anchor = tas.find(Name.fromString("bla."), DClass.IN);
    assertEquals(set2, anchor);
    assertIterableEquals(Collections.singleton(set2), tas.items());
  }

  @Test
  public void testCaseInsensitiveSameSetAnchor() throws TextParseException {
    TrustAnchorStore tas = new TrustAnchorStore();
    SRRset set = new SRRset();
    set.addRR(new DSRecord(Name.fromString("Bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    set.addRR(new DSRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    tas.store(set);
    SRRset anchor = tas.find(Name.fromString("bla."), DClass.IN);
    assertEquals(set, anchor);
    assertIterableEquals(Collections.singleton(set), tas.items());
  }
}
