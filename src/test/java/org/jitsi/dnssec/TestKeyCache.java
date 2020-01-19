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

import java.util.Properties;
import org.jitsi.dnssec.validator.KeyCache;
import org.jitsi.dnssec.validator.KeyEntry;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

public class TestKeyCache {
  @Test
  public void testNullPropertiesDontFail() {
    KeyCache kc = new KeyCache();
    kc.init(null);
  }

  @Test
  public void testMaxCacheSize() throws TextParseException {
    Properties p = new Properties();
    p.put(KeyCache.MAX_CACHE_SIZE_CONFIG, "1");
    KeyCache kc = new KeyCache();
    kc.init(p);
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 60);
    KeyEntry nkeB = KeyEntry.newNullKeyEntry(Name.fromString("b."), DClass.IN, 60);
    kc.store(nkeA);
    kc.store(nkeB);
    KeyEntry fromCache = kc.find(Name.fromString("a."), DClass.IN);
    assertNull(fromCache);
  }

  @Test
  public void testTtlExpiration() throws TextParseException, InterruptedException {
    KeyCache kc = new KeyCache();
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 1);
    kc.store(nkeA);
    Thread.sleep(1100);
    KeyEntry fromCache = kc.find(Name.fromString("a."), DClass.IN);
    assertNull(fromCache);
  }

  @Test
  public void testTtlNoLongerThanMaxTtl() throws TextParseException, InterruptedException {
    Properties p = new Properties();
    p.put(KeyCache.MAX_TTL_CONFIG, "1");
    KeyCache kc = new KeyCache();
    kc.init(p);
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 60);
    kc.store(nkeA);
    Thread.sleep(1100);
    KeyEntry fromCache = kc.find(Name.fromString("a."), DClass.IN);
    assertNull(fromCache);
  }

  @Test
  public void testPositiveEntryExactMatch() throws TextParseException {
    KeyCache kc = new KeyCache();
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a.a."), DClass.IN, 60);
    KeyEntry nkeB = KeyEntry.newNullKeyEntry(Name.fromString("a.b."), DClass.IN, 60);
    kc.store(nkeA);
    kc.store(nkeB);
    KeyEntry fromCache = kc.find(Name.fromString("a.a."), DClass.IN);
    assertEquals(nkeA, fromCache);
  }

  @Test
  public void testPositiveEntryEncloserMatch() throws TextParseException {
    KeyCache kc = new KeyCache();
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 60);
    KeyEntry nkeB = KeyEntry.newNullKeyEntry(Name.fromString("b."), DClass.IN, 60);
    kc.store(nkeA);
    kc.store(nkeB);
    KeyEntry fromCache = kc.find(Name.fromString("a.a."), DClass.IN);
    assertEquals(nkeA, fromCache);
  }

  @Test
  public void testCacheOnlySecureDNSKEYs() throws TextParseException {
    KeyCache kc = new KeyCache();

    DNSKEYRecord rA =
        new DNSKEYRecord(Name.fromString("a."), DClass.IN, 60, 0, 0, 0, new byte[] {0});
    SRRset setA = new SRRset(rA);
    setA.setSecurityStatus(SecurityStatus.SECURE);
    KeyEntry nkeA = KeyEntry.newKeyEntry(setA);
    kc.store(nkeA);

    DSRecord rB = new DSRecord(Name.fromString("b."), DClass.IN, 60, 0, 0, 0, new byte[] {0});
    SRRset setB = new SRRset(rB);
    KeyEntry nkeB = KeyEntry.newKeyEntry(setB);
    kc.store(nkeB);

    DNSKEYRecord rC =
        new DNSKEYRecord(Name.fromString("c."), DClass.IN, 60, 0, 0, 0, new byte[] {0});
    SRRset setC = new SRRset(rC);
    KeyEntry nkeC = KeyEntry.newKeyEntry(setC);
    kc.store(nkeC);

    KeyEntry fromCacheA = kc.find(Name.fromString("a."), DClass.IN);
    assertEquals(nkeA, fromCacheA);

    KeyEntry fromCacheB = kc.find(Name.fromString("b."), DClass.IN);
    assertNull(fromCacheB);

    KeyEntry fromCacheC = kc.find(Name.fromString("c."), DClass.IN);
    assertNull(fromCacheC);
  }
}
