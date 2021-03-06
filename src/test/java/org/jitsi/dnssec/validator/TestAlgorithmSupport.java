/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2015 Ingo Bauersachs
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

package org.jitsi.dnssec.validator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.Security;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jitsi.dnssec.AlwaysOffline;
import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.TestBase;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.DSRecord.Digest;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;

public class TestAlgorithmSupport extends TestBase {
  @Test
  public void testMd5AlgRfc6944() throws IOException {
    Message response = resolver.send(createMessage("rsamd5.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.noalgorithms:rsamd5.ingotronic.ch.", getReason(response));
  }

  @Test
  public void testEccgostAlgIsUnknown() throws IOException {
    Message response = resolver.send(createMessage("eccgost.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.noalgorithms:eccgost.ingotronic.ch.", getReason(response));
  }

  @Test
  public void testEd25519() throws IOException {
    try {
      BouncyCastleProvider bc = new BouncyCastleProvider();
      Security.addProvider(bc);
      resolver.init(new Properties());
      Message response = resolver.send(createMessage("ed25519.nl./A"));
      assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
      assertEquals(Rcode.NOERROR, response.getRcode());
      assertNull(getReason(response));
    } finally {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void testEd448() throws IOException {
    try {
      BouncyCastleProvider bc = new BouncyCastleProvider();
      Security.addProvider(bc);
      resolver.init(new Properties());
      Message response = resolver.send(createMessage("ed448.nl./A"));
      assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
      assertEquals(Rcode.NOERROR, response.getRcode());
      assertNull(getReason(response));
    } finally {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void testDigestIdIsUnknown() throws IOException {
    Message response = resolver.send(createMessage("unknown-alg.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("failed.ds.nodigest:unknown-alg.ingotronic.ch.", getReason(response));
  }

  @AlwaysOffline
  @Test(expected = IllegalArgumentException.class)
  public void testUnsupportedDigestInDigestPreference() throws IOException {
    Properties config = new Properties();
    config.put("org.jitsi.dnssec.digest_preference", "1,2,0");
    resolver.init(config);
  }

  @AlwaysOffline
  @Test
  public void testFavoriteDigestNotInRRset() {
    Properties config = new Properties();
    config.put("org.jitsi.dnssec.digest_preference", "4");
    ValUtils v = new ValUtils();
    v.init(config);
    SRRset set = new SRRset();
    set.addRR(
        new DSRecord(
            Name.root, DClass.IN, 120, 1234, Algorithm.DSA, Digest.SHA1, new byte[] {1, 2, 3}));
    set.addRR(
        new DSRecord(
            Name.root, DClass.IN, 120, 1234, Algorithm.DSA, Digest.SHA256, new byte[] {1, 2, 3}));
    int digestId = v.favoriteDSDigestID(set);
    assertEquals(0, digestId);
  }

  @AlwaysOffline
  @Test
  public void testOnlyUnsupportedDigestInRRset() {
    ValUtils v = new ValUtils();
    SRRset set = new SRRset();
    set.addRR(
        new DSRecord(
            Name.root, DClass.IN, 120, 1234, Algorithm.DSA, 3 /*GOST*/, new byte[] {1, 2, 3}));
    int digestId = v.favoriteDSDigestID(set);
    assertEquals(0, digestId);
  }

  @AlwaysOffline
  @Test
  public void testOnlyUnsupportedAlgorithmInRRset() {
    ValUtils v = new ValUtils();
    SRRset set = new SRRset();
    set.addRR(
        new DSRecord(
            Name.root, DClass.IN, 120, 1234, 0 /*Unknown alg*/, Digest.SHA1, new byte[] {1, 2, 3}));
    int digestId = v.favoriteDSDigestID(set);
    assertEquals(0, digestId);
  }
}
