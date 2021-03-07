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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.MessageDigestSpi;
import java.security.Provider;
import java.security.Security;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class TestPriming extends TestBase {
  @Test
  public void testDnskeyPrimeResponseWithEmptyAnswerIsBad() throws IOException {
    Message message = new Message();
    message.addRecord(Record.newRecord(Name.root, Type.DNSKEY, DClass.IN), Section.QUESTION);
    add("./DNSKEY", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:.:dnskey.no_rrset:.", getReason(response));
  }

  @Test
  public void testRootDnskeyPrimeResponseWithNxDomainIsBad() throws IOException {
    Message message = new Message();
    message.addRecord(Record.newRecord(Name.root, Type.DNSKEY, DClass.IN), Section.QUESTION);
    message.getHeader().setRcode(Rcode.NXDOMAIN);
    add("./DNSKEY", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:.:dnskey.no_rrset:.", getReason(response));
  }

  @Test
  public void testDnskeyPrimeResponseWithInvalidSignatureIsBad()
      throws IOException, NumberFormatException {
    Message m = resolver.send(createMessage("./DNSKEY"));
    Message message =
        messageFromString(
            m.toString()
                .replaceAll("(.*\\sRRSIG\\sDNSKEY\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("./DNSKEY", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
  }

  @Test
  @PrepareMocks("prepareTestDnskeyPrimeResponseWithMismatchedFootprintIsBad")
  public void testDnskeyPrimeResponseWithMismatchedFootprintIsBad() throws Exception {
    try {
      Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
      assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
      assertEquals(Rcode.SERVFAIL, response.getRcode());
      assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    } finally {
      Type.register(Type.DNSKEY, Type.string(Type.DNSKEY), () -> spy(DNSKEYRecord.class));
    }
  }

  public void prepareTestDnskeyPrimeResponseWithMismatchedFootprintIsBad() {
    Type.register(
        Type.DNSKEY,
        Type.string(Type.DNSKEY),
        () -> {
          DNSKEYRecord minus1FootprintDnskey = spy(DNSKEYRecord.class);
          when(minus1FootprintDnskey.getFootprint()).thenReturn(-1);
          return minus1FootprintDnskey;
        });
  }

  @Test
  @PrepareMocks("prepareTestDnskeyPrimeResponseWithMismatchedAlgorithmIsBad")
  public void testDnskeyPrimeResponseWithMismatchedAlgorithmIsBad() throws Exception {
    try {
      Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
      assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
      assertEquals(Rcode.SERVFAIL, response.getRcode());
      assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    } finally {
      Type.register(Type.DNSKEY, Type.string(Type.DNSKEY), () -> spy(DNSKEYRecord.class));
    }
  }

  public void prepareTestDnskeyPrimeResponseWithMismatchedAlgorithmIsBad() {
    Type.register(
        Type.DNSKEY,
        Type.string(Type.DNSKEY),
        () -> {
          DNSKEYRecord minus1AlgorithmDnskey = spy(DNSKEYRecord.class);
          when(minus1AlgorithmDnskey.getAlgorithm()).thenReturn(-1);
          return minus1AlgorithmDnskey;
        });
  }

  public static class FakeShaProvider extends Provider {
    protected FakeShaProvider() {
      super("FakeShaProvider", 1, "FakeShaProvider");
      put("MessageDigest.SHA", FakeSha.class.getName());
      put("MessageDigest.SHA-256", FakeSha.class.getName());
    }

    public static class FakeSha extends MessageDigestSpi {
      @Override
      protected void engineUpdate(byte input) {}

      @Override
      protected void engineUpdate(byte[] input, int offset, int len) {}

      @Override
      protected byte[] engineDigest() {
        return new byte[] {1, 2, 3};
      }

      @Override
      protected void engineReset() {}
    }
  }

  @Test
  public void testDnskeyPrimeResponseWithWeirdHashIsBad() throws Exception {
    Provider p = new FakeShaProvider();
    try {
      Security.insertProviderAt(p, 1);
      Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
      assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
      assertEquals(Rcode.SERVFAIL, response.getRcode());
      assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
    } finally {
      Security.removeProvider(p.getName());
    }
  }

  @Test
  public void testDsPrimeResponseWithEmptyAnswerIsBad() throws IOException {
    Message message = new Message();
    message.addRecord(
        Record.newRecord(Name.fromString("ch."), Type.DS, DClass.IN), Section.QUESTION);
    add("ch./DS", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:ch.:failed.ds.nonsec:ch.", getReason(response));
  }

  @Test
  public void testDsPrimeResponseWithNxDomainForTld() throws IOException {
    Message message = new Message();
    message.addRecord(
        Record.newRecord(Name.fromString("ch."), Type.DS, DClass.IN), Section.QUESTION);
    message.getHeader().setRcode(Rcode.NXDOMAIN);
    add("ch./DS", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:ch.:failed.ds.nonsec:ch.", getReason(response));
  }

  @Test
  public void testDsNoDataWhenNsecIsFromChildApex() throws IOException {
    Message nsec = resolver.send(createMessage("1.sub.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().toString().startsWith("sub.ingotronic.ch") && set.getType() == Type.NSEC) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("sub.ingotronic.ch./DS");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("sub.ingotronic.ch./DS", m);

    Message response = resolver.send(createMessage("sub.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:sub.ingotronic.ch.:failed.ds.nsec", getReason(response));
  }

  @Test
  public void testDsNoDataWhenNsecOnEntIsBad() throws IOException {
    Message m = resolver.send(createMessage("e.ingotronic.ch./DS"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("e.ingotronic.ch./DS", message);

    Message response = resolver.send(createMessage("a.e.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus:failed.ds.nsec.ent", getReason(response));
  }

  @Test
  public void testDsNoDataWhenOnInsecureDelegationWithWrongNsec() throws IOException {
    Message nsec = resolver.send(createMessage("alias.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
      if (set.getName().toString().startsWith("alias.ingotronic.ch")
          && set.getType() == Type.NSEC) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("unsigned.ingotronic.ch./DS");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("unsigned.ingotronic.ch./DS", m);

    Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus:failed.ds.unknown", getReason(response));
  }
}
