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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.time.Instant;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class TestInvalid extends TestBase {
  @Test
  @AlwaysOffline
  public void testUnknownAlg() throws IOException {
    Message response = resolver.send(createMessage("unknownalgorithm.dnssec.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:unknownalgorithm.dnssec.tjeb.nl.:failed.ds", getReason(response));
  }

  @Test
  @Disabled
  @AlwaysOffline
  public void testSigNotIncepted() throws IOException {
    Message response = resolver.send(createMessage("signotincepted.dnssec.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:signotincepted.dnssec.tjeb.nl.:failed.ds", getReason(response));
  }

  @Test
  @AlwaysOffline
  public void testSigExpired() throws IOException {
    Message response = resolver.send(createMessage("sigexpired.dnssec.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:sigexpired.dnssec.tjeb.nl.:failed.ds", getReason(response));
  }

  @Test
  @AlwaysOffline
  public void testBogusSig() throws IOException {
    Message response = resolver.send(createMessage("bogussig.dnssec.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:bogussig.dnssec.tjeb.nl.:failed.ds", getReason(response));
  }

  @Test
  @AlwaysOffline
  public void testSignedBelowUnsignedBelowSigned() throws IOException {
    Message response = resolver.send(createMessage("ok.nods.ok.dnssec.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertFalse(isEmptyAnswer(response));
    assertEquals("insecure.ds.nsec", getReason(response));
  }

  @Test
  @AlwaysOffline
  public void testUnknownAlgNsec3() throws IOException {
    Message response = resolver.send(createMessage("unknownalgorithm.Nsec3.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:unknownalgorithm.nsec3.tjeb.nl.:failed.ds", getReason(response));
  }

  @Test
  @AlwaysOffline
  public void testSigNotInceptedNsec3() throws IOException {
    Message response = resolver.send(createMessage("signotincepted.Nsec3.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
  }

  @Test
  @AlwaysOffline
  public void testSigExpiredNsec3() throws IOException {
    Message response = resolver.send(createMessage("sigexpired.Nsec3.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:sigexpired.nsec3.tjeb.nl.:failed.ds", getReason(response));
  }

  @Test
  @AlwaysOffline
  public void testBogusSigNsec3() throws IOException {
    Message response = resolver.send(createMessage("bogussig.Nsec3.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:bogussig.nsec3.tjeb.nl.:failed.ds", getReason(response));
  }

  @Test
  @AlwaysOffline
  public void testSignedBelowUnsignedBelowSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("ok.nods.ok.Nsec3.tjeb.nl./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertFalse(isEmptyAnswer(response));
    assertEquals("insecure.ds.nsec3", getReason(response));
  }

  @Test
  public void testUnsignedThatMustBeSigned() throws IOException {
    Name query = Name.fromString("www.ingotronic.ch.");

    // prepare a faked, unsigned response message that must have a signature
    // to be valid
    Message message = new Message();
    message.addRecord(Record.newRecord(query, Type.A, DClass.IN), Section.QUESTION);
    message.addRecord(
        new ARecord(query, Type.A, DClass.IN, InetAddress.getByName(localhost)), Section.ANSWER);
    add("www.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.missingsig", getReason(response));
  }

  @Test
  public void testModifiedSignature() throws IOException {
    Name query = Name.fromString("www.ingotronic.ch.");

    // prepare a faked, unsigned response message that must have a signature
    // to be valid
    Message message = new Message();
    message.addRecord(Record.newRecord(query, Type.A, DClass.IN), Section.QUESTION);
    message.addRecord(
        new ARecord(query, Type.A, DClass.IN, InetAddress.getByName(localhost)), Section.ANSWER);
    Instant now = Instant.now();
    message.addRecord(
        new RRSIGRecord(
            query,
            DClass.IN,
            0,
            Type.A,
            Algorithm.RSASHA256,
            5,
            now.plusSeconds(5),
            now.minusSeconds(5),
            1234,
            Name.fromString("ingotronic.ch."),
            new byte[] {1, 2, 3}),
        Section.ANSWER);
    add("www.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.answer.positive:{ www.ingotronic.ch."));
  }

  @Test
  public void testReturnServfailIfIntermediateQueryFails() throws IOException {
    Message message = new Message();
    message.getHeader().setRcode(Rcode.NOTAUTH);
    message.addRecord(
        Record.newRecord(Name.fromString("ch."), Type.DS, DClass.IN), Section.QUESTION);
    add("ch./DS", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    // rfc4035#section-5.5
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:ch.:failed.ds.nonsec:ch.", getReason(response));
  }

  @Test
  public void testReturnOriginalRcodeIfPrimaryQueryFails() throws IOException {
    Message message = new Message();
    message.getHeader().setRcode(Rcode.REFUSED);
    message.addRecord(
        Record.newRecord(Name.fromString("www.ingotronic.ch."), Type.A, DClass.IN),
        Section.QUESTION);
    add("www.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    // rfc4035#section-5.5
    assertEquals(Rcode.REFUSED, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }
}
