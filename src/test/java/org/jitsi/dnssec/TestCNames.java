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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestCNames extends TestBase {
  @Test
  public void testCNameToUnsignedA() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
  }

  @Test
  public void testCNameToUnsignedMX() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.ingotronic.ch./MX"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
  }

  @Test
  public void testCNameToSignedA() throws IOException {
    Message response = resolver.send(createMessage("csigned.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToSignedMX() throws IOException {
    Message response = resolver.send(createMessage("csigned.ingotronic.ch./MX"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToSignedAExternal() throws IOException {
    Message response = resolver.send(createMessage("csext.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToInvalidSigned() throws IOException {
    Message response = resolver.send(createMessage("cfailed.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:dnssec-failed.org.:dnskey.no_ds_match", getReason(response));
  }

  @Test
  public void testCNameToUnsignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
  }

  @Test
  public void testCNameToSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("csigned.nsec3.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToInvalidSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("cfailed.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:dnssec-failed.org.:dnskey.no_ds_match", getReason(response));
  }

  @Test
  public void testCNameToVoid3Chain() throws IOException {
    Message response = resolver.send(createMessage("cvoid3.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToVoid2Chain() throws IOException {
    Message response = resolver.send(createMessage("cvoid2.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToVoid() throws IOException {
    Message response = resolver.send(createMessage("cvoid1.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToUnsignedVoid() throws IOException {
    Message response = resolver.send(createMessage("cvoid4.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertEquals("insecure.ds.nsec", getReason(response));
  }

  @Test
  public void testCNameToExternalUnsignedVoid() throws IOException {
    Message response = resolver.send(createMessage("cvoid.dnssectest.jitsi.net./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
  }

  @Test
  public void testCNameToSubSigned() throws IOException {
    Message response = resolver.send(createMessage("cssub.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToVoidExternalInvalidTld() throws IOException {
    Message response = resolver.send(createMessage("cvoidext1.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToVoidExternalValidTld() throws IOException {
    Message response = resolver.send(createMessage("cvoidext2.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testCNameToVoidNsec3() throws IOException {
    Message response = resolver.send(createMessage("cvoid.nsec3.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }
}
