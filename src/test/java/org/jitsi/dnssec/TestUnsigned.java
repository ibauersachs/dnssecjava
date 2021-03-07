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

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestUnsigned extends TestBase {
  @Test
  public void testUnsignedBelowSignedZoneBind() throws IOException {
    Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertEquals("insecure.ds.nsec", getReason(response));
  }

  @Test
  public void testUnsignedBelowSignedTldNsec3NoOptOut() throws IOException {
    Message response = resolver.send(createMessage("20min.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
  }

  @Test
  public void testUnsignedBelowSignedTldNsec3OptOut() throws IOException {
    Message response = resolver.send(createMessage("yahoo.com./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
  }

  @Test
  public void testUnsignedBelowUnsignedZone() throws IOException {
    Message response = resolver.send(createMessage("www.sub.unsigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertEquals("insecure.ds.nsec", getReason(response));
  }
}
