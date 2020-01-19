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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestNoData extends TestBase {
  @Test
  public void testFakedNoDataNsec3WithoutNsecs() throws IOException {
    Message m = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("www\\.nsec3\\.ingotronic\\.ch\\.\\s+.*", ""));
    add("www.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.nodata"));
  }

  @Test
  public void testFakedNoDataNsec3WithNsecs() throws IOException {
    Message m = resolver.send(createMessage("www.nsec3.ingotronic.ch./MX"));
    Message message = messageFromString(m.toString().replaceAll("type = MX", "type = A"));
    add("www.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.nodata"));
  }
}
