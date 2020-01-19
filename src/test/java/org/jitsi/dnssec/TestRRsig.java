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

import java.io.IOException;
import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

public class TestRRsig extends TestBase {
  @Test
  public void testRRsigNodata() throws IOException {
    Message message = createMessage("www.ingotronic.ch./RRSIG");
    add("www.ingotronic.ch./RRSIG", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./RRSIG"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }

  @Test
  public void testRRsigServfail() throws IOException {
    Message message = createMessage("www.ingotronic.ch./RRSIG");
    message.getHeader().setRcode(Rcode.SERVFAIL);
    add("www.ingotronic.ch./RRSIG", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./RRSIG"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }
}
