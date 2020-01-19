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

import java.io.IOException;
import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Section;

public class TestNonExistence extends TestBase {
  @Test
  public void testNonExistingBelowRoot() throws IOException {
    Message response = resolver.send(createMessage("gibtsnicht./A"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testSingleLabelABelowSigned() throws IOException {
    Message response = resolver.send(createMessage("gibtsnicht.ingotronic.ch./A"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testSingleLabelABelowSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("gibtsnicht.nsec3.ingotronic.ch./A"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testDoubleLabelABelowSigned() throws IOException {
    Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.ingotronic.ch./A"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testDoubleLabelABelowSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testDoubleLabelABelowSignedNsec3MissingNsec3() throws IOException {
    Message m = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("L40.+nsec3\\.ingotronic\\.ch\\.\\s+300.*", ""));
    add("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
  }

  @Test
  public void testDoubleLabelABelowSignedBeforeZoneNsec3() throws IOException {
    // the query name here must hash to a name BEFORE the first existing
    // NSEC3 owner name
    Message response = resolver.send(createMessage("alias.1gibtsnicht.nsec3.ingotronic.ch./A"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testSingleLabelMXBelowSignedForExistingA() throws IOException {
    Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertTrue(response.getSectionRRsets(Section.ANSWER).isEmpty());
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testSingleLabelMXBelowSignedForExistingANsec3() throws IOException {
    Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./MX"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertTrue(response.getSectionRRsets(Section.ANSWER).isEmpty());
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testDoubleLabelMXBelowSignedForExistingA() throws IOException {
    // a.b.ingotronic.ch./A exists
    Message response = resolver.send(createMessage("a.b.ingotronic.ch./MX"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertTrue(response.getSectionRRsets(Section.ANSWER).isEmpty());
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testDoubleLabelMXBelowSignedForExistingANsec3() throws IOException {
    // a.b.nsec3.ingotronic.ch./A exists
    Message response = resolver.send(createMessage("a.b.nsec3.ingotronic.ch./MX"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertTrue(response.getSectionRRsets(Section.ANSWER).isEmpty());
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testDoubleLabelMXBelowSignedForExistingWildcardA() throws IOException {
    // *.d.ingotronic.ch./A exists
    Message response = resolver.send(createMessage("b.d.ingotronic.ch./MX"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertTrue(response.getSectionRRsets(Section.ANSWER).isEmpty());
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testDoubleLabelMXBelowSignedForExistingWildcardANsec3() throws IOException {
    // *.d.nsec3.ingotronic.ch./A exists
    Message response = resolver.send(createMessage("b.d.nsec3.ingotronic.ch./MX"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertTrue(response.getSectionRRsets(Section.ANSWER).isEmpty());
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testNxDomainWithInvalidNsecSignature() throws IOException {
    Message m = resolver.send(createMessage("x.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("x.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("x.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.nxdomain.authority"));
  }

  @Test
  public void testNoDataWithInvalidNsecSignature() throws IOException {
    Message m = resolver.send(createMessage("www.ingotronic.ch./MX"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("www.ingotronic.ch./MX", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.authority.nodata"));
  }

  @Test
  public void testNoDataOnENT() throws IOException {
    Message response = resolver.send(createMessage("b.ingotronic.ch./A"));
    assertTrue("AD flag must be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NOERROR, response.getRcode());
  }
}
