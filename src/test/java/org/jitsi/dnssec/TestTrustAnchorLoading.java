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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class TestTrustAnchorLoading extends TestBase {
  @Test
  public void testLoadRootTrustAnchors() throws IOException {
    assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
    assertNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
  }

  @Test
  public void testLoadRootTrustAnchorsFromFile() throws IOException {
    resolver.getTrustAnchors().clear();
    Properties config = new Properties();
    config.put("org.jitsi.dnssec.trust_anchor_file", "./src/test/resources/trust_anchors");
    resolver.init(config);
    assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
  }

  @Test
  public void testInitializingWithEmptyConfigDoesNotFail() throws IOException {
    resolver.getTrustAnchors().clear();
    Properties config = new Properties();
    resolver.init(config);
    assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
  }

  @Test
  public void testInitializingWithNonExistingFileThrows() throws IOException {
    resolver.getTrustAnchors().clear();
    Properties config = new Properties();
    config.put("org.jitsi.dnssec.trust_anchor_file", "xyz");
    assertThrows(IOException.class, () -> resolver.init(config));
  }

  @Test
  public void testLoadRootTrustAnchorWithDNSKEY() throws IOException {
    Message keys = resolver.send(createMessage("./DNSKEY"));
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    OutputStreamWriter osw = new OutputStreamWriter(bos);
    for (RRset set : keys.getSectionRRsets(Section.ANSWER)) {
      if (set.getType() == Type.DNSKEY) {
        for (Record r : set.rrs()) {
          osw.write(r.toString());
          osw.write('\n');
        }
      }
    }

    osw.close();

    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(new ByteArrayInputStream(bos.toByteArray()));
    assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  public void testLoadRootTrustAnchorWithInvalidDNSKEY() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_dnskey_invalid"));
    assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
  }

  @Test
  public void testLoadRootTrustAnchorWithInvalidDS() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_invalid"));
    assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.bogus.badkey:.:dnskey.no_ds_match", getReason(response));
  }

  @Test
  public void testLoadRootTrustAnchorsAlongWithGarbage() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_test"));
    assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
    assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
  }

  @Test
  public void testLoadEmptyTrustAnchors() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_empty"));
    assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
  }

  @Test
  public void testInsecureWithEmptyTrustAnchor() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_empty"));
    assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("validate.insecure", getReason(response));
  }
}
