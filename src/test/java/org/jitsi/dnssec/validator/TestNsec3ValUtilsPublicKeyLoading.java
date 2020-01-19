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
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import java.io.IOException;
import java.security.PublicKey;
import org.jitsi.dnssec.PrepareMocks;
import org.jitsi.dnssec.TestBase;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Type;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Type.class})
public class TestNsec3ValUtilsPublicKeyLoading extends TestBase {
  private int invocationCount = 0;

  @Test
  @PrepareMocks("prepareTestPublicKeyLoadingException")
  public void testPublicKeyLoadingException() throws IOException {
    Message response = resolver.send(createMessage("www.wc.nsec3.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("failed.nsec3_ignored", getReason(response));
  }

  public void prepareTestPublicKeyLoadingException() throws Exception {
    DNSKEYRecord proto = spy(Whitebox.invokeConstructor(DNSKEYRecord.class));
    doAnswer(
            (Answer<DNSKEYRecord>)
                invocationOnMock -> {
                  DNSKEYRecord dr = spy(Whitebox.invokeConstructor(DNSKEYRecord.class));
                  doAnswer(
                          (Answer<PublicKey>)
                              invocation -> {
                                DNSKEYRecord dr1 = (DNSKEYRecord) invocation.getMock();
                                invocationCount++;
                                if (dr1.getName()
                                        .equals(Name.fromConstantString("nsec3.ingotronic.ch."))
                                    && invocationCount == 11) {
                                  throw Whitebox.invokeConstructor(
                                      DNSSEC.DNSSECException.class, "mock-test");
                                }

                                return (PublicKey) invocation.callRealMethod();
                              })
                      .when(dr)
                      .getPublicKey();
                  return dr;
                })
        .when(proto, "getObject");
    whenNew(DNSKEYRecord.class).withNoArguments().thenReturn(proto);
  }
}
