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
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.jitsi.dnssec.PrepareMocks;
import org.jitsi.dnssec.TestBase;
import org.junit.Test;
import org.mockito.stubbing.Answer;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Type;

public class TestNsec3ValUtilsPublicKeyLoading extends TestBase {
  @Test
  @PrepareMocks("prepareTestPublicKeyLoadingException")
  public void testPublicKeyLoadingException() throws Exception {
    try {
      resolver.setTimeout(Duration.ofDays(1));
      Message response = resolver.send(createMessage("www.wc.nsec3.ingotronic.ch./A"));
      assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
      assertEquals(Rcode.NOERROR, response.getRcode());
      assertEquals("failed.nsec3_ignored", getReason(response));
    } finally {
      Type.register(Type.DNSKEY, Type.string(Type.DNSKEY), () -> spy(DNSKEYRecord.class));
    }
  }

  public void prepareTestPublicKeyLoadingException() {
    Name fakeName = Name.fromConstantString("nsec3.ingotronic.ch.");
    Type.register(
        Type.DNSKEY,
        Type.string(Type.DNSKEY),
        () -> {
          DNSKEYRecord throwingDnskey = spy(DNSKEYRecord.class);
          AtomicInteger invocationCount = new AtomicInteger(0);
          try {
            doAnswer(
                    (Answer<PublicKey>)
                        a -> {
                          if (((DNSKEYRecord) a.getMock()).getName().equals(fakeName)) {
                            if (invocationCount.getAndIncrement() == 3) {
                              throwDnssecException();
                            }
                            return (PublicKey) a.callRealMethod();
                          }
                          return (PublicKey) a.callRealMethod();
                        })
                .when(throwingDnskey)
                .getPublicKey();
          } catch (DNSSECException e) {
            throw new RuntimeException(e);
          }
          return throwingDnskey;
        });
  }

  private void throwDnssecException() throws DNSSECException {
    try {
      Constructor<DNSSECException> c = DNSSECException.class.getDeclaredConstructor(String.class);
      c.setAccessible(true);
      throw c.newInstance("mock-text");
    } catch (NoSuchMethodException
        | IllegalAccessException
        | InvocationTargetException
        | InstantiationException e) {
      throw new RuntimeException(e);
    }
  }
}
