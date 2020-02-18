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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.spy;

import java.lang.reflect.Modifier;
import java.security.PublicKey;
import java.time.Duration;
import org.jitsi.dnssec.PrepareMocks;
import org.jitsi.dnssec.TestBase;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Answers;
import org.mockito.internal.stubbing.answers.CallsRealMethods;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Record.class)
public class TestNsec3ValUtilsPublicKeyLoading extends TestBase {
  private int invocationCount = 0;

  @Test
  @PrepareMocks("prepareTestPublicKeyLoadingException")
  public void testPublicKeyLoadingException() throws Exception {
    resolver.setTimeout(Duration.ofDays(1));
    Message response = resolver.send(createMessage("www.wc.nsec3.ingotronic.ch./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals("failed.nsec3_ignored", getReason(response));
  }

  public void prepareTestPublicKeyLoadingException() throws Exception {
    spy(Record.class);
    doAnswer(
            (Answer<Record>)
                getEmptyRecordInvocation -> {
                  Record orig = (Record) getEmptyRecordInvocation.callRealMethod();
                  if (orig instanceof DNSKEYRecord) {
                    DNSKEYRecord dr =
                        mock(
                            DNSKEYRecord.class,
                            withSettings()
                                .spiedInstance(orig)
                                .defaultAnswer(
                                    new CallsRealMethods() {
                                      @Override
                                      public Object answer(InvocationOnMock invocation)
                                          throws Throwable {
                                        return Modifier.isAbstract(
                                                invocation.getMethod().getModifiers())
                                            ? (invocation.getMethod().getName().equals("compareTo")
                                                ? ((Comparable<?>) orig)
                                                    .compareTo(invocation.getArgument(0))
                                                : Answers.RETURNS_DEFAULTS.answer(invocation))
                                            : invocation.callRealMethod();
                                      }
                                    }));
                    doAnswer(
                            (Answer<PublicKey>)
                                getPublicKeyInvocation -> {
                                  if (invocationCount++ == 5) {
                                    throw Whitebox.invokeConstructor(
                                        DNSSEC.DNSSECException.class, "mock-test");
                                  }

                                  return (PublicKey) getPublicKeyInvocation.callRealMethod();
                                })
                        .when(dr)
                        .getPublicKey();
                    return dr;
                  }
                  return orig;
                })
        .when(
            Record.class,
            "getEmptyRecord",
            eq(Name.fromConstantString("nsec3.ingotronic.ch.")),
            eq(Type.DNSKEY),
            eq(DClass.IN),
            anyLong(),
            anyBoolean());
  }
}
