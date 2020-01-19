/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2016 Ingo Bauersachs
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

public class TestBogusReasonMessage extends TestBase {
  @Test
  public void testLongBogusReasonIsSplitCorrectly() throws IOException {
    Message response =
        resolver.send(
            createMessage(
                "01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.isc.org./A"));
    assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "failed.nxdomain.authority:{ isc.org. 2962 IN NSEC [01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.isc.org. A NS SOA MX TXT AAAA NAPTR RRSIG NSEC DNSKEY SPF] sigs: [NSEC 5 2 3600 20160706234032 20160606234032 13953 isc.org. fnOJeQG2vOwrERAPIqAenLOosbIBT7UvmxOV8Az2ExOhlGxP2CEqZEc5NPVbidq4oZC2kHyG7x31D6LBJXeXgOuanv+uqPNe9UIiUhdj+Egf8FEWIOKp8nxgjQGiGSNbQenWjeWoR91sReFEU+Pn7NPlEI072MzEESOT8oVucx8=] }",
        getReason(response));
  }
}
