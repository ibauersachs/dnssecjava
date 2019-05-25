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

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jitsi.dnssec.validator.DnsSecVerifier;
import org.jitsi.dnssec.validator.ResponseClassification;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/**
 * These test run checks that are unable to occur during actual validations.
 * 
 * @author Ingo Bauersachs
 */
public class TestNormallyUnreachableCode {
    private InetAddress localhost;

    @Before
    public void setUp() throws UnknownHostException {
        localhost = InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 });
    }

    @Test
    public void testVerifyWithoutSignaturesIsBogus() {
        DnsSecVerifier verifier = new DnsSecVerifier();
        ARecord record = new ARecord(Name.root, DClass.IN, 120, localhost);
        SRRset set = new SRRset();
        set.addRR(record);
        RRset keys = new RRset();
        SecurityStatus result = verifier.verify(set, keys);
        assertEquals(SecurityStatus.BOGUS, result);
    }

    @Test
    public void useAllEnumCode() {
        SecurityStatus.valueOf(SecurityStatus.values()[0].toString());
        ResponseClassification.valueOf(ResponseClassification.values()[0].toString());
    }

    @Test
    public void testSmessageReturnsOptRecordOfOriginal() {
        int xrcode = 0xFED;
        Message m = Message.newQuery(Record.newRecord(Name.root, Type.NS, DClass.IN));
        m.getHeader().setRcode(xrcode & 0xF);
        m.addRecord(new OPTRecord(1, xrcode >> 4, 1), Section.ADDITIONAL);
        SMessage sm = new SMessage(m);
        assertEquals(m.toString(), sm.getMessage().toString());
        assertEquals(xrcode, sm.getRcode());
    }

    @Test
    public void testCopyMessageWithoutQuestion() {
        Message m = new Message();
        m.addRecord(new ARecord(Name.root, DClass.IN, 120, localhost), Section.ANSWER);
        SMessage sm = new SMessage(m);
        assertEquals(m.toString(), sm.getMessage().toString());
    }
}
