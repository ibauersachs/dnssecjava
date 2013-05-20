/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (C) 2013 Ingo Bauersachs. All rights reserved.
 *
 * This file is part of dnssecjava.
 *
 * Dnssecjava is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dnssecjava is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with dnssecjava.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.jitsi.dnssec;

import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jitsi.dnssec.SMessage;
import org.jitsi.dnssec.SRRset;
import org.junit.Test;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class TestSMessage {
    @Test(expected = IllegalArgumentException.class)
    public void testGetUndefinedSectionBelow() {
        SMessage m = new SMessage(0, null);
        m.getSectionRRsets(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetUndefinedSectionAtLowerBorder() {
        SMessage m = new SMessage(0, null);
        m.getSectionRRsets(0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetUndefinedSectionAtUpperBorder() {
        SMessage m = new SMessage(0, null);
        m.getSectionRRsets(4);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetUndefinedSectionAbove() {
        SMessage m = new SMessage(0, null);
        m.getSectionRRsets(100);
    }

    @Test()
    public void testGetEmptySection() {
        SMessage m = new SMessage(0, null);
        SRRset[] sets = m.getSectionRRsets(Section.ANSWER);
        assertEquals(0, sets.length);
    }

    @Test()
    public void testGetEmptySectionByType() {
        SMessage m = new SMessage(0, null);
        SRRset[] sets = m.getSectionRRsets(Section.ANSWER, Type.A);
        assertEquals(0, sets.length);
    }
    @Test()
    public void testGetSectionByType() throws UnknownHostException {
        Message m = new Message();
        Record r1 = new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[]{0,0,0,0}));
        m.addRecord(r1, Section.ANSWER);
        Record r2 = new AAAARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}));
        m.addRecord(r2, Section.ANSWER);
        SMessage sm = new SMessage(m);
        SRRset[] result = sm.getSectionRRsets(Section.ANSWER, Type.A);
        assertEquals(1, result.length);
        assertEquals(Type.A, result[0].getType());
    }

    @Test()
    public void testRecordCountForQuestionIsOne() {
        SMessage m = new SMessage(0, null);
        int count = m.getCount(Section.QUESTION);
        assertEquals(1, count);
    }

    @Test()
    public void testRecordCountForEmptySectionIsZero() {
        SMessage m = new SMessage(0, null);
        int count = m.getCount(Section.ADDITIONAL);
        assertEquals(0, count);
    }

    @Test()
    public void testRecordCountForIsValid() throws UnknownHostException {
        Message m = new Message();
        m.addRecord(new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[]{0,0,0,0})), Section.ANSWER);
        SMessage sm = new SMessage(m);
        int count = sm.getCount(Section.ANSWER);
        assertEquals(1, count);
    }

    @Test()
    public void testAnswerSectionSearchFound() throws UnknownHostException {
        Message m = new Message();
        Record r = new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[]{0,0,0,0}));
        m.addRecord(r, Section.ANSWER);
        SMessage sm = new SMessage(m);
        SRRset result = sm.findAnswerRRset(Name.root, Type.A, DClass.IN);
        assertEquals(r, result.first());
    }

    @Test()
    public void testAnswerSectionSearchNotFoundDifferentClass() throws UnknownHostException {
        Message m = new Message();
        Record r = new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[]{0,0,0,0}));
        m.addRecord(r, Section.ANSWER);
        SMessage sm = new SMessage(m);
        SRRset result = sm.findAnswerRRset(Name.root, Type.A, DClass.CH);
        assertNull(result);
    }

    @Test()
    public void testAnswerSectionSearchNotFoundDifferentType() throws UnknownHostException {
        Message m = new Message();
        Record r = new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[]{0,0,0,0}));
        m.addRecord(r, Section.ANSWER);
        SMessage sm = new SMessage(m);
        SRRset result = sm.findAnswerRRset(Name.root, Type.MX, DClass.IN);
        assertNull(result);
    }

    @Test()
    public void testAnswerSectionSearchNotFoundDifferentName() throws UnknownHostException, TextParseException {
        Message m = new Message();
        Record r = new ARecord(Name.fromString("asdf."), DClass.IN, 0, InetAddress.getByAddress(new byte[]{0,0,0,0}));
        m.addRecord(r, Section.ANSWER);
        SMessage sm = new SMessage(m);
        SRRset result = sm.findAnswerRRset(Name.root, Type.MX, DClass.IN);
        assertNull(result);
    }
}
