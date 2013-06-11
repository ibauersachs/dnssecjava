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

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Appender;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.jitsi.dnssec.validator.ValidatingResolver;
import org.junit.Before;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public abstract class TestBase {
    protected final static String localhost = "127.0.0.1";

    protected ValidatingResolver resolver;

    private Map<String, Message> queryResponsePairs = new HashMap<String, Message>();
    private MessageReader messageReader;

    private final static boolean offline = false;

    {
        Logger root = Logger.getRootLogger();
        if (root.getAppender("junit") == null) {
            root.setLevel(Level.ALL);
            Appender junit = new ConsoleAppender(new PatternLayout("%r %c{2}.%M.%L - %m%n"));
            junit.setName("junit");
            root.addAppender(junit);
        }
    }

    @Before
    public void setup() throws NumberFormatException, IOException, DNSSECException {
        messageReader = new MessageReader();

        if (offline) {
            // TODO: read all not already existing queries into the query-response map
        }

        resolver = new ValidatingResolver(new SimpleResolver("62.192.5.131") {
            @Override
            public Message send(Message query) throws IOException {
                System.err.println(query.getQuestion().getName() + "/" + Type.string(query.getQuestion().getType()));
                Message response = queryResponsePairs.get(query.getQuestion().getName() + "/" + Type.string(query.getQuestion().getType()));
                if (response != null) {
                    return response;
                }
                else if (offline) {
                    throw new RuntimeException("Response for " + query.getQuestion().toString() + " not found.");
                }

                return super.send(query);
            }
        });

        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors"));
        System.err.println("--------------");
    }

    protected void add(String query, String response) throws IOException {
        queryResponsePairs.put(query, createMessageFromHex(response));
    }

    protected void add(String query, Message response) throws IOException {
        queryResponsePairs.put(query, response);
    }

    private Message createMessageFromHex(String hex) throws IOException {
        return new Message(fromHex(hex));
    }

    protected Message createMessage(String query) throws IOException {
        return Message.newQuery(Record.newRecord(Name.fromString(query.split("/")[0]), Type.value(query.split("/")[1]), DClass.IN));
    }

    protected Message messageFromRes(String fileName) throws IOException {
        return messageReader.readMessage(getClass().getResourceAsStream(fileName));
    }

    @SuppressWarnings("unchecked")
    protected String firstA(Message response) {
        RRset[] sectionRRsets = response.getSectionRRsets(Section.ANSWER);
        if (sectionRRsets.length > 0) {
            Iterator<Record> rrs = sectionRRsets[0].rrs();
            while (rrs.hasNext()) {
                Record r = rrs.next();
                if (r.getType() == Type.A) {
                    return ((ARecord)r).getAddress().getHostAddress();
                }
            }
        }

        return null;
    }

    protected boolean isEmptyAnswer(Message response) {
        RRset[] sectionRRsets = response.getSectionRRsets(Section.ANSWER);
        return sectionRRsets.length == 0;
    }

    private byte[] fromHex(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length() / 2; i++) {
            data[i] = (byte) Short.parseShort(hex.substring(i * 2, i * 2 + 2), 16);
        }

        return data;
    }

    protected String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(String.format("%02X", data[i]));
        }

        return sb.toString();
    }
}
