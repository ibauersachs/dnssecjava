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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Appender;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.jitsi.dnssec.validator.ValidatingResolver;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
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
    private final static boolean offline = Boolean.getBoolean("org.jitsi.dnssecjava.offline");
    private final static boolean record = Boolean.getBoolean("org.jitsi.dnssecjava.record");

    private Map<String, Message> queryResponsePairs = new HashMap<String, Message>();
    private MessageReader messageReader = new MessageReader();
    private FileWriter w;
    private BufferedReader r;

    protected final static String localhost = "127.0.0.1";
    protected ValidatingResolver resolver;

    {
        Logger root = Logger.getRootLogger();
        if (root.getAppender("junit") == null) {
            root.setLevel(Level.ALL);
            Appender junit = new ConsoleAppender(new PatternLayout("%r %c{2}.%M.%L - %m%n"));
            junit.setName("junit");
            root.addAppender(junit);
        }
    }

    @Rule
    public TestRule watcher = new TestWatcher() {
        @Override
        protected void starting(Description description) {
            try {
                String filename = "/recordings/" + description.getClassName().replace(".", "_") + "/" + description.getMethodName();
                if (record) {
                    File f = new File("./src/test/resources" + filename);
                    f.getParentFile().mkdir();
                    w = new FileWriter(f.getAbsoluteFile());
                    w.write("#Date: " + new DateTime().toString(ISODateTimeFormat.dateTimeNoMillis()));
                    w.write("\n");
                }
                else if (offline) {
                    r = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream(filename)));
                    SystemMock.overriddenMillis = DateTime.parse(r.readLine().substring("#Date: ".length()), ISODateTimeFormat.dateTimeNoMillis()).getMillis();
                    Message m;
                    while ((m = messageReader.readMessage(r)) != null) {
                        queryResponsePairs.put(key(m), m);
                    }

                    r.close();
                }
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void finished(Description description) {
            try {
                if (record) {
                    w.flush();
                    w.close();
                    w = null;
                }

                SystemMock.overriddenMillis = 0;
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    };

    @Before
    public void setup() throws NumberFormatException, IOException, DNSSECException {
        resolver = new ValidatingResolver(new SimpleResolver("62.192.5.131") {
            @Override
            public Message send(Message query) throws IOException {
                System.out.println("---" + key(query));
                Message response = queryResponsePairs.get(key(query));
                if (response != null) {
                    return response;
                }
                else if (offline) {
                    throw new RuntimeException("Response for " + key(query) + " not found.");
                }

                Message networkResult = super.send(query);
                if (record) {
                    w.write(networkResult.toString());
                    w.write("\n\n###############################################\n\n");
                }

                return networkResult;
            }
        });

        resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors"));
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
        return messageReader.readMessage(new InputStreamReader(getClass().getResourceAsStream(fileName)));
    }

    protected Message messageFromString(String message) throws IOException {
        return messageReader.readMessage(new StringReader(message));
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
            data[i] = (byte)Short.parseShort(hex.substring(i * 2, i * 2 + 2), 16);
        }

        return data;
    }

    private String key(Message m) {
        return m.getQuestion().getName() + "/" + Type.string(m.getQuestion().getType());
    }

    protected String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(String.format("%02X", data[i]));
        }

        return sb.toString();
    }
}
