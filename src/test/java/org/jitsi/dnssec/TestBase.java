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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.LogManager;

import org.jitsi.dnssec.validator.ValidatingResolver;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import static org.powermock.api.mockito.PowerMockito.whenNew;

@RunWith(PowerMockRunner.class)
@PrepareForTest({DNSSEC.class, TestInvalid.class})
public abstract class TestBase {
    private static final Logger logger = LoggerFactory.getLogger(TestBase.class);

    private final static boolean offline = !Boolean.getBoolean("org.jitsi.dnssecjava.online");
    private final static boolean partialOffline = "partial".equals(System.getProperty("org.jitsi.dnssecjava.offline"));
    private final static boolean record = Boolean.getBoolean("org.jitsi.dnssecjava.record");
    private boolean unboundTest = false;
    private boolean alwaysOffline = false;

    private Map<String, Message> queryResponsePairs = new HashMap<String, Message>();
    private MessageReader messageReader = new MessageReader();
    private FileWriter w;
    private BufferedReader r;

    protected final static String localhost = "127.0.0.1";
    protected ValidatingResolver resolver;
    protected String testName;

    static {
        try {
            LogManager.getLogManager().readConfiguration(TestBase.class.getResourceAsStream("logging.properties"));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Rule
    public TestRule watcher = new TestWatcher() {
        @Override
        protected void starting(Description description) {
            unboundTest = false;
            testName = description.getMethodName();

            try {
                // do not record or process unbound unit tests offline
                alwaysOffline = description.getAnnotation(AlwaysOffline.class) != null;
                if (description.getClassName().contains("unbound")) {
                    unboundTest = true;
                    return;
                }

                String filename = "/recordings/" + description.getClassName().replace(".", "_") + "/" + testName;
                File f = new File("./src/test/resources" + filename);
                if ((record || !f.exists()) && !alwaysOffline) {
                    f.getParentFile().getParentFile().mkdir();
                    f.getParentFile().mkdir();
                    w = new FileWriter(f.getAbsoluteFile());
                    w.write("#Date: " + new DateTime().toString(ISODateTimeFormat.dateTimeNoMillis()));
                    w.write("\n");
                }
                else if (offline || partialOffline || alwaysOffline) {
                    PrepareMocks pm = description.getAnnotation(PrepareMocks.class);
                    if (pm != null) {
                        Whitebox.invokeMethod(TestBase.this, pm.value());
                    }

                    InputStream stream = getClass().getResourceAsStream(filename);
                    if (stream != null) {
                        r = new BufferedReader(new InputStreamReader(stream));
                        long millis = DateTime.parse(r.readLine().substring("#Date: ".length()), ISODateTimeFormat.dateTimeNoMillis()).getMillis();
                        whenNew(Date.class).withNoArguments().thenReturn(new Date(millis));
                        whenNew(Date.class).withArguments(Mockito.anyLong()).thenAnswer(new Answer<Date>(){
                            @Override
                            public Date answer(InvocationOnMock invocationOnMock) throws Throwable {
                                return new Date((Long)invocationOnMock.getArguments()[0]);
                            }
                        });

                        Message m;
                        while ((m = messageReader.readMessage(r)) != null) {
                            queryResponsePairs.put(key(m), m);
                        }

                        r.close();
                    }
                }
            }
            catch (Exception e) {
                System.err.println(e);
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void finished(Description description) {
            try {
                if (record && w != null) {
                    w.flush();
                    w.close();
                    w = null;
                }
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    };

    @BeforeClass
    public static void setupClass() {
        R.setBundle(null);
        R.setUseNeutralMessages(true);
    }

    @Before
    public void setup() throws NumberFormatException, IOException, DNSSECException {
        resolver = new ValidatingResolver(new SimpleResolver("62.192.5.131") {
            @Override
            public Message send(Message query) throws IOException {
                logger.info("---{}", key(query));
                Message response = queryResponsePairs.get(key(query));
                if (response != null) {
                    return response;
                }
                else if ((offline && !partialOffline) || unboundTest || alwaysOffline) {
                    Assert.fail("Response for " + key(query) + " not found.");
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
    }

    protected void add(Message m) throws IOException {
        this.add(key(m), m, true);
    }

    protected void add(String query, Message response) throws IOException {
        this.add(query, response, true);
    }

    protected void add(String query, Message response, boolean clear) throws IOException {
        queryResponsePairs.put(query, messageFromString(response.toString()));

        // reset the resolver so any cached stuff is cleared
        if (!clear) {
            return;
        }

        try {
            setup();
        }
        catch (NumberFormatException e) {
            throw new IOException(e);
        }
        catch (DNSSECException e) {
            throw new IOException(e);
        }
    }

    protected Message get(Name target, int type) {
        return queryResponsePairs.get(key(target, type));
    }

    protected void clear() {
        queryResponsePairs.clear();
    }

    protected Message createMessage(String query) throws IOException {
        return Message.newQuery(Record.newRecord(Name.fromString(query.split("/")[0]), Type.value(query.split("/")[1]), DClass.IN));
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

    protected String getReason(Message m) {
        for (RRset set : m.getSectionRRsets(Section.ADDITIONAL)) {
            if (set.getName().equals(Name.root) && set.getType() == Type.TXT && set.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
                StringBuilder sb = new StringBuilder();
                @SuppressWarnings("unchecked")
                List<String> strings = (List<String>)((TXTRecord)set.first()).getStrings();
                for (String part : strings){
                    sb.append(part);
                }

                return sb.toString();
            }
        }

        return null;
    }

    protected boolean isEmptyAnswer(Message response) {
        RRset[] sectionRRsets = response.getSectionRRsets(Section.ANSWER);
        return sectionRRsets.length == 0;
    }

    private String key(Name n, int t) {
        return n + "/" + Type.string(t);
    }

    private String key(Record r) {
        return key(r.getName(), r.getType());
    }

    private String key(Message m) {
        return key(m.getQuestion());
    }

    protected Record toRecord(String data){
        try {
            InputStream in = new ByteArrayInputStream(data.getBytes("UTF-8"));
            Master m = new Master(in, Name.root);
            return m._nextRecord();
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
