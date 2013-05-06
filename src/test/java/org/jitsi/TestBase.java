package org.jitsi;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

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
import org.xbill.DNS.Type;

public abstract class TestBase {
    protected ValidatingResolver resolver;

    private Map<String, Message> queryResponsePairs = new HashMap<String, Message>();

    protected final static String localhost = "127.0.0.1";

    private final static boolean offline = false;

    @Before
    public void setup() throws NumberFormatException, IOException, DNSSECException {
        Logger root = Logger.getRootLogger();
        root.setLevel(Level.ALL);
        root.addAppender(new ConsoleAppender(new PatternLayout("%r %c{2} - %m%n")));

        if (offline) {
            // TODO: read all not already existing queries into the query-response map
        }

        resolver = new ValidatingResolver("62.192.5.131") {
            @Override
            protected Message prepareResponse(Message query) {
                Message response = queryResponsePairs.get(query.getQuestion().getName() + "/" + Type.string(query.getQuestion().getType()));
                if (response != null) {
                    return response;
                }
                else if (offline) {
                    throw new RuntimeException("Response for " + query.getQuestion().toString() + " not found.");
                }

                return query;
            }
        };

        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors"));
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

    @SuppressWarnings("unchecked")
    protected String firstA(Message response) {
        RRset[] sectionRRsets = response.getSectionRRsets(Section.ANSWER);
        Iterator<ARecord> rrs = sectionRRsets[0].rrs();
        return rrs.next().getAddress().getHostAddress();
    }

    private byte[] fromHex(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length() / 2; i++) {
            data[i] = (byte) Short.parseShort(hex.substring(i * 2, i * 2 + 2), 16);
        }

        return data;
    }

//    private String toHex(byte[] data) {
//        StringBuilder sb = new StringBuilder();
//        for (int i = 0; i < data.length; i++) {
//            sb.append(String.format("%02X", data[i]));
//        }
//
//        return sb.toString();
//    }
}
