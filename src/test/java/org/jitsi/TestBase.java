package org.jitsi;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public abstract class TestBase {
    protected DnssecResolver resolver;

    private Map<String, Message> queryResponsePairs = new HashMap<String, Message>();

    protected final static String localhost = "127.0.0.1";

    private final static boolean offline = false;

    @Before
    public void setup() throws NumberFormatException, IOException, DNSSECException {
        if (offline) {
            // TODO: read all not already existing queries into the query-response map
        }

        resolver = new DnssecResolver("62.192.5.131") {
            @Override
            public Message send(Message query, boolean validate, Set<DNSKEYRecord> trustedKeys) throws IOException {
                Message response = queryResponsePairs.get(query.getQuestion().getName() + "/" + Type.string(query.getQuestion().getType()));
                if (response == null) {
                    if (offline) {
                        throw new IOException("Response for " + query.getQuestion().toString() + " not found.");
                    }
                    else {
                        response = super.send(query, validate, trustedKeys);
                    }
                }

                if (validate) {
                    try {
                        validateDnssec(query, response, trustedKeys);
                    }
                    catch (DNSSECException e) {
                        throw new RuntimeException(e);
                    }
                }

//                System.out.println(result);
                return response;
            }

            @Override
            protected Date getCurrentDate() {
                if (offline) {
                    Calendar c = Calendar.getInstance();
                    c.set(2013, 3, 20); // 3 is actually April. Brain-burned java idiots...
                    return c.getTime();
                }

                return new Date();
            }
        };

        resolver.addTrustAnchor(".   0   IN  DS  19036 8 1 B256BD09DC8DD59F0E0F0D8541B8328DD986DF6E");
        resolver.addTrustAnchor(". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5");
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
