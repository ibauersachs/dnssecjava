package org.jitsi.dnssec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class TestPriming extends TestBase {
    @Test
    public void testPrimeResponseToEmptyAnswer() throws IOException {
        Message message = new Message();
        message.addRecord(Record.newRecord(Name.root, Type.DNSKEY, DClass.IN), Section.QUESTION);
        add("./DNSKEY", message);

        Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
        assertFalse("AD flag must not be set", response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.SERVFAIL, response.getRcode());
    }
}
