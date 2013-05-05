package org.jitsi;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Section;

public class TestNonExistence extends TestBase {
    @Test
    public void testNonExistingBelowSignedZoneIcann() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht./A"));
        assertTrue(response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testSingleLabelABelowSigned() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht.ingotronic.ch./A"));
        assertTrue(response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testDoubleLabelABelowSigned() throws IOException {
        Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.ingotronic.ch./A"));
        assertTrue(response.getHeader().getFlag(Flags.AD));
        assertEquals(Rcode.NXDOMAIN, response.getRcode());
    }

    @Test
    public void testSingleLabelMXBelowSignedForExistingA() throws IOException {
        Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
        assertTrue(response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testDoubleLabelMXBelowSignedForExistingA() throws IOException {
        Message response = resolver.send(createMessage("a.b.ingotronic.ch./MX"));
        assertTrue(response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }

    @Test
    public void testDoubleLabelMXBelowSignedForExistingWildcardA() throws IOException {
        // *.d.ingotronic.ch./A exists
        Message response = resolver.send(createMessage("b.d.ingotronic.ch./MX"));
        assertTrue(response.getHeader().getFlag(Flags.AD));
        assertEquals(0, response.getSectionRRsets(Section.ANSWER).length);
        assertEquals(Rcode.NOERROR, response.getRcode());
    }
}
