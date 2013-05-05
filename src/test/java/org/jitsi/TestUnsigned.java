package org.jitsi;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;

public class TestUnsigned extends TestBase {
    @Test
    public void testUnsignedBelowSignedZoneBind() throws IOException {
        Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
        assertFalse(response.getHeader().getFlag(Flags.AD));
        assertEquals(localhost, firstA(response));
    }

    @Test
    public void testUnsignedBelowSignedZoneSwitch() throws IOException {
        Message response = resolver.send(createMessage("20min.ch./A"));
        assertFalse(response.getHeader().getFlag(Flags.AD));
        assertEquals(localhost, firstA(response));
    }

    @Test
    public void testUnsignedBelowUnsignedZone() throws IOException {
        Message response = resolver.send(createMessage("www.sub.unsigned.ingotronic.ch./A"));
        assertFalse(response.getHeader().getFlag(Flags.AD));
        assertEquals(localhost, firstA(response));
    }
}
