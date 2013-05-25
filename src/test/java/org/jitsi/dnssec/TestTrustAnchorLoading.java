package org.jitsi.dnssec;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.net.UnknownHostException;

import org.jitsi.dnssec.validator.ValidatingResolver;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.SimpleResolver;

public class TestTrustAnchorLoading {
    private ValidatingResolver resolver;

    @Before
    public void setup() throws UnknownHostException {
        this.resolver = new ValidatingResolver(new SimpleResolver());
    }

    @Test
    public void testLoadRootTrustAnchors() throws IOException {
        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
    }

    @Test
    public void testLoadRootTrustAnchorsAlongWithGarbage() throws IOException {
        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors_test"));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
        assertNotNull(resolver.getTrustAnchors().find(Name.root, DClass.CH));
    }

    @Test
    public void testLoadEmptyTrustAnchors() throws IOException {
        resolver.loadTrustAnchors(getClass().getResourceAsStream( "/trust_anchors_empty"));
        assertNull(resolver.getTrustAnchors().find(Name.root, DClass.IN));
    }
}
