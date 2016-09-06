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

import mockit.Mock;
import mockit.MockUp;
import org.junit.Test;

import java.util.ResourceBundle;

import static org.junit.Assert.assertEquals;

public class RTest {
    @Test
    public void testCustomResourceBundle() {
        MockUp<ResourceBundle> rb = new MockUp<ResourceBundle>() {
            @Mock
            public String getString(String key) {
                return key;
            }
        };
        R.setUseNeutralMessages(false);
        R.setBundle(rb.getMockInstance());
        assertEquals("key", R.get("key"));
        assertEquals("msg 1", R.get("msg {0}", 1));
    }

    @Test
    public void testExplicitNullBundle() {
        R.setUseNeutralMessages(true);
        assertEquals("key", R.get("key"));
        assertEquals("key:1", R.get("key", 1));
    }

    @Test
    public void testNormal() {
        R.setUseNeutralMessages(false);
        R.setBundle(null);
        assertEquals("no parameters", R.get("test.noparam"));
        assertEquals("parameter: abc", R.get("test.withparam", "abc"));
    }

    @Test
    public void testMissingResource() {
        R.setUseNeutralMessages(false);
        R.setBundle(null);
        assertEquals("test.notthere.noparam", R.get("test.notthere.noparam"));
        assertEquals("test.notthere.withparam:abc", R.get("test.notthere.withparam", "abc"));
        assertEquals("test.notthere.withparam:abc:null:1", R.get("test.notthere.withparam", "abc", null, 1));
    }
}
