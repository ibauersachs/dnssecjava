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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.ResourceBundle;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest(R.class)
public class RTest {
    @Test
    public void testCustomResourceBundle() {
        ResourceBundle rb = mock(ResourceBundle.class);
        when(rb.getString(anyString())).then(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return (String)invocation.getArguments()[0];
            }
        });
        R.setUseNeutralMessages(false);
        R.setBundle(rb);
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
