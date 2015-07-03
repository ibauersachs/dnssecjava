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

import mockit.Deencapsulation;
import mockit.Invocation;
import mockit.Mock;
import mockit.MockUp;

public class DateMock extends MockUp<java.util.Date> {
    private static long startTimeNanos = System.nanoTime();
    private static long startTimeMillis = System.currentTimeMillis();

    public static long overriddenMillis = 0;

    @Mock
    public void $init(Invocation invocation){
        Deencapsulation.setField(invocation.getInvokedInstance(), "fastTime", (overriddenMillis == 0 ? startTimeMillis : overriddenMillis) + (System.nanoTime() - startTimeNanos) / 1000000);
    }
}
