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

public class RMock extends MockUp<R> {
    @Mock
    public static String get(String key, Object... values){
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        for (Object o : values) {
            sb.append(":");
            sb.append(o);
        }

        return sb.toString();
    }
}
