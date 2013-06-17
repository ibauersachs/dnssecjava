package org.jitsi.dnssec;

import mockit.Mock;
import mockit.MockUp;

public class SystemMock extends MockUp<System> {
    private static long startTimeNanos = System.nanoTime();
    private static long startTimeMillis = System.currentTimeMillis();

    public static long overriddenMillis = 0;

    @Mock
    public static long currentTimeMillis(){
        return (overriddenMillis == 0 ? startTimeMillis : overriddenMillis) + (System.nanoTime() - startTimeNanos) / 1000000;
    }
}
