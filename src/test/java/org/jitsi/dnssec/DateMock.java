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
