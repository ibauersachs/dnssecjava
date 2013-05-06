package org.jitsi.dnssec.validator;

import java.util.Comparator;

/**
 * This class implements a basic comparitor for byte arrays. It is primarily
 * useful for comparing RDATA portions of DNS records in doing DNSSEC
 * canonical ordering.
 * 
 * @author David Blacka (original)
 */
public class ByteArrayComparator implements Comparator<Object> {
    private int mOffset = 0;

    public ByteArrayComparator() {
    }

    public ByteArrayComparator(int offset, boolean debug) {
        mOffset = offset;
    }

    public int compare(Object o1, Object o2) throws ClassCastException {
        byte[] b1 = (byte[])o1;
        byte[] b2 = (byte[])o2;
        for (int i = mOffset; i < b1.length && i < b2.length; i++) {
            if (b1[i] != b2[i]) {
                return (b1[i] & 0xFF) - (b2[i] & 0xFF);
            }
        }

        return b1.length - b2.length;
    }
}