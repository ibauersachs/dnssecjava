/*
 * $Id: KeyEntry.java 305 2006-04-28 16:13:06Z davidb $
 *
 * Copyright (c) 2005 VeriSign, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package org.jitsi.dnssec.validator;

import org.jitsi.dnssec.SRRset;
import org.xbill.DNS.Name;

public class KeyEntry {
    private SRRset mRRset;
    private Name mName;
    private int mDClass;
    private long mTTL;
    private boolean mIsBad;

    private KeyEntry() {
        mIsBad = false;
    }

    /**
     * Create a new, postive key entry
     * 
     * @param rrset
     */
    private KeyEntry(SRRset rrset) {
        this();
        mRRset = rrset;
        mName = rrset.getName();
        mDClass = rrset.getDClass();
    }

    private KeyEntry(Name n, int dclass, long ttl, boolean isBad) {
        this();
        mRRset = null;
        mName = n;
        mDClass = dclass;
        mTTL = ttl;
        mIsBad = isBad;
    }

    public static KeyEntry newKeyEntry(SRRset rrset) {
        return new KeyEntry(rrset);
    }

    public static KeyEntry newNullKeyEntry(Name n, int dclass, long ttl) {
        return new KeyEntry(n, dclass, ttl, false);
    }

    public static KeyEntry newBadKeyEntry(Name n, int dclass) {
        return new KeyEntry(n, dclass, 0, true);
    }

    public SRRset getRRset() {
        return mRRset;
    }

    public Name getName() {
        return mName;
    }

    public int getDClass() {
        return mDClass;
    }

    public long getTTL() {
        return mTTL;
    }

    public boolean isNull() {
        return !mIsBad && mRRset == null;
    }

    public boolean isBad() {
        return mIsBad;
    }

    public boolean isGood() {
        return !mIsBad && mRRset != null;
    }
}