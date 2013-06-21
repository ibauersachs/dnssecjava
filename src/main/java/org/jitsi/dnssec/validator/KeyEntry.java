/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (C) 2013 Ingo Bauersachs. All rights reserved.
 *
 * This file is part of dnssecjava.
 *
 * Dnssecjava is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dnssecjava is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with dnssecjava.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * 
 * This file is based on work under the following copyright and permission
 * notice:
 * 
 *     Copyright (c) 2005 VeriSign. All rights reserved.
 * 
 *     Redistribution and use in source and binary forms, with or without
 *     modification, are permitted provided that the following conditions are
 *     met:
 * 
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *     3. The name of the author may not be used to endorse or promote
 *        products derived from this software without specific prior written
 *        permission.
 * 
 *     THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *     IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *     ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 *     INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *     (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *     SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *     STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *     IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *     POSSIBILITY OF SUCH DAMAGE.
 */

package org.jitsi.dnssec.validator;

import org.apache.log4j.Logger;
import org.jitsi.dnssec.SRRset;
import org.xbill.DNS.Name;

/**
 * DNSKEY cache entry for a given {@link Name}, with or without actual keys.
 */
public final class KeyEntry {
    private static final Logger logger = Logger.getLogger(KeyEntry.class);

    private SRRset rrset;
    private Name name;
    private int dclass;
    private long ttl;
    private boolean isBad = false;
    private String badReason;

    /**
     * Create a new, positive key entry.
     * 
     * @param rrset The set of records to cache.
     */
    private KeyEntry(SRRset rrset) {
        this.rrset = rrset;
        this.name = rrset.getName();
        this.dclass = rrset.getDClass();
        this.ttl = rrset.getTTL();
    }

    private KeyEntry(Name name, int dclass, long ttl, boolean isBad) {
        this.rrset = null;
        this.name = name;
        this.dclass = dclass;
        this.ttl = ttl;
        this.isBad = isBad;
    }

    /**
     * Creates a new key entry from actual DNSKEYs.
     * 
     * @param rrset The DNSKEYs to cache.
     * @return The created key entry.
     */
    public static KeyEntry newKeyEntry(SRRset rrset) {
        return new KeyEntry(rrset);
    }

    /**
     * Creates a new trusted key entry without actual DNSKEYs, i.e. it is proven
     * that there are no keys.
     * 
     * @param n The name for which the empty cache entry is created.
     * @param dclass The DNS class.
     * @param ttl The TTL [s].
     * @return The created key entry.
     */
    public static KeyEntry newNullKeyEntry(Name n, int dclass, long ttl) {
        return new KeyEntry(n, dclass, ttl, false);
    }

    /**
     * Creates a new bad key entry without actual DNSKEYs, i.e. from a response
     * that did not validate.
     * 
     * @param n The name for which the bad cache entry is created.
     * @param dclass The DNS class.
     * @param ttl The TTL [s].
     * @return The created key entry.s
     */
    public static KeyEntry newBadKeyEntry(Name n, int dclass, long ttl) {
        return new KeyEntry(n, dclass, ttl, true);
    }

    /**
     * Gets the DNSKEYs for the cached key entry. Can be <code>null</code>.
     * 
     * @return The DNSKEYs for the cached key entry. Can be <code>null</code>.
     */
    public SRRset getRRset() {
        return this.rrset;
    }

    /**
     * Gets the name of the cache entry.
     * 
     * @return The name of the cache entry.
     */
    public Name getName() {
        return this.name;
    }

    /**
     * Gets the DNS class.
     * 
     * @return The DNS class.
     */
    public int getDClass() {
        return this.dclass;
    }

    /**
     * Gets the TTL [s].
     * 
     * @return The TTL [s].
     */
    public long getTTL() {
        return this.ttl;
    }

    /**
     * Gets an indication if this is a null key, i.e. a proven secure response
     * without keys.
     * 
     * @return <code>True</code> is it is null, <code>false</code> otherwise.
     */
    public boolean isNull() {
        return !this.isBad && this.rrset == null;
    }

    /**
     * Gets an indication if this is a bad key, i.e. an invalid response.
     * 
     * @return <code>True</code> is it is bad, <code>false</code> otherwise.
     */
    public boolean isBad() {
        return this.isBad;
    }

    /**
     * Gets an indication if this is a good key, i.e. a proven secure response
     * with keys.
     * 
     * @return <code>True</code> is it is good, <code>false</code> otherwise.
     */
    public boolean isGood() {
        return !this.isBad && this.rrset != null;
    }

    /**
     * Gets the reason why this key entry is bad.
     * 
     * @return The reason why this key entry is bad.
     */
    public String getBadReason() {
        return this.badReason;
    }

    /**
     * Sets the reason why this key entry is bad.
     * 
     * @param reason The reason why this key entry is bad.
     */
    public void setBadReason(String reason) {
        this.badReason = reason;
        logger.debug(this.badReason);
    }
}
