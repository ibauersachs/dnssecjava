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

import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

/**
 * @author davidb
 * @version $Revision: 286 $
 */
public class KeyCache {
    private static class CacheEntry {
        public Date expiration;
        public KeyEntry keyEntry;

        public CacheEntry(SRRset r, long maxTtl) {
            long ttl = r.getTTL();
            if (ttl > maxTtl) {
                ttl = maxTtl;
            }

            this.expiration = new Date(System.currentTimeMillis() + (ttl * 1000));
            this.keyEntry = KeyEntry.newKeyEntry(r);
        }

        public CacheEntry(Name n, int dclass, long ttl, long maxTtl) {
            if (ttl > maxTtl) {
                ttl = maxTtl;
            }

            this.expiration = new Date(System.currentTimeMillis() + (ttl * 1000));
            this.keyEntry = KeyEntry.newNullKeyEntry(n, dclass, ttl);
        }
    }

    /** This is the main caching data structure. */
    private Map<String, CacheEntry> cache;

    /** This is the maximum TTL [s] that all key cache entries will have. */
    private long maxTtl = 900;

    /** This is the maximum number of entries that the key cache will hold. */
    private int maxCacheSize = 1000;

    public KeyCache() {
        this.cache = Collections.synchronizedMap(new LinkedHashMap<String, CacheEntry>() {
            @Override
            protected boolean removeEldestEntry(java.util.Map.Entry<String, CacheEntry> eldest) {
                return size() > KeyCache.this.maxCacheSize;
            }
        });
    }

    /**
     * Initialize the cache. This implementation recognizes the following
     * configuration parameters:
     * <dl>
     * <dt>org.jitsi.dnssec.keycache.max_ttl
     * <dd>The maximum TTL to apply to any cache entry.
     * <dt>org.jitsi.dnssec.keycache.max_size
     * <dd>The maximum number of entries that the cache will hold.
     * </dl>
     * 
     * @param config The configuration information.
     */
    public void init(Properties config) {
        if (config == null) {
            return;
        }

        String s = config.getProperty("org.jitsi.dnssec.keycache.max_ttl");
        if (s != null) {
            this.maxTtl = Long.parseLong(s);
        }

        s = config.getProperty("org.jitsi.dnssec.keycache.max_size");
        if (s != null) {
            this.maxCacheSize = Integer.parseInt(s);
        }
    }

    /**
     * Find the 'closest' trusted DNSKEY rrset to the given name.
     * 
     * @param n The name to start the search.
     * @param dclass The class this DNSKEY rrset should be in.
     * 
     * @return The 'closest' entry to 'n' in the same class as 'dclass'.
     */
    public KeyEntry find(Name n, int dclass) {
        while (n.labels() > 0) {
            String k = key(n, dclass);
            KeyEntry entry = lookupEntry(k);
            if (entry != null) {
                return entry;
            }

            n = new Name(n, 1);
        }

        return null;
    }

    /**
     * Store a DNSKEY rrset in the cache. The rrset will be ignored if it isn't
     * a DNSKEY rrset or if it doesn't have the SECURE security status.
     * 
     * @param keyRrset The SRRset to store.
     */
    public void store(SRRset keyRrset) {
        if (keyRrset == null) {
            return;
        }

        if (keyRrset.getType() != Type.DNSKEY) {
            return;
        }

        if (keyRrset.getSecurityStatus() != SecurityStatus.SECURE) {
            return;
        }

        String k = key(keyRrset.getName(), keyRrset.getDClass());
        CacheEntry ce = new CacheEntry(keyRrset, this.maxTtl);

        this.cache.put(k, ce);
    }

    public void store(Name n, int dclass, long ttl) {
        if (n == null) {
            return;
        }

        if (ttl <= 0) {
            return;
        }

        String k = key(n, dclass);
        CacheEntry ce = new CacheEntry(n, dclass, ttl, maxTtl);
        this.cache.put(k, ce);
    }

    private String key(Name n, int dclass) {
        return "K" + dclass + "/" + n;
    }

    private KeyEntry lookupEntry(String key) {
        CacheEntry centry = (CacheEntry)this.cache.get(key);
        if (centry == null) {
            return null;
        }

        if (centry.expiration.before(new Date())) {
            this.cache.remove(key);
            return null;
        }

        return centry.keyEntry;
    }
}
