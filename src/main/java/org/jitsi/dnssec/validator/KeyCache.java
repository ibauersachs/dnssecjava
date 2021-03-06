/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2015 Ingo Bauersachs
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
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
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

/**
 * Cache for DNSKEY RRsets or corresponding null/bad key entries with a limited size and respect for
 * TTL values.
 *
 * @author davidb
 * @author Ingo Bauersachs
 */
public class KeyCache {
  /** Name of the property that configures the maximum cache TTL. */
  public static final String MAX_TTL_CONFIG = "org.jitsi.dnssec.keycache.max_ttl";

  /** Name of the property that configures the maximum cache size. */
  public static final String MAX_CACHE_SIZE_CONFIG = "org.jitsi.dnssec.keycache.max_size";

  private static final int MILLISECONDS_PER_SECOND = 1000;
  private static final int DEFAULT_MAX_TTL = 900;
  private static final int DEFAULT_MAX_CACHE_SIZE = 1000;

  /** This is the main caching data structure. */
  private Map<String, CacheEntry> cache;

  /** This is the maximum TTL [s] that all key cache entries will have. */
  private long maxTtl = DEFAULT_MAX_TTL;

  /** This is the maximum number of entries that the key cache will hold. */
  private int maxCacheSize = DEFAULT_MAX_CACHE_SIZE;

  /** Creates a new instance of this class. */
  public KeyCache() {
    this.cache =
        Collections.synchronizedMap(
            new LinkedHashMap<String, CacheEntry>() {
              @Override
              protected boolean removeEldestEntry(java.util.Map.Entry<String, CacheEntry> eldest) {
                return size() >= KeyCache.this.maxCacheSize;
              }
            });
  }

  /**
   * Initialize the cache. This implementation recognizes the following configuration parameters:
   *
   * <dl>
   *   <dt>org.jitsi.dnssec.keycache.max_ttl
   *   <dd>The maximum TTL to apply to any cache entry.
   *   <dt>org.jitsi.dnssec.keycache.max_size
   *   <dd>The maximum number of entries that the cache will hold.
   * </dl>
   *
   * @param config The configuration information.
   */
  public void init(Properties config) {
    if (config == null) {
      return;
    }

    String s = config.getProperty(MAX_TTL_CONFIG);
    if (s != null) {
      this.maxTtl = Long.parseLong(s);
    }

    s = config.getProperty(MAX_CACHE_SIZE_CONFIG);
    if (s != null) {
      this.maxCacheSize = Integer.parseInt(s);
    }
  }

  /**
   * Find the 'closest' trusted DNSKEY rrset to the given name.
   *
   * @param n The name to start the search.
   * @param dclass The class this DNSKEY rrset should be in.
   * @return The 'closest' entry to 'n' in the same class as 'dclass'.
   */
  public KeyEntry find(Name n, int dclass) {
    while (n.labels() > 0) {
      String k = this.key(n, dclass);
      KeyEntry entry = this.lookupEntry(k);
      if (entry != null) {
        return entry;
      }

      n = new Name(n, 1);
    }

    return null;
  }

  /**
   * Store a {@link KeyEntry} in the cache. The entry will be ignored if it isn't a DNSKEY rrset, if
   * it doesn't have the SECURE security status, or if it isn't a null-Key.
   *
   * @param ke The key entry to cache.
   */
  public void store(KeyEntry ke) {
    if (!ke.isGood() && !ke.isNull()) {
      return;
    }

    if (ke.getType() != Type.DNSKEY) {
      return;
    }

    String k = this.key(ke.getName(), ke.getDClass());
    CacheEntry ce = new CacheEntry(ke, this.maxTtl);
    this.cache.put(k, ce);
  }

  private String key(Name n, int dclass) {
    return "K" + dclass + "/" + n;
  }

  private KeyEntry lookupEntry(String key) {
    CacheEntry centry = this.cache.get(key);
    if (centry == null) {
      return null;
    }

    if (centry.expiration.before(new Date())) {
      this.cache.remove(key);
      return null;
    }

    return centry.keyEntry;
  }

  /** Utility class to cache key entries with an expiration date. */
  private static class CacheEntry {
    private Date expiration;
    private KeyEntry keyEntry;

    CacheEntry(KeyEntry keyEntry, long maxTtl) {
      long ttl = keyEntry.getTTL();
      if (ttl > maxTtl) {
        ttl = maxTtl;
      }

      this.expiration = new Date(System.currentTimeMillis() + (ttl * MILLISECONDS_PER_SECOND));
      this.keyEntry = keyEntry;
    }
  }
}
