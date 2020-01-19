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

import java.util.HashMap;
import java.util.Map;
import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * Storage for DS or DNSKEY records that are known to be trusted.
 *
 * @author davidb
 */
public class TrustAnchorStore {
  private Map<String, SRRset> map;

  /** Creates a new instance of this class. */
  public TrustAnchorStore() {
    this.map = new HashMap<>();
  }

  /**
   * Stores the given RRset as known trusted keys. Existing keys for the same name and class are
   * overwritten.
   *
   * @param rrset The key set to store as trusted.
   */
  public void store(SRRset rrset) {
    if (rrset.getType() != Type.DS && rrset.getType() != Type.DNSKEY) {
      throw new IllegalArgumentException("Trust anchors can only be DS or DNSKEY records");
    }

    if (rrset.getType() == Type.DNSKEY) {
      SRRset temp = new SRRset();
      for (Record r : rrset.rrs()) {
        DNSKEYRecord key = (DNSKEYRecord) r;
        DSRecord ds =
            new DSRecord(key.getName(), key.getDClass(), key.getTTL(), DSRecord.Digest.SHA384, key);
        temp.addRR(ds);
      }

      rrset = temp;
    }

    String k = this.key(rrset.getName(), rrset.getDClass());
    rrset.setSecurityStatus(SecurityStatus.SECURE);
    SRRset previous = this.map.put(k, rrset);
    if (previous != null) {
      previous.rrs().forEach(rrset::addRR);
    }
  }

  /**
   * Gets the closest trusted key for the given name or <code>null</code> if no match is found.
   *
   * @param name The name to search for.
   * @param dclass The class of the keys.
   * @return The closest found key for <code>name</code> or <code>null</code>.
   */
  public SRRset find(Name name, int dclass) {
    while (name.labels() > 0) {
      String k = this.key(name, dclass);
      SRRset r = this.lookup(k);
      if (r != null) {
        return r;
      }

      name = new Name(name, 1);
    }

    return null;
  }

  /** Removes all stored trust anchors. */
  public void clear() {
    this.map.clear();
  }

  private SRRset lookup(String key) {
    return this.map.get(key);
  }

  private String key(Name n, int dclass) {
    return "T" + dclass + "/" + n;
  }
}
