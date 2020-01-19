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

import org.jitsi.dnssec.R;
import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/** DNSKEY cache entry for a given {@link Name}, with or without actual keys. */
public final class KeyEntry extends SRRset {
  private static final Logger logger = LoggerFactory.getLogger(KeyEntry.class);

  private String badReason;
  private boolean isEmpty;

  /**
   * Create a new, positive key entry.
   *
   * @param rrset The set of records to cache.
   */
  private KeyEntry(SRRset rrset) {
    super(rrset);
  }

  private KeyEntry(Name name, int dclass, long ttl, boolean isBad) {
    super(new SRRset(Record.newRecord(name, Type.DNSKEY, dclass, ttl)));
    this.isEmpty = true;
    if (isBad) {
      setSecurityStatus(SecurityStatus.BOGUS);
    }
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
   * Creates a new trusted key entry without actual DNSKEYs, i.e. it is proven that there are no
   * keys.
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
   * Creates a new bad key entry without actual DNSKEYs, i.e. from a response that did not validate.
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
   * Gets an indication if this is a null key, i.e. a proven secure response without keys.
   *
   * @return <code>True</code> is it is null, <code>false</code> otherwise.
   */
  public boolean isNull() {
    return this.isEmpty && this.getSecurityStatus() == SecurityStatus.UNCHECKED;
  }

  /**
   * Gets an indication if this is a bad key, i.e. an invalid response.
   *
   * @return <code>True</code> is it is bad, <code>false</code> otherwise.
   */
  public boolean isBad() {
    return this.isEmpty && this.getSecurityStatus() == SecurityStatus.BOGUS;
  }

  /**
   * Gets an indication if this is a good key, i.e. a proven secure response with keys.
   *
   * @return <code>True</code> is it is good, <code>false</code> otherwise.
   */
  public boolean isGood() {
    return !this.isEmpty && this.getSecurityStatus() == SecurityStatus.SECURE;
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

  /**
   * Validate if this key instance is valid for the specified name.
   *
   * @param signerName the name against which this key is validated.
   * @return A security status indicating if this key is valid, or if not, why.
   */
  JustifiedSecStatus validateKeyFor(Name signerName) {
    // signerName being null is the indicator that this response was
    // unsigned
    if (signerName == null) {
      logger.debug("no signerName");
      // Unsigned responses must be underneath a "null" key entry.
      if (this.isNull()) {
        String reason = this.badReason;
        if (reason == null) {
          reason = R.get("validate.insecure_unsigned");
        }

        return new JustifiedSecStatus(SecurityStatus.INSECURE, reason);
      }

      if (this.isGood()) {
        return new JustifiedSecStatus(SecurityStatus.BOGUS, R.get("validate.bogus.missingsig"));
      }

      return new JustifiedSecStatus(SecurityStatus.BOGUS, R.get("validate.bogus", this.badReason));
    }

    if (this.isBad()) {
      return new JustifiedSecStatus(
          SecurityStatus.BOGUS, R.get("validate.bogus.badkey", this.getName(), this.badReason));
    }

    if (this.isNull()) {
      String reason = this.badReason;
      if (reason == null) {
        reason = R.get("validate.insecure");
      }

      return new JustifiedSecStatus(SecurityStatus.INSECURE, reason);
    }

    return null;
  }
}
