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

import java.util.*;

import org.apache.log4j.Logger;
import org.jitsi.dnssec.SecurityStatus;
import org.xbill.DNS.*;
import org.xbill.DNS.DNSSEC.DNSSECException;


/**
 * A class for performing basic DNSSEC verification. The DNSJAVA package
 * contains a similar class. This is a reimplementation that allows us to have
 * finer control over the validation process.
 * 
 * @author davidb
 * @version $Revision: 361 $
 */
public class DnsSecVerifier {
    private final static Logger log = Logger.getLogger(DnsSecVerifier.class);

    /**
     * Find the matching DNSKEY(s) to an RRSIG within a DNSKEY rrset. Normally
     * this will only return one DNSKEY. It can return more than one, since
     * KeyID/Footprints are not guaranteed to be unique.
     * 
     * @param dnskey_rrset The DNSKEY rrset to search.
     * @param signature The RRSIG to match against.
     * @return A List contains a one or more DNSKEYRecord objects, or null if a
     *         matching DNSKEY could not be found.
     */
    private List<DNSKEYRecord> findKey(RRset dnskey_rrset, RRSIGRecord signature) {
        if (!signature.getSigner().equals(dnskey_rrset.getName())) {
            log.trace("findKey: could not find appropriate key because incorrect keyset was supplied. Wanted: " + signature.getSigner() + ", got: " + dnskey_rrset.getName());
            return null;
        }

        int keyid = signature.getFootprint();
        int alg = signature.getAlgorithm();
        List<DNSKEYRecord> res = new ArrayList<DNSKEYRecord>(dnskey_rrset.size());
        for (Iterator<?> i = dnskey_rrset.rrs(); i.hasNext();) {
            DNSKEYRecord r = (DNSKEYRecord) i.next();
            if (r.getAlgorithm() == alg && r.getFootprint() == keyid) {
                res.add(r);
            }
        }

        if (res.size() == 0) {
            log.trace("findKey: could not find a key matching the algorithm and footprint in supplied keyset. ");
            return null;
        }

        return res;
    }

    /**
     * Verify an RRset against a particular signature.
     * 
     * @return DNSSEC.Secure if the signature verfied, DNSSEC.Failed if it did
     *         not verify (for any reason), and DNSSEC.Insecure if verification
     *         could not be completed (usually because the public key was not
     *         available).
     */
    private SecurityStatus verifySignature(RRset rrset, RRSIGRecord sigrec, RRset key_rrset) {
        List<DNSKEYRecord> keys = findKey(key_rrset, sigrec);
        if (keys == null) {
            log.trace("could not find appropriate key");
            return SecurityStatus.BOGUS;
        }

        SecurityStatus status = SecurityStatus.UNCHECKED;
        for (DNSKEYRecord key : keys) {
            try {
                DNSSEC.verify(rrset, sigrec, key);
                return SecurityStatus.SECURE;
            }
            catch (DNSSECException e) {
                log.error("Failed to validate RRset", e);
                status = SecurityStatus.BOGUS;
            }
        }

        return status;
    }

    /**
     * Verifies an RRset. This routine does not modify the RRset. This RRset is
     * presumed to be verifiable, and the correct DNSKEY rrset is presumed to
     * have been found.
     * 
     * @return SecurityStatus.SECURE if the rrest verified positively,
     *         SecurityStatus.BOGUS otherwise.
     */
    public SecurityStatus verify(RRset rrset, RRset key_rrset) {
        Iterator<?> i = rrset.sigs();
        if (!i.hasNext()) {
            log.info("RRset failed to verify due to lack of signatures");
            return SecurityStatus.BOGUS;
        }

        while (i.hasNext()) {
            RRSIGRecord sigrec = (RRSIGRecord) i.next();
            SecurityStatus res = verifySignature(rrset, sigrec, key_rrset);
            if (res == SecurityStatus.SECURE) {
                return res;
            }
        }

        log.info("RRset failed to verify: all signatures were BOGUS");
        return SecurityStatus.BOGUS;
    }

    /**
     * Verify an RRset against a single DNSKEY. Use this when you must be
     * certain that an RRset signed and verifies with a particular DNSKEY (as
     * opposed to a particular DNSKEY rrset).
     * 
     * @param rrset The rrset to verify.
     * @param dnskey The DNSKEY to verify with.
     * @return SecurityStatus.SECURE if the rrset verified, BOGUS otherwise.
     */
    public SecurityStatus verify(RRset rrset, DNSKEYRecord dnskey) {
        Iterator<?> i = rrset.sigs();
        if (!i.hasNext()) {
            log.info("RRset failed to verify due to lack of signatures");
            return SecurityStatus.BOGUS;
        }

        while (i.hasNext()) {
            RRSIGRecord sigrec = (RRSIGRecord) i.next();

            // Skip RRSIGs that do not match our given key's footprint.
            if (sigrec.getFootprint() != dnskey.getFootprint()) {
                continue;
            }

            try {
                DNSSEC.verify(rrset, sigrec, dnskey);
                return SecurityStatus.SECURE;
            }
            catch (DNSSECException e) {
                log.error("Failed to validate RRset", e);
            }
        }

        log.info("RRset failed to verify: all signatures were BOGUS");
        return SecurityStatus.BOGUS;
    }
}
